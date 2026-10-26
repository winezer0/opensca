package golang

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/xmirrorsecurity/opensca-cli/v3/cmd/config"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
)

// GomodModuleName 读取 go.mod 的 module 声明。
//
// 用 vendor/modules.txt 建图时，项目自身的名字只能从 go.mod 拿。
func GomodModuleName(file *model.File) string {
	var name string
	file.ReadLineNoComment(&model.CommentType{
		Simple: "//",
	}, func(line string) {
		if name != "" {
			return
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module") {
			name = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "module")), `'"`)
		}
	})
	return name
}

// ParseGomod 解析go.mod文件
func ParseGomod(file *model.File) *model.DepGraph {

	root := &model.DepGraph{Path: file.Relpath(), Project: true}

	var require bool
	var replace bool

	parseDepLine := func(line string) (name, version string) {
		line = strings.TrimSpace(line)
		words := strings.Fields(line)
		if len(words) >= 2 {
			name = strings.Trim(words[0], `'"`)
			// +incompatible 是版本号的一部分：v6.15.9+incompatible 表示这个
			// 主版本还没有 go.mod。剥掉它版本就和 vendor/modules.txt 对不上，
			// OSV 也匹配不到对应公告（go.sum 里的记录同样是这个形态）。
			version = strings.Trim(words[1], `'"`)
		}
		return
	}

	deps := map[string]string{}

	file.ReadLineNoComment(&model.CommentType{
		Simple: "//",
	}, func(line string) {

		if strings.HasPrefix(line, "module") {
			root.Name = strings.TrimSpace(strings.TrimPrefix(line, "module"))
			return
		}

		if strings.HasPrefix(line, "require") {
			require = true
			line = strings.TrimPrefix(line, "require")
			if strings.TrimSpace(line) == "" {
				return
			}
		}

		if strings.HasPrefix(line, "replace") {
			replace = true
			line = strings.TrimPrefix(line, "replace")
			if strings.TrimSpace(line) == "" {
				return
			}
		}

		if strings.HasPrefix(line, ")") {
			require = false
			replace = false
			return
		}

		if require {
			name, version := parseDepLine(line)
			if name != "" {
				deps[name] = version
			}
			return
		}

		if replace {
			line = strings.TrimSpace(line)
			i := strings.Index(line, "=>")
			if i == -1 {
				return
			}
			// 左边可能是 "A" 也可能是 "A v1.0.0"，组件键始终是模块路径。
			old := strings.Fields(strings.TrimSpace(line[:i]))
			if len(old) == 0 {
				return
			}
			oldPath := strings.Trim(old[0], `'"`)
			if _, ok := deps[oldPath]; !ok {
				// replace 一个没被 require 的模块不会影响构建结果。
				return
			}
			right := strings.Fields(strings.TrimSpace(line[i+2:]))
			if len(right) < 2 {
				// `=> ./local`：源码换成本地目录，模块路径与版本都不变。
				// 原来的代码在这里把 deps 删了又不补回去，等于让这个组件消失。
				return
			}
			newPath := strings.Trim(right[0], `'"`)
			newVersion := strings.Trim(right[1], `'"`)
			delete(deps, oldPath)
			deps[newPath] = newVersion
			return
		}

	})

	for name, version := range deps {
		root.AppendChild(&model.DepGraph{
			Name:    name,
			Version: version,
		})
	}

	return root
}

// ParseGosum 解析go.sum文件
//
// 只在没有 go.mod 可读时作为兜底使用。go.sum 记录的是历史上解析过的所有
// module@version（本工程 1177 行），不是最终选中并参与构建的集合。
func ParseGosum(file *model.File) *model.DepGraph {

	depMap := map[string]string{}
	file.ReadLine(func(line string) {
		line = strings.TrimSpace(line)
		words := strings.Fields(line)
		if len(words) >= 2 {
			name := strings.Trim(words[0], `'"`)
			// go.sum 会同时记录 module 与 module/go.mod 两种条目，去掉后者；
			// 但 +incompatible 属于版本号，必须保留。
			version := strings.TrimSuffix(words[1], "/go.mod")
			depMap[name] = version
		}
	})

	root := &model.DepGraph{Path: file.Relpath()}
	for name, version := range depMap {
		root.AppendChild(&model.DepGraph{
			Name:    name,
			Version: version,
		})
	}

	sort.Slice(root.Children, func(i, j int) bool {
		return root.Children[i].Name < root.Children[j].Name
	})

	return root
}

// GoModGraph 调用 go mod graph 解析依赖
func GoModGraph(ctx context.Context, modfile *model.File) *model.DepGraph {

	if !config.Conf().Optional.Dynamic.Enabled() {
		return nil
	}

	_, err := exec.LookPath("go")
	if err != nil {
		return nil
	}

	cmd := exec.CommandContext(ctx, "go", "mod", "graph")
	cmd.Dir = filepath.Dir(modfile.Abspath())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil
	}

	_dep := model.NewDepGraphMap(nil, func(s ...string) *model.DepGraph {
		return &model.DepGraph{
			Name:    s[0],
			Version: s[1],
		}
	})

	parse := func(s string) *model.DepGraph {
		words := strings.Split(s, "@")
		if len(words) == 2 {
			return _dep.LoadOrStore(words...)
		}
		return _dep.LoadOrStore(s, "")
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		words := strings.Fields(strings.TrimSpace(scanner.Text()))
		if len(words) == 2 {
			parent := parse(words[0])
			child := parse(words[1])
			parent.AppendChild(child)
		}
	}

	root := &model.DepGraph{Path: modfile.Relpath()}
	_dep.Range(func(k string, v *model.DepGraph) bool {
		if len(v.Parents) == 0 {
			root.AppendChild(v)
		}
		return true
	})

	return root
}
