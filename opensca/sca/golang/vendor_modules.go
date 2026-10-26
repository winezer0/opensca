package golang

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
)

// vendorModule 是 vendor/modules.txt 里的一条模块记录。
type vendorModule struct {
	Path string
	// Version 是实际参与编译的版本，replace 已在此生效。
	Version string
	// Explicit 表示该模块出现在主模块 go.mod 的 require 列表里。
	// 它不等于「业务上的直接依赖」：go.mod 会把间接依赖也写成 require。
	Explicit bool
}

// ParseVendorModules 解析 <dir>/vendor/modules.txt，返回依赖图。
//
// 文件不存在、读不动或没有模块时返回 nil，调用方应退回解析 go.mod。
//
// 为什么优先用它：vendor 模式下 go 命令已经把 replace、MVS 和 exclude 算完，
// modules.txt 是这次构建真正使用的模块集合；go.mod 的 require 只是输入。
// 本项目就有这种差异——go.mod 写 golang.org/x/sys v0.6.0，replace 到
// v0.0.0-20210112080510-489259a85091，只看 go.mod 会报错版本。
//
// 文件格式（cmd/go/internal/modload 写出）：
//
//	# github.com/foo/bar v1.2.3
//	## explicit
//	github.com/foo/bar                     <- 该模块提供的包，忽略
//	# github.com/a/b v1.0.0 => github.com/fork/b v1.2.0
//	# github.com/old/m v1.0.0 => ./local   <- 本地目录替换，版本不变
//	# github.com/a/b => github.com/fork/b v1.2.0   <- 末尾的 replace 汇总，跳过
//
// 最后这种不带版本的行只是复述 replace 指令，当成模块会凭空多出一条组件。
func ParseVendorModules(dir string) *model.DepGraph {
	path := filepath.Join(dir, "vendor", "modules.txt")
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var mods []vendorModule
	var curIdx = -1
	var scanner = bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "## "):
			// "## explicit" 或 "## explicit; go 1.17"
			if curIdx >= 0 && strings.Contains(line, "explicit") {
				mods[curIdx].Explicit = true
			}
		case strings.HasPrefix(line, "# "):
			curIdx = -1
			body := strings.TrimSpace(strings.TrimPrefix(line, "# "))
			left, right := body, ""
			if i := strings.Index(body, "=>"); i >= 0 {
				left = strings.TrimSpace(body[:i])
				right = strings.TrimSpace(body[i+2:])
			}
			fields := strings.Fields(left)
			if len(fields) < 2 {
				// 不带版本的 `# A => B v2`：replace 汇总行，不是模块。
				continue
			}
			m := vendorModule{Path: fields[0], Version: fields[1]}
			if right != "" {
				r := strings.Fields(right)
				if len(r) >= 2 && !isLocalPath(r[0]) {
					// 换成另一个模块或另一个版本：报实际参与编译的那个。
					m.Path, m.Version = r[0], r[1]
				}
			}
			mods = append(mods, m)
			curIdx = len(mods) - 1
		}
	}
	if err := scanner.Err(); err != nil || len(mods) == 0 {
		return nil
	}

	root := &model.DepGraph{Project: true}
	for _, m := range mods {
		root.AppendChild(&model.DepGraph{
			Name:    m.Path,
			Version: m.Version,
			// 不把 Explicit 映射到 Direct：go.mod 会把间接依赖也写成 require，
			// 一个 tidy 过的 vendor 工程里每个模块都是 explicit，直接/间接只能
			// 从 go.mod 的 "// indirect" 注释判断，与 ParseGomod 保持一致。
		})
	}
	return root
}

// isLocalPath 判断 replace 右侧是不是本地文件系统路径。
func isLocalPath(p string) bool {
	if p == "" {
		return false
	}
	for _, prefix := range []string{"./", "../", ".\\", "..\\"} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return filepath.IsAbs(p)
}
