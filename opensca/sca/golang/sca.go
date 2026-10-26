package golang

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/xmirrorsecurity/opensca-cli/v3/cmd/config"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/sca/filter"
)

type Sca struct{}

func (sca Sca) Language() model.Language {
	return model.Lan_Golang
}

func (sca Sca) Filter(relpath string) bool {
	// vendor/ 是依赖的完整源码副本，里面还带着它们自己的清单
	// （Gopkg.lock、go.mod、package.json）。把这些当成独立项目解析，
	// 会把依赖的依赖算到本项目头上：本仓库 vendor 里的两个 Gopkg.lock
	// 就让 modern-go/concurrent 多出一个不带 v 前缀的 1.0.0。
	// 本项目的依赖由根目录 go.mod 或 vendor/modules.txt 描述。
	if inVendorDir(relpath) {
		return false
	}
	return filter.GoMod(relpath) || filter.GoSum(relpath) || filter.GoPkgToml(relpath) || filter.GoPkgLock(relpath)
}

// inVendorDir 判断相对路径是否位于某个 vendor 目录内。
func inVendorDir(relpath string) bool {
	for _, seg := range strings.Split(filepath.ToSlash(relpath), "/") {
		if seg == "vendor" {
			return true
		}
	}
	return false
}

func (sca Sca) Sca(ctx context.Context, parent *model.File, files []*model.File, call model.ResCallback) {

	// map[dir]*File
	gomod := map[string]*model.File{}
	gosum := map[string]*model.File{}
	pkglock := map[string]*model.File{}
	pkgtoml := map[string]*model.File{}

	// 记录相关文件
	for _, f := range files {
		dir := filepath.Dir(f.Relpath())
		if filter.GoPkgToml(f.Relpath()) {
			pkgtoml[dir] = f
		}
		if filter.GoPkgLock(f.Relpath()) {
			pkglock[dir] = f
		}
		if filter.GoMod(f.Relpath()) {
			gomod[dir] = f
		}
		if filter.GoSum(f.Relpath()) {
			gosum[dir] = f
		}
	}

	// 尝试调用 go mod graph
	if config.Conf().Optional.Dynamic.Enabled() {
		for dir, f := range gomod {
			graph := GoModGraph(ctx, f)
			if graph != nil && len(graph.Children) > 0 {
				call(f, graph)
				delete(gomod, dir)
				delete(gosum, dir)
			}
		}
	}

	// vendor 构建：vendor/modules.txt 是 go 命令的解析结果，replace、MVS、
	// exclude 都已生效，比 go.mod 的 require 更接近实际参与编译的模块。
	for dir, f := range gomod {
		graph := ParseVendorModules(filepath.Dir(f.Abspath()))
		if graph == nil {
			continue
		}
		graph.Path = f.Relpath()
		graph.Name = GomodModuleName(f)
		call(f, graph)
		delete(gomod, dir)
		delete(gosum, dir)
	}

	// 静态解析go.mod
	for dir, f := range gomod {
		mod := ParseGomod(f)
		call(f, mod)
		delete(gosum, dir)
	}

	// 静态解析go.sum
	//
	// 只作为兜底：go.sum 记录的是历史上解析过的所有 module@version（本工程
	// 1177 行），不是最终选中的集合（67 个）。有 go.mod 时永远不该走这里，
	// 否则组件数会从 67 涨到 498，漏洞从 35 涨到 187。
	for _, f := range gosum {
		sum := ParseGosum(f)
		call(f, sum)
	}

	// 静态解析gopkg.lock
	for dir, f := range pkglock {
		lock := ParseGopkgLock(f)
		call(f, lock)
		delete(pkgtoml, dir)
	}

	// 静态解析gopkg.toml
	for _, f := range pkgtoml {
		pkg := ParseGopkgToml(f)
		call(f, pkg)
	}

}
