package javascript

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/common"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/sca/filter"
)

type Sca struct{}

func (sca Sca) Language() model.Language {
	return model.Lan_JavaScript
}

func (sca Sca) Filter(relpath string) bool {
	return filter.JavaScriptPackageJson(relpath) ||
		filter.JavaScriptPackageLock(relpath) ||
		filter.JavaScriptYarnLock(relpath) || isPnpmLock(relpath)
}

func (sca Sca) Sca(ctx context.Context, parent *model.File, files []*model.File, call model.ResCallback) {

	// map[dirpath]
	jsonMap := map[string]*PackageJson{}
	jsonNameMap := map[string]*PackageJson{}
	// map[dirpath]
	lockMap := map[string]*PackageLock{}
	invalidLocks := map[string]bool{}
	// map[dirpath]
	nodeMap := map[string]*PackageJson{}
	// map[dirpath]
	yarnMap := map[string]map[string]*YarnLock{}
	pnpmFiles := map[string]*model.File{}

	// 将npm相关文件按上述方案分类
	for _, f := range files {

		dir := filepath.Dir(strings.ReplaceAll(f.Relpath(), `\`, `/`))
		dir = strings.ReplaceAll(dir, `\`, `/`)
		if isPnpmLock(f.Relpath()) {
			pnpmFiles[dir] = f
		}

		if filter.JavaScriptYarnLock(f.Relpath()) {
			yarnMap[dir] = ParseYarnLock(f)
		}

		if filter.JavaScriptPackageJson(f.Relpath()) {
			var js *PackageJson
			f.OpenReader(func(reader io.Reader) {
				js = readJson[PackageJson](reader)
				if js == nil {
					return
				}
				if js.Dependencies == nil {
					js.Dependencies = map[string]string{}
				}
				// 记录peerDependencies
				for k, v := range js.PeerDependencies {
					js.Dependencies[k] = v
				}
				js.File = f
				if strings.Contains(f.Relpath(), "node_modules") {
					nodeMap[dir] = js
				} else {
					jsonMap[dir] = js
					jsonNameMap[js.Name] = js
				}
			})
		}

		if filter.JavaScriptPackageLock(f.Relpath()) {
			err := f.OpenReader(func(reader io.Reader) {
				lock, err := readPackageLock(reader)
				if err != nil {
					invalidLocks[dir] = true
					model.AddDiagnostic(ctx, fmt.Sprintf("invalid %s: %v; dependency data may be incomplete", f.Relpath(), err))
					return
				}
				lock.File = f
				lockMap[dir] = lock
			})
			if err != nil {
				invalidLocks[dir] = true
				model.AddDiagnostic(ctx, fmt.Sprintf("reading %s: %v; dependency data may be incomplete", f.Relpath(), err))
			}
		}
	}

	pnpmClaimed := scanPnpm(ctx, pnpmFiles, jsonMap, call)
	// 遍历非node_modules下的package.json
	for dir, js := range jsonMap {
		if invalidLocks[dir] || pnpmClaimed[dir] {
			continue
		}

		// 尝试从package-lock.json获取
		if lock, ok := lockMap[dir]; ok {
			call(js.File, ParsePackageJsonWithLock(js, lock))
			continue
		}

		// 尝试从yarn.lock获取
		if js.File != nil {
			if yarn, ok := yarnMap[dir]; ok {
				call(js.File, ParsePackageJsonWithYarnLock(js, yarn))
				continue
			}
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		// 尝试从node_modules及外部源获取
		call(js.File, ParsePackageJsonWithNode(js, nodeMap, jsonNameMap))
	}

	// A package-lock.json is sufficient input when its package.json is absent.
	for dir, lock := range lockMap {
		if pnpmClaimed[dir] || pnpmFiles[dir] != nil {
			continue
		}
		if _, hasPackageJson := jsonMap[dir]; hasPackageJson || lock.File == nil {
			continue
		}
		pkg := packageJsonFromLock(lock, lock.File)
		if graph := ParsePackageJsonWithLock(pkg, lock); graph != nil {
			call(lock.File, graph)
		}
	}
}

func packageJsonFromLock(lock *PackageLock, file *model.File) *PackageJson {
	pkg := &PackageJson{
		Name:            lock.Name,
		Version:         lock.Version,
		Dependencies:    map[string]string{},
		DevDependencies: map[string]string{},
		File:            file,
	}
	if root := lock.Packages[""]; root != nil {
		if root.Name != "" {
			pkg.Name = root.Name
		}
		if root.Version != "" {
			pkg.Version = root.Version
		}
		for name, version := range root.Dependencies {
			pkg.Dependencies[name] = version
		}
		for name, version := range root.DevDependencies {
			pkg.DevDependencies[name] = version
		}
		for name, version := range root.OptionalDependencies {
			pkg.Dependencies[name] = version
		}
		pkg.PeerDependencies = root.PeerDependencies
		pkg.PeerDependenciesMeta = root.PeerDependenciesMeta
	}
	if lock.LockfileVersion == 1 {
		for name, dep := range lock.Dependencies {
			if dep == nil {
				continue
			}
			if dep.Develop {
				pkg.DevDependencies[name] = dep.Version
			} else {
				pkg.Dependencies[name] = dep.Version
			}
		}
	}
	return pkg
}

var defaultNpmRepo = []common.RepoConfig{
	{Url: "https://r.cnpmjs.org/"},
}

func RegisterNpmRepo(repos ...common.RepoConfig) {
	newRepo := common.TrimRepo(repos...)
	if len(newRepo) > 0 {
		defaultNpmRepo = newRepo
	}
}
