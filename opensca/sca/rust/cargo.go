package rust

import (
	"io"
	"strings"

	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/logs"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"

	"github.com/BurntSushi/toml"
)

// ParseCargoLock 解析Cargo.lock文件
func ParseCargoLock(file *model.File) *model.DepGraph {

	cargo := struct {
		Pkgs []struct {
			Name         string   `toml:"name"`
			Version      string   `toml:"version"`
			Source       string   `toml:"source"`
			Dependencies []string `toml:"dependencies"`
		} `toml:"package"`
	}{}

	file.OpenReader(func(reader io.Reader) {
		_, err := toml.NewDecoder(reader).Decode(&cargo)
		if err != nil {
			logs.Warnf("parse %s fail:%s", file.Relpath(), err)
		}
	})

	// 记录组件信息
	depMap := map[string]*model.DepGraph{}
	depKey := func(name, version string) string { return name + "\x00" + version }
	byName := map[string][]*model.DepGraph{}
	for _, c := range cargo.Pkgs {
		key := depKey(c.Name, c.Version)
		dep := depMap[key]
		if dep == nil {
			dep = &model.DepGraph{Name: c.Name, Version: c.Version, Project: c.Source == ""}
			depMap[key] = dep
			byName[c.Name] = append(byName[c.Name], dep)
		}
	}

	// 记录依赖关系
	for _, c := range cargo.Pkgs {
		dep := depMap[depKey(c.Name, c.Version)]
		for _, dependency := range c.Dependencies {
			parts := strings.Fields(dependency)
			if len(parts) == 0 {
				continue
			}
			name, version := parts[0], ""
			if len(parts) > 1 && !strings.HasPrefix(parts[1], "(") {
				version = parts[1]
			}
			if version != "" {
				dep.AppendChild(depMap[depKey(name, version)])
				continue
			}
			if len(byName[name]) == 1 {
				dep.AppendChild(byName[name][0])
			}
		}
	}

	root := &model.DepGraph{Path: file.Relpath()}
	for _, dep := range depMap {
		if len(dep.Parents) == 0 {
			root.AppendChild(dep)
		}
	}

	return root
}
