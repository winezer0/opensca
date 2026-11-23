package python

import (
	"encoding/json"
	"github.com/BurntSushi/toml"
	"io"
	"strings"

	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/logs"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
)

func ParsePipfile(file *model.File) *model.DepGraph {

	pip := struct {
		DevPackages map[string]any `toml:"dev-packages"`
		Packages    map[string]any `toml:"packages"`
	}{}

	root := &model.DepGraph{Path: file.Relpath()}

	_dep := model.NewDepGraphMap(nil, func(s ...string) *model.DepGraph {
		return &model.DepGraph{Name: s[0], Version: strings.TrimPrefix(s[1], "=="), DeclaredVersion: s[1]}
	}).LoadOrStore

	file.OpenReader(func(reader io.Reader) {
		if _, err := toml.NewDecoder(reader).Decode(&pip); err != nil {
			logs.Warnf("unmarshal file %s err: %s", file.Relpath(), err)
		}
	})

	versionOf := func(value any) string {
		v, _ := value.(string)
		if table, ok := value.(map[string]any); ok {
			v, _ = table["version"].(string)
		}
		return v
	}
	for name, version := range pip.Packages {
		root.AppendChild(_dep(name, versionOf(version)))
	}
	for name, version := range pip.DevPackages {
		dep := _dep(name, versionOf(version))
		if dep == nil {
			continue
		}
		dep.Develop = true
		root.AppendChild(dep)
	}

	return root
}

func ParsePipfileLock(file *model.File) *model.DepGraph {

	lock := struct {
		Default map[string]struct {
			Version string `json:"version"`
		} `json:"default"`
	}{}

	root := &model.DepGraph{Path: file.Relpath()}

	_dep := model.NewDepGraphMap(nil, func(s ...string) *model.DepGraph { return &model.DepGraph{Name: s[0], Version: s[1]} }).LoadOrStore

	file.OpenReader(func(reader io.Reader) {
		if err := json.NewDecoder(reader).Decode(&lock); err != nil {
			logs.Warnf("unmarshal file %s err: %s", file.Relpath(), err)
		}
	})

	for name, v := range lock.Default {
		version := strings.TrimPrefix(v.Version, "==")
		root.AppendChild(_dep(name, version))
	}

	return root
}

// ParseRequirementTxt parses requirements.txt using the scan-version policy.
func ParseRequirementTxt(file *model.File) *model.DepGraph {
	return parseRequirementsFile(file)
}

// ParseRequirementIn parses requirements.in using the same scan-version policy.
func ParseRequirementIn(file *model.File) *model.DepGraph {
	return parseRequirementsFile(file)
}

// parseRequirementsFile shares declaration handling between requirements manifests.
func parseRequirementsFile(file *model.File) *model.DepGraph {
	root := &model.DepGraph{Path: file.Relpath()}
	file.OpenReader(func(reader io.Reader) {
		data, err := io.ReadAll(reader)
		if err != nil {
			logs.Warnf("read requirements file %s: %s", file.Relpath(), err)
			return
		}
		for _, item := range parseRequirementDeclarations(string(data)) {
			root.AppendChild(&model.DepGraph{Name: item.name, Version: item.version, DeclaredVersion: item.constraint})
		}
	})
	return root
}
