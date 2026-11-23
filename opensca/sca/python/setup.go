package python

import (
	_ "embed"
	"io"
	"regexp"

	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
)

// ParseSetup 解析setup.py
func ParseSetup(file *model.File) *model.DepGraph {

	root := &model.DepGraph{Path: file.Relpath()}

	// 静态解析
	file.OpenReader(func(reader io.Reader) {
		data, err := io.ReadAll(reader)
		if err != nil {
			return
		}
		reg := regexp.MustCompile(`install_requires\s*=\s*\[([^\]]+)\]`)
		requires := reg.FindStringSubmatch(string(data))
		if len(requires) < 2 {
			return
		}
		for _, literal := range regexp.MustCompile(`['"]([^'"]+)['"]`).FindAllStringSubmatch(requires[1], -1) {
			if item, ok := parseRequirementDeclaration(literal[1]); ok {
				root.AppendChild(&model.DepGraph{Name: item.name, Version: item.version, DeclaredVersion: item.constraint})
			}
		}
	})

	return root
}
