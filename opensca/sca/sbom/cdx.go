package sbom

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
)

func ParseCdxJson(f *model.File) *model.DepGraph {
	bom := &cyclonedx.BOM{}
	var decodeErr error
	f.OpenReader(func(reader io.Reader) {
		decodeErr = json.NewDecoder(reader).Decode(&bom)
	})
	if decodeErr != nil {
		return nil
	}
	return parseCdxBom(f, bom)
}

func ParseCdxXml(f *model.File) *model.DepGraph {
	bom := &cyclonedx.BOM{}
	var decodeErr error
	f.OpenReader(func(reader io.Reader) {
		decodeErr = xml.NewDecoder(reader).Decode(&bom)
	})
	if decodeErr != nil {
		return nil
	}
	return parseCdxBom(f, bom)
}

func parseCdxBom(f *model.File, bom *cyclonedx.BOM) *model.DepGraph {

	if bom == nil {
		return nil
	}

	if bom.BOMFormat != "CycloneDX" && !strings.HasPrefix(bom.XMLNS, "http://cyclonedx.org/schema/bom/") {
		return nil
	}

	if bom.Components == nil || len(*bom.Components) == 0 {
		return nil
	}

	depRefMap := map[string]*model.DepGraph{}
	_dep := model.NewDepGraphMap(func(s ...string) string {
		return s[0]
	}, func(s ...string) *model.DepGraph {
		return &model.DepGraph{
			Vendor:  s[1],
			Name:    s[2],
			Version: s[3],
		}
	}).LoadOrStore

	for i, d := range *bom.Components {
		if d.BOMRef == "" {
			d.BOMRef = fmt.Sprintf("component-%d", i)
		}

		if d.PackageURL != "" {
			vendor, name, version, language := model.ParsePurl(d.PackageURL)
			if name != "" {
				dep := _dep(d.BOMRef, vendor, name, version)
				dep.Language = language
				dep.PackageURL = model.CanonicalPurl(d.PackageURL)
				depRefMap[d.BOMRef] = dep
				continue
			}
		}

		if d.Name != "" {
			depRefMap[d.BOMRef] = _dep(d.BOMRef, d.Author, d.Name, d.Version)
		}
	}

	if bom.Dependencies != nil {
		for _, d := range *bom.Dependencies {
			dep, ok := depRefMap[d.Ref]
			if !ok || d.Dependencies == nil {
				continue
			}
			for _, subRef := range *d.Dependencies {
				dep.AppendChild(depRefMap[subRef])
			}
		}
	}

	root := &model.DepGraph{Path: f.Relpath()}
	for _, dep := range depRefMap {
		if len(dep.Parents) == 0 {
			root.AppendChild(dep)
		}
	}
	// Preserve components in disconnected cycles as well as ordinary roots.
	visited := map[*model.DepGraph]bool{}
	visit := func(n *model.DepGraph) {
		n.ForEachNode(func(_, child *model.DepGraph) bool {
			if visited[child] {
				return false
			}
			visited[child] = true
			return true
		})
	}
	visit(root)
	for _, dep := range depRefMap {
		if !visited[dep] {
			root.AppendChild(dep)
			visit(dep)
		}
	}

	return root
}
