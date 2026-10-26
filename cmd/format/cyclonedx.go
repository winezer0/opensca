package format

import (
	"crypto/sha256"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/xmirrorsecurity/opensca-cli/v3/cmd/config"
	"github.com/xmirrorsecurity/opensca-cli/v3/cmd/detail"
)

// ComponentRef is stable across scans, including components without a PURL.
func ComponentRef(n *detail.DepDetailGraph) string {
	if p := n.Purl(); p != "" {
		return p
	}
	return fmt.Sprintf("urn:opensca:component:%x", sha256.Sum256([]byte(n.Key())))
}

// CycloneDXBOM preserves the graph and stable package identities.
func CycloneDXBOM(dep *detail.DepDetailGraph) *cyclonedx.BOM {
	bom := cyclonedx.NewBOM()
	components := []cyclonedx.Component{}
	edges := map[string]map[string]bool{}
	seen := map[string]bool{}
	if dep == nil {
		bom.Components = &components
		return bom
	}
	rootRef := ComponentRef(dep)
	rootName := dep.Name
	if rootName == "" {
		rootName = "scanned-project"
	}
	bom.Metadata = &cyclonedx.Metadata{Component: &cyclonedx.Component{BOMRef: rootRef, Type: cyclonedx.ComponentTypeApplication, Name: rootName, Version: dep.Version, PackageURL: dep.Purl()}}
	visited := map[*detail.DepDetailGraph]bool{}
	dep.ForEach(func(n *detail.DepDetailGraph) bool {
		if visited[n] {
			return false
		}
		visited[n] = true
		ref := ComponentRef(n)
		if edges[ref] == nil {
			edges[ref] = map[string]bool{}
		}
		if n != dep && ref != rootRef && !seen[ref] && n.Name != "" {
			seen[ref] = true
			typ := cyclonedx.ComponentTypeLibrary
			if n.Project {
				typ = cyclonedx.ComponentTypeApplication
			}
			purl := n.Purl()
			if n.Project && !config.Conf().IncludeProject {
				purl = ""
			}
			components = append(components, cyclonedx.Component{BOMRef: ref, Type: typ, Group: n.Vendor, Name: n.Name[strings.LastIndex(n.Name, "/")+1:], Version: n.Version, PackageURL: purl})
		}
		pending := append([]*detail.DepDetailGraph(nil), n.Children...)
		anonymous := map[*detail.DepDetailGraph]bool{}
		for len(pending) > 0 {
			child := pending[0]
			pending = pending[1:]
			if child.Name == "" && !anonymous[child] {
				anonymous[child] = true
				pending = append(pending, child.Children...)
			} else if child.Name != "" {
				if cr := ComponentRef(child); cr != ref {
					edges[ref][cr] = true
				}
			}
		}
		return true
	})
	valid := map[string]bool{rootRef: true}
	for _, c := range components {
		valid[c.BOMRef] = true
	}
	refs := []string{}
	for ref := range edges {
		if valid[ref] {
			refs = append(refs, ref)
		}
	}
	sort.Strings(refs)
	dependencies := []cyclonedx.Dependency{}
	for _, ref := range refs {
		children := []string{}
		for child := range edges[ref] {
			if valid[child] {
				children = append(children, child)
			}
		}
		sort.Strings(children)
		dependencies = append(dependencies, cyclonedx.Dependency{Ref: ref, Dependencies: &children})
	}
	sort.Slice(components, func(i, j int) bool { return components[i].BOMRef < components[j].BOMRef })
	bom.Components, bom.Dependencies = &components, &dependencies
	return bom
}

func cyclonedxbom(dep *detail.DepDetailGraph) *cyclonedx.BOM { return CycloneDXBOM(dep) }

func reportBOM(report Report) *cyclonedx.BOM {
	bom := CycloneDXBOM(report.DepDetailGraph)
	props := []cyclonedx.Property{}
	missingPURL := map[string]bool{}
	if report.DepDetailGraph != nil {
		report.DepDetailGraph.ForEach(func(n *detail.DepDetailGraph) bool {
			if n != report.DepDetailGraph && !n.Project && n.Name != "" && n.Purl() == "" {
				identity := n.Name + "@" + n.Version
				if !missingPURL[identity] {
					missingPURL[identity] = true
					props = append(props, cyclonedx.Property{
						Name:  "opensca:diagnostic",
						Value: "dependency has no valid PURL; OSV matching may be incomplete: " + identity,
					})
				}
			}
			return true
		})
	}
	for _, issue := range report.TaskInfo.Diagnostics {
		props = append(props, cyclonedx.Property{Name: "opensca:diagnostic", Value: issue})
	}
	for _, issue := range report.DepDetailGraph.Issues {
		props = append(props, cyclonedx.Property{Name: "opensca:diagnostic", Value: issue})
	}
	if report.TaskInfo.ErrorString != "" {
		props = append(props, cyclonedx.Property{Name: "opensca:error", Value: report.TaskInfo.ErrorString})
	}
	if len(props) > 0 {
		bom.Properties = &props
	}
	return bom
}

func CycloneDXJson(report Report, out string) error {
	bom := reportBOM(report)
	return outWrite(out, func(w io.Writer) error {
		return cyclonedx.NewBOMEncoder(w, cyclonedx.BOMFileFormatJSON).SetPretty(true).Encode(bom)
	})
}

func CycloneDXXml(report Report, out string) error {
	bom := reportBOM(report)
	return outWrite(out, func(w io.Writer) error {
		return cyclonedx.NewBOMEncoder(w, cyclonedx.BOMFileFormatXML).SetPretty(true).Encode(bom)
	})
}
