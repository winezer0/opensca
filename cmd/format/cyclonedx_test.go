package format

import (
	"encoding/json"
	"github.com/xmirrorsecurity/opensca-cli/v3/cmd/config"
	"github.com/xmirrorsecurity/opensca-cli/v3/cmd/detail"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func component(name string) *detail.DepDetailGraph {
	return &detail.DepDetailGraph{Dep: detail.Dep{Vendor: "g", Name: name, Version: "1", Language: "Java"}}
}

func TestCycloneDXProjectAndAnonymousNodes(t *testing.T) {
	before := config.Conf().IncludeProject
	t.Cleanup(func() { config.Conf().IncludeProject = before })
	config.Conf().IncludeProject = false
	root, module, lib := component("root"), component("module"), component("lib")
	root.Project = true
	module.Project = true
	container := &detail.DepDetailGraph{Children: []*detail.DepDetailGraph{module}}
	root.Children = []*detail.DepDetailGraph{container}
	module.Children = []*detail.DepDetailGraph{lib}
	bom := CycloneDXBOM(root)
	if len(*bom.Components) != 2 {
		t.Fatal("lost components")
	}
	edges := map[string]map[string]bool{}
	for _, e := range *bom.Dependencies {
		children := map[string]bool{}
		for _, child := range *e.Dependencies {
			children[child] = true
		}
		edges[e.Ref] = children
	}
	if !edges[ComponentRef(root)][ComponentRef(module)] {
		t.Fatal("anonymous container lost root dependency")
	}
	if !edges[ComponentRef(module)][ComponentRef(lib)] {
		t.Fatal("indirect dependency edge was lost")
	}
	validRefs := map[string]bool{bom.Metadata.Component.BOMRef: true}
	for _, c := range *bom.Components {
		validRefs[c.BOMRef] = true
	}
	for _, e := range *bom.Dependencies {
		if !validRefs[e.Ref] {
			t.Fatalf("dependency references missing component %q", e.Ref)
		}
		for _, child := range *e.Dependencies {
			if !validRefs[child] {
				t.Fatalf("dependency edge references missing child %q", child)
			}
		}
	}
	for _, c := range *bom.Components {
		if c.Name == "module" && c.PackageURL != "" {
			t.Fatal("project unexpectedly matchable")
		}
		if c.Name == "lib" && c.PackageURL == "" {
			t.Fatal("external dependency PURL lost")
		}
	}
	config.Conf().IncludeProject = true
	for _, c := range *CycloneDXBOM(root).Components {
		if c.Name == "module" && c.PackageURL == "" {
			t.Fatal("include-project ignored")
		}
	}
}

func TestCycloneDXAnonymousRootKeepsDirectDependency(t *testing.T) {
	root := &detail.DepDetailGraph{}
	direct := component("direct")
	root.Children = []*detail.DepDetailGraph{direct}

	bom := CycloneDXBOM(root)
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		t.Fatal("anonymous project root missing metadata component")
	}
	if bom.Metadata.Component.Name != "scanned-project" {
		t.Fatalf("anonymous project name = %q, want scanned-project", bom.Metadata.Component.Name)
	}
	found := false
	for _, dependency := range *bom.Dependencies {
		if dependency.Ref != bom.Metadata.Component.BOMRef {
			continue
		}
		for _, child := range *dependency.Dependencies {
			found = found || child == ComponentRef(direct)
		}
	}
	if !found {
		t.Fatal("anonymous project root lost its direct dependency")
	}
}

func TestCycloneDXPreservesKnownDirectness(t *testing.T) {
	root := &model.DepGraph{Project: true, Name: "demo", Language: model.Lan_Golang}
	direct := &model.DepGraph{Name: "example.com/direct", Version: "1.0.0", Language: model.Lan_Golang, Direct: true, DirectKnown: true}
	indirect := &model.DepGraph{Name: "example.com/indirect", Version: "1.1.0", Language: model.Lan_Golang, DirectKnown: true}
	root.AppendChild(direct)
	root.AppendChild(indirect)
	graph := detail.NewDepDetailGraph(root)
	bom := CycloneDXBOM(graph)

	rootRef := bom.Metadata.Component.BOMRef
	foundRoot := false
	for _, dependency := range *bom.Dependencies {
		if dependency.Ref != rootRef {
			continue
		}
		foundRoot = true
		if len(*dependency.Dependencies) != 1 || (*dependency.Dependencies)[0] != ComponentRef(graph.Children[0]) {
			t.Fatalf("root dependencies = %v, want only the direct module", *dependency.Dependencies)
		}
	}
	if !foundRoot {
		t.Fatal("CycloneDX dependency graph omitted the project root")
	}

	properties := map[string]string{}
	for _, component := range *bom.Components {
		if component.Properties == nil {
			continue
		}
		for _, property := range *component.Properties {
			if property.Name == "tanspec:direct" {
				properties[component.Name] = property.Value
			}
		}
	}
	if properties["direct"] != "true" || properties["indirect"] != "false" {
		t.Fatalf("directness properties = %v, want direct=true and indirect=false", properties)
	}
}

func TestCycloneDXWriteFailure(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := Save(Report{DepDetailGraph: component("root")}, filepath.Join(file, "bom.cdx.json")); err == nil {
		t.Fatal("write failure reported as success")
	}
}

func TestCycloneDXMissingPURLDiagnostic(t *testing.T) {
	root := component("root")
	root.Project = true
	root.Children = []*detail.DepDetailGraph{{Dep: detail.Dep{Name: "unmapped-package", Version: "1.2.3", Language: "Unknown"}}}

	bom := reportBOM(Report{DepDetailGraph: root})
	foundComponentWithoutPURL := false
	for _, component := range *bom.Components {
		if component.Name == "unmapped-package" && component.PackageURL == "" {
			foundComponentWithoutPURL = true
		}
	}
	if !foundComponentWithoutPURL {
		t.Fatalf("unmapped component should remain in the BOM without a PURL: %+v", bom.Components)
	}
	found := false
	for _, property := range *bom.Properties {
		if property.Name == "opensca:diagnostic" && strings.Contains(property.Value, "dependency has no valid PURL") && strings.Contains(property.Value, "unmapped-package@1.2.3") {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing PURL diagnostic not present: %+v", bom.Properties)
	}
}

func TestCycloneDXGraphIdentity(t *testing.T) {
	root, a, b, c1, c2 := component("root"), component("a"), component("b"), component("c"), component("c")
	root.Project = true
	root.Children = []*detail.DepDetailGraph{a, b}
	a.Children = []*detail.DepDetailGraph{c1}
	b.Children = []*detail.DepDetailGraph{c2}
	unknown := &detail.DepDetailGraph{Dep: detail.Dep{Name: "unknown", Version: "1"}}
	a.Children = append(a.Children, unknown)
	bom := CycloneDXBOM(root)
	if len(*bom.Components) != 4 {
		t.Fatalf("components: %+v", *bom.Components)
	}
	refs := map[string]bool{bom.Metadata.Component.BOMRef: true}
	for _, c := range *bom.Components {
		if refs[c.BOMRef] {
			t.Fatal("duplicate", c.BOMRef)
		}
		refs[c.BOMRef] = true
	}
	for _, e := range *bom.Dependencies {
		if !refs[e.Ref] {
			t.Fatal("dangling", e.Ref)
		}
		for _, ref := range *e.Dependencies {
			if !refs[ref] {
				t.Fatal("dangling child", ref)
			}
		}
	}
	if len(*(*bom.Dependencies)[0].Dependencies) == 0 {
		t.Fatal("missing graph edges")
	}
	x, _ := json.Marshal(bom.Components)
	a.ID = "different-random-id"
	y, _ := json.Marshal(CycloneDXBOM(root).Components)
	if string(x) != string(y) {
		t.Fatal("unstable output")
	}
}
