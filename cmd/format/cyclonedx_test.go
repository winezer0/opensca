package format

import (
	"encoding/json"
	"github.com/xmirrorsecurity/opensca-cli/v3/cmd/config"
	"github.com/xmirrorsecurity/opensca-cli/v3/cmd/detail"
	"os"
	"path/filepath"
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
	foundEdge := false
	for _, e := range *bom.Dependencies {
		if e.Ref == ComponentRef(root) {
			for _, child := range *e.Dependencies {
				foundEdge = foundEdge || child == ComponentRef(module)
			}
		}
	}
	if !foundEdge {
		t.Fatal("anonymous container lost root dependency")
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

func TestCycloneDXWriteFailure(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := Save(Report{DepDetailGraph: component("root")}, filepath.Join(file, "bom.cdx.json")); err == nil {
		t.Fatal("write failure reported as success")
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
