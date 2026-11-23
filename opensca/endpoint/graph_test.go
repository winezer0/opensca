package endpoint

import (
	"context"
	"reflect"
	"testing"

	"github.com/winezer0/opensca/versionaudit"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
)

type catalog struct {
	versions []string
	calls    int
}

// Versions supplies a deterministic catalog without network access.
func (d *catalog) Versions(context.Context, versionaudit.Package) ([]string, error) {
	d.calls++
	return d.versions, nil
}

// TestExpandRangesPreservesParentsAndStopsCandidateTransitives verifies graph evidence boundaries.
func TestExpandRangesPreservesParentsAndStopsCandidateTransitives(t *testing.T) {
	root := &model.DepGraph{Project: true, Name: "project"}
	declared := &model.DepGraph{Name: "pkg", DeclaredVersion: ">1.0 <2.0", Version: ">1.0 <2.0", Language: model.Lan_JavaScript, Direct: true, Path: "package.json"}
	declared.AppendChild(&model.DepGraph{Name: "unverified", Version: "7.0", Language: model.Lan_JavaScript})
	root.AppendChild(declared)
	directory := &catalog{versions: []string{"2.0", "1.9", "1.1", "1.0"}}
	got := Expand(context.Background(), root, directory)
	if len(got) != 1 || len(got[0].Children) != 2 {
		t.Fatalf("graph=%#v", got)
	}
	versions := []string{}
	for _, node := range got[0].Children {
		versions = append(versions, node.Version)
		if node.DeclaredVersion != declared.DeclaredVersion || node.VersionSource != "published_endpoint" || !node.Direct || node.Path != "package.json" || len(node.Children) != 0 {
			t.Fatalf("candidate=%#v", node)
		}
	}
	if !reflect.DeepEqual(versions, []string{"1.1", "1.9"}) {
		t.Fatalf("versions=%v", versions)
	}
	if declared.Version != ">1.0 <2.0" || len(declared.Children) != 1 {
		t.Fatal("original graph mutated")
	}
}

// TestActualAndExactKeepVerifiedChildren avoids unnecessary catalog calls.
func TestActualAndExactKeepVerifiedChildren(t *testing.T) {
	for _, declaration := range []string{"", "==1.5"} {
		root := &model.DepGraph{Name: "pkg", Version: "1.5", DeclaredVersion: declaration, Language: model.Lan_Python}
		root.AppendChild(&model.DepGraph{Name: "child", Version: "1.0", Language: model.Lan_Python})
		directory := &catalog{}
		got := Expand(context.Background(), root, directory)
		if len(got) != 1 || len(got[0].Children) != 1 || directory.calls != 0 {
			t.Fatalf("graph=%#v calls=%d", got, directory.calls)
		}
	}
}

// TestExpandFallbackAndEmptyCatalog differentiates unavailable from no releases.
func TestExpandFallbackAndEmptyCatalog(t *testing.T) {
	node := &model.DepGraph{Name: "pkg", Language: model.Lan_Python, DeclaredVersion: ">1.0,<2.0"}
	fallback := Expand(context.Background(), node, nil)
	if len(fallback) != 2 || fallback[0].Version != "1.0" || fallback[1].Version != "2.0" || fallback[0].VersionSource != "boundary_fallback" {
		t.Fatalf("fallback=%#v", fallback)
	}
	empty := Expand(context.Background(), node, &catalog{})
	if len(empty) != 1 || empty[0].Version != "" || empty[0].DeclaredVersion != node.DeclaredVersion || empty[0].VersionSource != "unresolved" {
		t.Fatalf("empty=%#v", empty)
	}
}
