package javascript

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
)

func scanLockFixture(t *testing.T, data []byte, paired bool) ([]*model.DepGraph, []string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "package-lock.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	files := []*model.File{model.NewFile(path, "package-lock.json")}
	if paired {
		var lock struct{ Packages map[string]json.RawMessage }
		_ = json.Unmarshal(data, &lock)
		manifest := lock.Packages[""]
		if len(manifest) == 0 {
			manifest = []byte("{\"name\":\"demo\"}")
		}
		path := filepath.Join(dir, "package.json")
		if err := os.WriteFile(path, manifest, 0600); err != nil {
			t.Fatal(err)
		}
		files = append(files, model.NewFile(path, "package.json"))
	}
	ctx, diagnostics := model.WithDiagnostics(context.Background())
	var graphs []*model.DepGraph
	Sca{}.Sca(ctx, nil, files, func(_ *model.File, roots ...*model.DepGraph) { graphs = append(graphs, roots...) })
	return graphs, diagnostics.List()
}

func TestLockfileNestedResolution(t *testing.T) {
	data, err := os.ReadFile("testdata/lockfile-nested.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []int{2, 3} {
		for _, paired := range []bool{false, true} {
			t.Run(fmt.Sprintf("v%d/paired=%v", version, paired), func(t *testing.T) {
				contents := []byte(strings.Replace(string(data), "\"lockfileVersion\": 3", fmt.Sprintf("\"lockfileVersion\": %d", version), 1))
				graphs, issues := scanLockFixture(t, contents, paired)
				if len(graphs) != 1 || len(issues) != 0 {
					t.Fatalf("graphs=%d diagnostics=%v", len(graphs), issues)
				}
				root := graphs[0]
				child := func(parent *model.DepGraph, name string) *model.DepGraph {
					for _, n := range parent.Children {
						if n.Name == name {
							return n
						}
					}
					t.Fatalf("missing %s under %s", name, parent.Name)
					return nil
				}
				a := child(child(root, "wrapper-a"), "common")
				b := child(child(root, "wrapper-b"), "common")
				if a == b {
					t.Fatal("distinct installation paths collapsed")
				}
				if child(a, "lodash").Version != "4.17.20" || child(b, "lodash").Version != "4.17.21" {
					t.Fatal("nested dependency versions lost")
				}
				root.ForEachNode(func(_, n *model.DepGraph) bool {
					if n.Name == "shared" && n.Develop {
						t.Error("runtime dependency classified as development-only")
					}
					if n.Name == "dev-tool" && !n.Develop {
						t.Error("development classification lost")
					}
					return true
				})
			})
		}
	}
}

func TestLockfileWorkspaceWithoutManifests(t *testing.T) {
	data, err := os.ReadFile("testdata/lockfile-workspace.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []int{2, 3} {
		contents := []byte(strings.Replace(string(data), "\"lockfileVersion\": 3", fmt.Sprintf("\"lockfileVersion\": %d", version), 1))
		graphs, issues := scanLockFixture(t, contents, false)
		if len(graphs) != 1 || len(issues) != 0 {
			t.Fatalf("v%d graphs=%d diagnostics=%v", version, len(graphs), issues)
		}
		found := false
		graphs[0].ForEachNode(func(_, n *model.DepGraph) bool {
			if n.Name == "app" {
				if !n.Project {
					t.Error("local workspace must be identified as a project")
				}
				for _, c := range n.Children {
					found = found || c.Name == "lodash" && c.Version == "4.17.21"
				}
			}
			return true
		})
		if !found {
			t.Fatalf("v%d workspace dependency edge missing", version)
		}
	}
}

func TestInvalidLockfileDiagnostics(t *testing.T) {
	cases := []struct{ name, data string }{
		{"null-legacy-dependencies", "{\"name\":\"demo\",\"lockfileVersion\":1,\"dependencies\":null}"},
		{"invalid-json", "{"},
		{"null-document", "null"},
		{"missing-version", "{\"packages\":{\"\":{}}}"},
		{"unknown-version", "{\"lockfileVersion\":4,\"packages\":{\"\":{}}}"},
		{"wrong-version-type", "{\"lockfileVersion\":\"3\",\"packages\":{\"\":{}}}"},
		{"missing-root-v2", "{\"lockfileVersion\":2,\"packages\":{\"node_modules/lodash\":{\"version\":\"4.17.21\"}}}"},
		{"missing-root-v3", "{\"lockfileVersion\":3,\"packages\":{\"node_modules/lodash\":{\"version\":\"4.17.21\"}}}"},
		{"null-root", "{\"lockfileVersion\":3,\"packages\":{\"\":null}}"},
		{"null-package", "{\"lockfileVersion\":3,\"packages\":{\"\":{},\"node_modules/lodash\":null}}"},
		{"null-legacy-package", "{\"lockfileVersion\":1,\"dependencies\":{\"lodash\":null}}"},
		{"missing-package-version", "{\"lockfileVersion\":3,\"packages\":{\"\":{},\"node_modules/lodash\":{}}}"},
		{"missing-required-dependency", "{\"lockfileVersion\":3,\"packages\":{\"\":{\"dependencies\":{\"lodash\":\"4.17.21\"}}}}"},
		{"broken-link", "{\"lockfileVersion\":3,\"packages\":{\"\":{},\"node_modules/app\":{\"link\":true,\"resolved\":\"packages/missing\"}}}"},
	}
	for _, tc := range cases {
		for _, paired := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/paired=%v", tc.name, paired), func(t *testing.T) {
				graphs, issues := scanLockFixture(t, []byte(tc.data), paired)
				if len(graphs) != 0 || len(issues) == 0 {
					t.Fatalf("invalid lock accepted: graphs=%d diagnostics=%v", len(graphs), issues)
				}
				if !strings.Contains(strings.Join(issues, " "), "dependency data may be incomplete") {
					t.Fatal(issues)
				}
			})
		}
	}
}

func TestEmptyLockfile(t *testing.T) {
	for _, data := range []string{
		"{\"name\":\"empty\",\"lockfileVersion\":1}",
		"{\"lockfileVersion\":2,\"packages\":{\"\":{}}}",
		"{\"lockfileVersion\":3,\"packages\":{\"\":{}}}",
	} {
		graphs, issues := scanLockFixture(t, []byte(data), false)
		if len(graphs) != 1 || len(graphs[0].Children) != 0 || len(issues) != 0 {
			t.Fatalf("empty project rejected: %v %v", graphs, issues)
		}
	}
}
