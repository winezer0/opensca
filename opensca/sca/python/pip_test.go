package python

import (
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestRequirementsManifestEntryPoints applies the policy to both supported manifest entry points.
func TestRequirementsManifestEntryPoints(t *testing.T) {
	for _, name := range []string{"requirements.txt", "requirements.in"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name)
			if err := os.WriteFile(path, []byte("package[extra]>=1.9,>=1.10\nunknown>1.0\n"), 0600); err != nil {
				t.Fatal(err)
			}
			file := model.NewFile(path, path)
			parse := ParseRequirementTxt
			if name == "requirements.in" {
				parse = ParseRequirementIn
			}
			graph := parse(file)
			actual := map[string]string{}
			for _, child := range graph.Children {
				actual[child.Name] = child.Version
			}
			want := map[string]string{"package": "1.10", "unknown": ""}
			if !reflect.DeepEqual(actual, want) {
				t.Fatalf("manifest components = %#v, want %#v", actual, want)
			}
		})
	}
}

func TestRequirementManifestsKeepDistinctSelectedVersions(t *testing.T) {
	root := t.TempDir()
	manifests := map[string]string{
		"requirements.txt":                 "aiohttp==3.14.4\n",
		"base/apis/imgen/requirements.txt": "aiohttp>=3.8.0\n",
		"base/apis/vgen/requirements.txt":  "aiohttp>=3.8.0\n",
	}
	components := make(map[string]bool)
	for relpath, contents := range manifests {
		path := filepath.Join(root, filepath.FromSlash(relpath))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		graph := ParseRequirementTxt(model.NewFile(path, relpath))
		if graph.Path != relpath {
			t.Fatalf("manifest graph path = %q, want %q", graph.Path, relpath)
		}
		if len(graph.Children) != 1 || graph.Children[0].Name != "aiohttp" {
			t.Fatalf("manifest %s components = %#v", relpath, graph.Children)
		}
		components[model.Purl("", graph.Children[0].Name, graph.Children[0].Version, model.Lan_Python)] = true
	}
	want := map[string]bool{"pkg:pypi/aiohttp@3.14.4": true, "pkg:pypi/aiohttp@3.8.0": true}
	if !reflect.DeepEqual(components, want) {
		t.Fatalf("manifest PURLs = %#v, want %#v", components, want)
	}
}

func TestPipfileTOML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Pipfile")
	data := `[packages]
plain = "*"
pinned = "==1.2.3"
table = {version = "==2.0", extras = ["test"]}
[dev-packages]
pytest = "==7.4.0"
`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	r := ParsePipfile(model.NewFile(path, path))
	want := map[string]string{"plain": "*", "pinned": "1.2.3", "table": "2.0", "pytest": "7.4.0"}
	for _, n := range r.Children {
		if n.Version != want[n.Name] {
			t.Errorf("%s version %s", n.Name, n.Version)
		}
		if n.Develop != (n.Name == "pytest") {
			t.Errorf("%s development flag", n.Name)
		}
		delete(want, n.Name)
	}
	if len(want) > 0 {
		t.Fatal("missing packages", want)
	}
}
