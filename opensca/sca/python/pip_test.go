package python

import (
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
	"os"
	"path/filepath"
	"testing"
)

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
	want := map[string]string{"plain": "", "pinned": "1.2.3", "table": "2.0", "pytest": "7.4.0"}
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
