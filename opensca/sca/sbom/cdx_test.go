package sbom

import (
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
	"os"
	"path/filepath"
	"testing"
)

func TestCycloneDXImportPreservesCyclesAndUnknown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bom.cdx.json")
	data := `{"bomFormat":"CycloneDX","specVersion":"1.4","version":1,"components":[{"type":"library","name":"a","version":"1","purl":"pkg:maven/g/a@1","bom-ref":"a"},{"type":"library","name":"b","version":"1","bom-ref":"b"}],"dependencies":[{"ref":"a","dependsOn":["b"]},{"ref":"b","dependsOn":["a"]}]}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	r := ParseCdxJson(model.NewFile(path, path))
	if r == nil {
		t.Fatal("missing cyclic graph")
	}
	count := 0
	r.ForEachNode(func(_, n *model.DepGraph) bool {
		if n.Name != "" {
			count++
		}
		if n.Name == "b" && (n.Language != model.Lan_None || n.PackageURL != "") {
			t.Fatal("guessed unknown ecosystem")
		}
		return true
	})
	if count != 2 {
		t.Fatal("lost components", count)
	}
	if err := os.WriteFile(path, []byte(`{"bomFormat":"Other","components":[{"name":"x"}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	if ParseCdxJson(model.NewFile(path, path)) != nil {
		t.Fatal("accepted unrelated document")
	}
}
