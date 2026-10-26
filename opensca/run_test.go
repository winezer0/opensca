package opensca

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/xmirrorsecurity/opensca-cli/v3/cmd/config"
)

func TestDirectoryDoesNotReingestSBOM(t *testing.T) {
	before := *config.Conf()
	t.Cleanup(func() { *config.Conf() = before })
	config.Conf().Offline = true
	dir := t.TempDir()
	path := filepath.Join(dir, "old.cdx.json")
	data := `{"bomFormat":"CycloneDX","specVersion":"1.4","version":1,"components":[{"type":"library","name":"a","version":"1","purl":"pkg:maven/g/a@1","bom-ref":"a"}]}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		r := RunTask(context.Background(), &TaskArg{DataOrigin: dir})
		if r.Error != nil || len(r.Deps) != 0 {
			t.Fatal(r)
		}
	}
	r := RunTask(context.Background(), &TaskArg{DataOrigin: path, InputType: "sbom"})
	if r.Error != nil || len(r.Deps) != 1 || len(r.Deps[0].Children) != 1 {
		t.Fatalf("explicit SBOM: %+v", r)
	}
}
