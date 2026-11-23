package opensca

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xmirrorsecurity/opensca-cli/v3/cmd/config"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/sca"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/sca/cache"
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

func TestRunTaskUsesScopedCacheAndPreservesConfiguredCache(t *testing.T) {
	previous := *config.Conf()
	t.Cleanup(func() { *config.Conf() = previous })
	fallbackDirectory := t.TempDir()
	*config.Conf() = config.Config{CacheDir: fallbackDirectory}

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cache-probe.txt"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		taskCache string
		wantRoot  string
	}{
		{name: "configured CLI cache", wantRoot: fallbackDirectory},
		{name: "first task cache", taskCache: t.TempDir()},
		{name: "second task cache", taskCache: t.TempDir()},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			wantRoot := test.wantRoot
			if test.taskCache != "" {
				wantRoot = test.taskCache
			}
			probe := &cachePathProbe{}
			result := RunTask(context.Background(), &TaskArg{
				DataOrigin: root,
				InputType:  "project",
				Sca:        []sca.Sca{probe},
				CacheDir:   test.taskCache,
			})
			if result.Error != nil {
				t.Fatalf("RunTask() error = %v", result.Error)
			}
			wantPath := filepath.Join(wantRoot, "npm", "cache-probe.json")
			if probe.path != wantPath {
				t.Fatalf("cache path = %q, want %q", probe.path, wantPath)
			}
			if data, err := os.ReadFile(wantPath); err != nil || string(data) != "task-cache" {
				t.Fatalf("cache file = %q, %v", data, err)
			}
		})
	}
}

type cachePathProbe struct{ path string }

func (*cachePathProbe) Language() model.Language { return model.Lan_JavaScript }

func (*cachePathProbe) Filter(relpath string) bool {
	return filepath.Base(relpath) == "cache-probe.txt"
}

func (probe *cachePathProbe) Sca(_ context.Context, _ *model.File, _ []*model.File, _ model.ResCallback) {
	probe.path = cache.Path("", "cache-probe", "", model.Lan_JavaScript)
	cache.Save(probe.path, strings.NewReader("task-cache"))
}
