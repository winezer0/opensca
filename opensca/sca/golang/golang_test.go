package golang

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
)

// 取自 inott-epg-go 的真实片段：replace、本地目录替换、末尾的汇总行。
const sampleVendorModules = `# github.com/Jeffail/gabs v1.4.0
## explicit
github.com/Jeffail/gabs
# github.com/go-redis/redis v6.15.9+incompatible
## explicit; go 1.17
github.com/go-redis/redis
github.com/go-redis/redis/internal
# github.com/unrolled/render v1.5.0 => github.com/unrolled/render v0.0.0-20160218130117-198ad4d8b8a4
## explicit
github.com/unrolled/render
# github.com/old/local v1.2.0 => ./forks/local
github.com/old/local
# github.com/unrolled/render => github.com/unrolled/render v0.0.0-20160218130117-198ad4d8b8a4
`

func writeVendorModules(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "vendor"), 0o755); err != nil {
		t.Fatalf("mkdir vendor: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vendor", "modules.txt"), []byte(content), 0o644); err != nil {
		t.Fatalf("write modules.txt: %v", err)
	}
	return dir
}

func TestParseVendorModules(t *testing.T) {
	dir := writeVendorModules(t, sampleVendorModules)
	graph := ParseVendorModules(dir)
	if graph == nil {
		t.Fatal("ParseVendorModules returned nil")
	}

	type dep struct{ name, version string }
	var want = []dep{
		{"github.com/Jeffail/gabs", "v1.4.0"},
		// +incompatible 是版本号的一部分，不能剥掉。
		{"github.com/go-redis/redis", "v6.15.9+incompatible"},
		// replace 到同一模块的另一个版本：报实际编译的版本。
		{"github.com/unrolled/render", "v0.0.0-20160218130117-198ad4d8b8a4"},
		// replace 到本地目录：模块路径与版本都不变。
		{"github.com/old/local", "v1.2.0"},
	}
	if len(graph.Children) != len(want) {
		t.Fatalf("got %d children, want %d: %+v", len(graph.Children), len(want), graph.Children)
	}
	for i, w := range want {
		got := graph.Children[i]
		if got.Name != w.name || got.Version != w.version {
			t.Fatalf("child[%d] = %s@%s, want %s@%s", i, got.Name, got.Version, w.name, w.version)
		}
	}
}

func TestParseVendorModulesSkipsReplaceSummary(t *testing.T) {
	dir := writeVendorModules(t, "# github.com/a/b => github.com/fork/b v1.2.0\n")
	if graph := ParseVendorModules(dir); graph != nil {
		t.Fatalf("only replace summary lines must yield nil, got %+v", graph.Children)
	}
}

func TestParseVendorModulesMissing(t *testing.T) {
	if graph := ParseVendorModules(t.TempDir()); graph != nil {
		t.Fatal("missing modules.txt must yield nil so the caller falls back to go.mod")
	}
}

func writeGomod(t *testing.T, content string) *model.File {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	return model.NewFile(path, "go.mod")
}

func depsOf(graph *model.DepGraph) map[string]string {
	out := map[string]string{}
	for _, c := range graph.Children {
		out[c.Name] = c.Version
	}
	return out
}

func TestParseGomodReplace(t *testing.T) {
	f := writeGomod(t, `module demo

go 1.17

require (
	github.com/go-redis/redis v6.15.9+incompatible
	github.com/old/local v1.2.0
	golang.org/x/sys v0.6.0 // indirect
	github.com/a/b v1.0.0
)

replace golang.org/x/sys => golang.org/x/sys v0.0.0-20210112080510-489259a85091

replace (
	github.com/old/local => ./forks/local
	github.com/a/b => github.com/fork/b v1.2.0
)
`)
	deps := depsOf(ParseGomod(f))

	if got := deps["golang.org/x/sys"]; got != "v0.0.0-20210112080510-489259a85091" {
		t.Fatalf("x/sys = %q, want the replaced version", got)
	}
	if got := deps["github.com/go-redis/redis"]; got != "v6.15.9+incompatible" {
		t.Fatalf("go-redis = %q, want v6.15.9+incompatible", got)
	}
	// `=> ./local` 不能把组件删掉。
	if got, ok := deps["github.com/old/local"]; !ok || got != "v1.2.0" {
		t.Fatalf("local replace dropped the component: %v", deps)
	}
	// 换成另一个模块：报实际参与编译的那个，原模块不应留下空壳。
	if _, ok := deps["github.com/a/b"]; ok {
		t.Fatalf("replaced module still present: %v", deps)
	}
	if got := deps["github.com/fork/b"]; got != "v1.2.0" {
		t.Fatalf("fork/b = %q, want v1.2.0", got)
	}
}

func TestParseGomodReplaceUnrequiredModule(t *testing.T) {
	// replace 一个没被 require 的模块不会影响构建结果，不能凭空产生组件。
	f := writeGomod(t, `module demo

go 1.17

require github.com/a/b v1.0.0

replace github.com/ghost/mod => github.com/other/mod v2.0.0
`)
	deps := depsOf(ParseGomod(f))
	if _, ok := deps["github.com/other/mod"]; ok {
		t.Fatalf("replace of an unrequired module must be ignored: %v", deps)
	}
	if len(deps) != 1 {
		t.Fatalf("deps = %v, want only github.com/a/b", deps)
	}
}

func TestGomodModuleName(t *testing.T) {
	f := writeGomod(t, "// header comment\nmodule inott-epg/inott-epg-go\n\ngo 1.17\n")
	if got := GomodModuleName(f); got != "inott-epg/inott-epg-go" {
		t.Fatalf("module name = %q", got)
	}
}

func TestInVendorDir(t *testing.T) {
	cases := map[string]bool{
		"go.mod":             false,
		"vendor/modules.txt": true,
		"vendor/github.com/json-iterator/go/Gopkg.lock":       true,
		"sub/vendor/github.com/modern-go/reflect2/Gopkg.lock": true,
		"sub/go.mod":      false,
		"myvendor/go.mod": false,
	}
	for rel, want := range cases {
		if got := inVendorDir(rel); got != want {
			t.Fatalf("inVendorDir(%q) = %v, want %v", rel, got, want)
		}
	}
}
