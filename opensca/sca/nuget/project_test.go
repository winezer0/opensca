package nuget

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xmirrorsecurity/opensca-cli/v3/cmd/config"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
)

const testAssets = `{
 "version":3,
 "targets":{"net8.0":{
  "Wrapper/1.2.0":{"type":"package","dependencies":{"Leaf":"[1.0.0, 2.0.0)"}},
  "Other/1.0.0":{"type":"package","dependencies":{"Leaf":"1.0.0"}},
  "Leaf/1.0.0":{"type":"package"},
  "Child/1.0.0":{"type":"project","dependencies":{"Leaf":"1.0.0"}}
 }},
 "libraries":{
  "Wrapper/1.2.0":{"type":"package"},"Other/1.0.0":{"type":"package"},
  "Leaf/1.0.0":{"type":"package"},"Child/1.0.0":{"type":"project","msbuildProject":"../Child/Child.csproj"}
 },
 "project":{"version":"1.0.0","restore":{
  "projectName":"App","projectPath":"/repo/App/App.csproj",
  "frameworks":{"net8.0":{"projectReferences":{"/repo/Child/Child.csproj":{"projectPath":"/repo/Child/Child.csproj"}}}}
 },"frameworks":{"net8.0":{"targetAlias":"net8.0","dependencies":{"Wrapper":{"target":"Package","version":"[1.0.0, 2.0.0)"},"Other":{"target":"Package","version":"1.0.0"}}}}}
}`

func TestAssetsResolvedVersionsAndSharedEdges(t *testing.T) {
	root, err := readAssets(strings.NewReader(testAssets), model.NewFile("/repo/App/obj/project.assets.json", "App/obj/project.assets.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	root.Build(false, model.Lan_DotNet)
	edges, packages := map[string]bool{}, map[string]bool{}
	root.ForEachNode(func(p, n *model.DepGraph) bool {
		if n.Name == "Child" && !n.Project {
			t.Error("project reference treated as public NuGet package")
		}
		if !n.Project {
			packages[model.Purl("", n.Name, n.Version, n.Language)] = true
		}
		if p != nil {
			edges[p.Name+"->"+n.Name] = true
		}
		return true
	})
	for _, want := range []string{"pkg:nuget/Wrapper@1.2.0", "pkg:nuget/Other@1.0.0", "pkg:nuget/Leaf@1.0.0"} {
		if !packages[want] {
			t.Errorf("missing resolved package %s: %v", want, packages)
		}
	}
	for _, want := range []string{"App->Wrapper", "App->Other", "App->Child", "Wrapper->Leaf", "Other->Leaf", "Child->Leaf"} {
		if !edges[want] {
			t.Errorf("missing dependency edge %s: %v", want, edges)
		}
	}
}

func mutateAssets(t *testing.T, fn func(map[string]any)) string {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(testAssets), &doc); err != nil {
		t.Fatal(err)
	}
	fn(doc)
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestAssetsInvalid(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"schema", func(d map[string]any) { d["version"] = 99 }},
		{"no-targets", func(d map[string]any) { delete(d, "targets") }},
		{"null-target", func(d map[string]any) { d["targets"].(map[string]any)["net8.0"] = nil }},
		{"missing-library", func(d map[string]any) { delete(d["libraries"].(map[string]any), "Leaf/1.0.0") }},
		{"bad-type", func(d map[string]any) {
			d["libraries"].(map[string]any)["Leaf/1.0.0"].(map[string]any)["type"] = "project"
		}},
		{"missing-transitive", func(d map[string]any) { delete(d["targets"].(map[string]any)["net8.0"].(map[string]any), "Leaf/1.0.0") }},
		{"missing-direct", func(d map[string]any) {
			delete(d["targets"].(map[string]any)["net8.0"].(map[string]any), "Wrapper/1.2.0")
		}},
		{"missing-project", func(d map[string]any) {
			delete(d["targets"].(map[string]any)["net8.0"].(map[string]any), "Child/1.0.0")
		}},
		{"missing-framework", func(d map[string]any) { d["project"].(map[string]any)["frameworks"] = map[string]any{} }},
		{"missing-project-metadata", func(d map[string]any) {
			d["project"].(map[string]any)["restore"].(map[string]any)["frameworks"] = map[string]any{}
		}},
		{"restore-error", func(d map[string]any) {
			d["logs"] = []any{map[string]any{"level": "Error", "code": "NU1101", "message": "package not found"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := mutateAssets(t, tc.mutate)
			if root, err := readAssets(strings.NewReader(data), model.NewFile("assets", "project.assets.json"), nil); err == nil || root != nil {
				t.Fatalf("invalid assets accepted: %s", data)
			}
		})
	}
	if _, err := readAssets(strings.NewReader("{"), model.NewFile("assets", "project.assets.json"), nil); err == nil {
		t.Fatal("invalid JSON accepted")
	}
}

func TestAssetsVersionsFrameworkAliasesAndRID(t *testing.T) {
	for _, schema := range []int{3, 4} {
		t.Run(string(rune('0'+schema)), func(t *testing.T) {
			data := mutateAssets(t, func(d map[string]any) {
				d["version"] = schema
				targets := d["targets"].(map[string]any)
				original := targets["net8.0"]
				delete(targets, "net8.0")
				targets[".NETCoreApp,Version=v8.0"] = original
				copyData, _ := json.Marshal(original)
				var rid map[string]any
				_ = json.Unmarshal(copyData, &rid)
				rid["Wrapper/1.3.0"] = rid["Wrapper/1.2.0"]
				delete(rid, "Wrapper/1.2.0")
				targets[".NETCoreApp,Version=v8.0/linux-x64"] = rid
				d["libraries"].(map[string]any)["Wrapper/1.3.0"] = map[string]any{"type": "package"}
			})
			root, err := readAssets(strings.NewReader(data), model.NewFile("assets", "project.assets.json"), nil)
			if err != nil {
				t.Fatal(err)
			}
			found := map[string]bool{}
			root.ForEachNode(func(_, n *model.DepGraph) bool {
				if n.Name == "Wrapper" {
					found[n.Version] = true
				}
				return true
			})
			if !found["1.2.0"] || !found["1.3.0"] {
				t.Fatalf("framework/RID-specific versions collapsed: %v", found)
			}
		})
	}
	for _, pair := range [][2]string{{".NETStandard,Version=v2.1", "netstandard2.1"}, {".NETFramework,Version=v4.7.2", "net472"}, {".NETCoreApp,Version=v3.1", "netcoreapp3.1"}} {
		if frameworkKey(pair[0]) != pair[1] {
			t.Errorf("framework %s", pair[0])
		}
	}
}

func TestNugetIncrementalRestoreValidatesUnchangedAssets(t *testing.T) {
	nugetTestConfig(t, false, config.DynamicAuto)
	dir := t.TempDir()
	project := writeProjectTestFile(t, dir, "App.csproj", `<Project Sdk="Microsoft.NET.Sdk" />`)
	asset := writeProjectTestFile(t, dir, "obj/project.assets.json", testAssets)
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(asset.Abspath(), old, old); err != nil {
		t.Fatal(err)
	}
	ctx, issues := model.WithDiagnostics(context.Background())
	calls, roots := 0, 0
	scanNuget(ctx, []*model.File{project}, func(_ *model.File, graphs ...*model.DepGraph) { roots += len(graphs) }, func(context.Context, string) error { calls++; return nil })
	if calls != 1 || roots != 1 || len(issues.List()) != 0 {
		t.Fatalf("calls=%d roots=%d issues=%v", calls, roots, issues.List())
	}
}

func TestDotnetRestoreCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := restoreProject(ctx, "unused.csproj"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

func writeProjectTestFile(t *testing.T, dir, name, contents string) *model.File {
	t.Helper()
	filename := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	return model.NewFile(filename, name)
}

func nugetTestConfig(t *testing.T, offline bool, mode config.DynamicMode) {
	t.Helper()
	previous := *config.Conf()
	t.Cleanup(func() { *config.Conf() = previous })
	config.Conf().Offline, config.Conf().Optional.Dynamic = offline, mode
}

func TestNugetAutoRestoreAndReuseAssets(t *testing.T) {
	for _, mode := range []config.DynamicMode{"", config.DynamicAuto, config.DynamicOn} {
		t.Run(string(mode), func(t *testing.T) {
			nugetTestConfig(t, false, mode)
			dir := t.TempDir()
			project := writeProjectTestFile(t, dir, "App.csproj", `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="Wrapper" Version="[1.0.0,2.0.0)" /></ItemGroup></Project>`)
			calls := 0
			restore := func(ctx context.Context, filename string) error {
				calls++
				if filename != project.Abspath() {
					t.Fatal(filename)
				}
				writeProjectTestFile(t, dir, "obj/project.assets.json", testAssets)
				return nil
			}
			for i := 0; i < 2; i++ {
				ctx, issues := model.WithDiagnostics(context.Background())
				var roots []*model.DepGraph
				scanNuget(ctx, []*model.File{project}, func(_ *model.File, graphs ...*model.DepGraph) { roots = append(roots, graphs...) }, restore)
				if len(issues.List()) != 0 || len(roots) != 1 {
					t.Fatalf("roots=%v issues=%v", roots, issues.List())
				}
			}
			if calls != 1 {
				t.Fatalf("restore calls=%d; expected reuse of valid assets", calls)
			}
		})
	}
}

func TestNugetFallbackNeverInventsResolvedVersions(t *testing.T) {
	for _, tc := range []struct {
		name       string
		offline    bool
		mode       config.DynamicMode
		restoreErr error
		wantCalls  int
	}{
		{"offline", true, config.DynamicAuto, nil, 0},
		{"off", false, config.DynamicOff, nil, 0},
		{"missing-sdk", false, config.DynamicAuto, errors.New("dotnet SDK unavailable"), 1},
		{"restore-failure", false, config.DynamicOn, errors.New("dotnet restore failed"), 1},
		{"empty-restore", false, config.DynamicAuto, nil, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nugetTestConfig(t, tc.offline, tc.mode)
			dir := t.TempDir()
			project := writeProjectTestFile(t, dir, "App.csproj", `<Project><PropertyGroup><V>3.0.0</V></PropertyGroup><ItemGroup><PackageReference Include="Minimum" Version="1.0.0" /><PackageReference Include="Range"><Version>[1.0.0,2.0.0)</Version></PackageReference><PackageReference Include="Pinned"><Version>[$(V)]</Version></PackageReference></ItemGroup></Project>`)
			ctx, issues := model.WithDiagnostics(context.Background())
			calls := 0
			var root *model.DepGraph
			scanNuget(ctx, []*model.File{project}, func(_ *model.File, graphs ...*model.DepGraph) { root = graphs[0] }, func(context.Context, string) error { calls++; return tc.restoreErr })
			if calls != tc.wantCalls || len(issues.List()) != 1 || root == nil || len(root.Children) != 3 {
				t.Fatalf("calls=%d root=%v issues=%v", calls, root, issues.List())
			}
			for _, n := range root.Children {
				if n.Name == "Pinned" {
					if n.Version != "3.0.0" {
						t.Fatalf("pinned identity lost: %+v", n)
					}
				} else if n.Version != "" {
					t.Fatalf("requested version mistaken for resolved: %+v", n)
				}
			}
		})
	}
}

func TestNugetExistingAssetsOfflineAndStaleProps(t *testing.T) {
	nugetTestConfig(t, true, config.DynamicOff)
	dir := t.TempDir()
	project := writeProjectTestFile(t, dir, "App.csproj", `<Project Sdk="Microsoft.NET.Sdk" />`)
	props := writeProjectTestFile(t, dir, "Directory.Packages.props", `<Project><PropertyGroup><ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally></PropertyGroup></Project>`)
	assets := writeProjectTestFile(t, dir, "obj/project.assets.json", testAssets)
	scan := func(wantIssues int) {
		ctx, issues := model.WithDiagnostics(context.Background())
		count := 0
		scanNuget(ctx, []*model.File{project, assets}, func(_ *model.File, graphs ...*model.DepGraph) { count += len(graphs) }, func(context.Context, string) error { t.Fatal("offline scan ran dotnet"); return nil })
		if count != 1 || len(issues.List()) != wantIssues {
			t.Fatalf("count=%d issues=%v", count, issues.List())
		}
	}
	scan(0)
	future := time.Now().Add(time.Second)
	if err := os.Chtimes(props.Abspath(), future, future); err != nil {
		t.Fatal(err)
	}
	scan(1)
}

func TestNugetSolutionAndCentralFallback(t *testing.T) {
	nugetTestConfig(t, true, config.DynamicOff)
	dir := t.TempDir()
	writeProjectTestFile(t, dir, "Directory.Packages.props", `<Project><PropertyGroup><ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally></PropertyGroup><ItemGroup><PackageVersion Include="Pinned" Version="[2.0.0]" /></ItemGroup></Project>`)
	writeProjectTestFile(t, dir, "child/Child.csproj", `<Project><ItemGroup><PackageReference Include="Pinned" /></ItemGroup></Project>`)
	solution := writeProjectTestFile(t, dir, "App.sln", "Project(\"{GUID}\") = \"Child\", \"child\\Child.csproj\", \"{ID}\"\nEndProject\n")
	ctx, issues := model.WithDiagnostics(context.Background())
	var roots []*model.DepGraph
	scanNuget(ctx, []*model.File{solution}, func(_ *model.File, graphs ...*model.DepGraph) { roots = append(roots, graphs...) }, nil)
	if len(roots) != 1 || len(roots[0].Children) != 1 || roots[0].Children[0].Version != "2.0.0" || len(issues.List()) != 1 {
		t.Fatalf("roots=%v issues=%v", roots, issues.List())
	}
}
