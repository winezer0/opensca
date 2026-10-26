package nuget

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
)

func TestPackagesConfigInventory(t *testing.T) {
	root, err := parsePackagesConfig(strings.NewReader(`<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.1" targetFramework="net45" />
  <package id="newtonsoft.json" version="13.0.1" />
  <package id="Newtonsoft.Json" version="12.0.3" />
  <package id="Build.Tool" version="1.0.0" developmentDependency="true" />
  <package id="Shared" version="2.0.0" developmentDependency="true" />
  <package id="shared" version="2.0.0" />
</packages>`), "src/packages.config")
	if err != nil {
		t.Fatal(err)
	}
	if len(root.Children) != 4 || !root.Project {
		t.Fatalf("wrong inventory: %+v", root)
	}
	root.Build(false, model.Lan_DotNet)
	seen := map[string]*model.DepGraph{}
	for _, n := range root.Children {
		seen[model.Purl("", n.Name, n.Version, n.Language)] = n
		if len(n.Children) != 0 {
			t.Error("invented package dependency edges")
		}
		if n.Name == "Build.Tool" && !n.Develop || strings.EqualFold(n.Name, "Shared") && n.Develop {
			t.Errorf("wrong development scope: %+v", n)
		}
	}
	for _, want := range []string{"pkg:nuget/Newtonsoft.Json@13.0.1", "pkg:nuget/Newtonsoft.Json@12.0.3"} {
		if seen[want] == nil {
			t.Errorf("missing package %s: %v", want, seen)
		}
	}
}

func TestPackagesConfigInvalidAndEmpty(t *testing.T) {
	for _, data := range []string{
		"", "<packages>", "<project />", `<packages><package id="A" /></packages>`,
		`<packages><package version="1.0.0" /></packages>`,
		`<packages><package id="A" version="[1.0,2.0)" /></packages>`,
		`<packages><package id="A" version="1.*" /></packages>`,
		`<packages><package id="A" version="latest" /></packages>`,
		`<packages><package id="@invalid/name" version="1.0.0" /></packages>`,
		`<packages><package id="A" version="1.0.0" developmentDependency="invalid" /></packages>`,
	} {
		if root, err := parsePackagesConfig(strings.NewReader(data), "packages.config"); err == nil || root != nil {
			t.Errorf("invalid inventory accepted: %q", data)
		}
	}
	if root, err := parsePackagesConfig(strings.NewReader("<packages />"), "packages.config"); err != nil || len(root.Children) != 0 {
		t.Fatalf("valid empty inventory rejected: root=%v err=%v", root, err)
	}
}

func TestPackagesConfigScannerDiagnostics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "packages.config")
	if err := os.WriteFile(path, []byte("<packages>"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, issues := model.WithDiagnostics(context.Background())
	called := false
	Sca{}.Sca(ctx, nil, []*model.File{model.NewFile(path, "packages.config")}, func(_ *model.File, _ ...*model.DepGraph) { called = true })
	if called || len(issues.List()) != 1 || !strings.Contains(issues.List()[0], "dependency data may be incomplete") {
		t.Fatalf("invalid inventory not diagnosed: called=%v issues=%v", called, issues.List())
	}
}
