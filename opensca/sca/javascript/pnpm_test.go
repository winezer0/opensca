package javascript

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
)

func scanPnpmFixture(t *testing.T, lock string, manifests map[string]string) ([]*model.DepGraph, []string) {
	t.Helper()
	dir := t.TempDir()
	inputs := map[string]string{"pnpm-lock.yaml": lock}
	for name, body := range manifests {
		inputs[name] = body
	}
	var files []*model.File
	for _, name := range pnpmKeys(inputs) {
		file := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(inputs[name]), 0600); err != nil {
			t.Fatal(err)
		}
		files = append(files, model.NewFile(file, name))
	}
	ctx, issues := model.WithDiagnostics(context.Background())
	var roots []*model.DepGraph
	Sca{}.Sca(ctx, nil, files, func(_ *model.File, graphs ...*model.DepGraph) { roots = append(roots, graphs...) })
	return roots, issues.List()
}

func TestPnpmVersionsAndGraph(t *testing.T) {
	for _, major := range []int{5, 6, 9} {
		for _, paired := range []bool{false, true} {
			t.Run(fmt.Sprintf("v%d/manifest=%v", major, paired), func(t *testing.T) {
				var lock string
				if major == 5 {
					lock = `lockfileVersion: 5.4
dependencies:
  alpha: 1.0.0
  beta: 1.0.0
devDependencies:
  dev-tool: 1.0.0
packages:
  /alpha/1.0.0:
    dependencies: {shared: 2.0.0}
  /beta/1.0.0:
    dependencies: {shared: 2.0.0}
  /dev-tool/1.0.0:
    dependencies: {shared: 2.0.0}
  /shared/2.0.0:
    dependencies: {alpha: 1.0.0}
`
				} else {
					prefix, collection := "/", "packages"
					if major == 9 {
						prefix, collection = "", "snapshots"
					}
					lock = fmt.Sprintf(`lockfileVersion: '%d.0'
importers:
  .:
    dependencies:
      alpha: {specifier: ^1, version: 1.0.0}
      beta: {specifier: ^1, version: 1.0.0}
    devDependencies:
      dev-tool: {specifier: ^1, version: 1.0.0}
%s:
  %salpha@1.0.0:
    dependencies: {shared: 2.0.0}
  %sbeta@1.0.0:
    dependencies: {shared: 2.0.0}
  %sdev-tool@1.0.0:
    dependencies: {shared: 2.0.0}
  %sshared@2.0.0:
    dependencies: {alpha: 1.0.0}
`, major, collection, prefix, prefix, prefix, prefix)
					if major == 9 {
						lock += "packages:\n  alpha@1.0.0: {}\n  beta@1.0.0: {}\n  dev-tool@1.0.0: {}\n  shared@2.0.0: {}\n"
					}
				}
				manifests := map[string]string{}
				if paired {
					manifests["package.json"] = `{"name":"app","version":"1.0.0","dependencies":{"alpha":"^1","beta":"^1"},"devDependencies":{"dev-tool":"^1"}}`
				}
				roots, issues := scanPnpmFixture(t, lock, manifests)
				if len(issues) > 0 || len(roots) != 1 {
					t.Fatalf("roots=%d issues=%v", len(roots), issues)
				}
				root := roots[0]
				root.Build(false, model.Lan_JavaScript)
				edges := map[string]bool{}
				packages := map[string]bool{}
				root.ForEachNode(func(p, n *model.DepGraph) bool {
					if p != nil {
						edges[p.Name+"->"+n.Name] = true
					}
					if n.Name == "dev-tool" && !n.Develop {
						t.Error("development scope lost")
					}
					if !n.Project && !n.Develop {
						packages[n.Name] = true
					}
					return true
				})
				for _, edge := range []string{"alpha->shared", "beta->shared", "dev-tool->shared", "shared->alpha"} {
					if !edges[edge] {
						t.Errorf("missing edge %s: %v", edge, edges)
					}
				}
				if !packages["shared"] || !packages["alpha"] || !packages["beta"] {
					t.Fatalf("production packages lost: %v", packages)
				}
			})
		}
	}
}

func TestPnpmWorkspacePeersAliasesOptional(t *testing.T) {
	for _, major := range []int{5, 6, 9} {
		t.Run(fmt.Sprintf("v%d", major), func(t *testing.T) {
			ref, pkgKey, depRef := "'/@acme/real/1.2.3_peer@2.0.0'", "/@acme/real/1.2.3_peer@2.0.0", "2.0.0"
			peerKey, collection := "/peer/2.0.0", "packages"
			if major != 5 {
				ref, pkgKey, peerKey = "'/@acme/real@1.2.3(peer@2.0.0)'", "/@acme/real@1.2.3(peer@2.0.0)", "/peer@2.0.0"
			}
			if major == 9 {
				ref, pkgKey, peerKey, collection = "'@acme/real@1.2.3(peer@2.0.0)'", "@acme/real@1.2.3(peer@2.0.0)", "peer@2.0.0", "snapshots"
			}
			if major != 5 {
				ref = "{specifier: 'npm:@acme/real@^1', version: " + ref + "}"
			}
			lock := fmt.Sprintf(`lockfileVersion: '%d.0'
importers:
  .:
    dependencies:
      workspace: %s
  packages/workspace:
    optionalDependencies:
      alias: %s
%s:
  '%s':
    optionalDependencies: {peer: '%s'}
  '%s': {}
`, major, "'link:packages/workspace'", ref, collection, pkgKey, depRef, peerKey)
			if major == 9 {
				lock += "packages:\n  '@acme/real@1.2.3': {}\n  peer@2.0.0: {}\n"
			}
			roots, issues := scanPnpmFixture(t, lock, map[string]string{
				"package.json":                    `{"name":"mono","version":"1.0.0"}`,
				"packages/workspace/package.json": `{"name":"@local/workspace","version":"1.0.0","dependencies":{"alias":"npm:@acme/real@^1"}}`,
			})
			if len(issues) > 0 || len(roots) != 1 {
				t.Fatalf("roots=%d issues=%v", len(roots), issues)
			}
			seen := map[string]bool{}
			roots[0].ForEachNode(func(p, n *model.DepGraph) bool {
				if n.Name == "@local/workspace" && !n.Project {
					t.Error("workspace is not marked as project")
				}
				if !n.Project {
					seen[model.Purl("", n.Name, n.Version, model.Lan_JavaScript)] = true
				}
				return true
			})
			for _, want := range []string{"pkg:npm/%40acme/real@1.2.3", "pkg:npm/peer@2.0.0"} {
				if !seen[want] {
					t.Errorf("missing %s: %v", want, seen)
				}
			}
		})
	}
}

func TestPnpmInvalidAndEmpty(t *testing.T) {
	for _, tc := range []struct{ name, lock string }{
		{"invalid-yaml", "lockfileVersion: ["},
		{"unknown-version", "lockfileVersion: '10.0'"},
		{"missing-version", "packages: {}"},
		{"missing-package", "lockfileVersion: '6.0'\ndependencies: {missing: {version: 1.0.0}}"},
		{"null-package", "lockfileVersion: '6.0'\npackages: {'/a@1.0.0': null}"},
		{"missing-metadata", "lockfileVersion: '9.0'\nimporters: {.: {}}\nsnapshots: {'a@1.0.0': {}}"},
		{"bad-workspace", "lockfileVersion: '6.0'\nimporters: {.: {dependencies: {app: 'link:missing'}}}"},
		{"invalid-ref", "lockfileVersion: '6.0'\ndependencies: {a: [1, 2]}"},
		{"range-ref", "lockfileVersion: '6.0'\ndependencies: {a: {specifier: ^1}}"},
		{"unlocked-version", "lockfileVersion: '6.0'\ndependencies: {a: latest}\npackages: {'/a@latest': {}}"},
		{"invalid-importer", "lockfileVersion: '6.0'\nimporters: {'../outside': {}}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			roots, issues := scanPnpmFixture(t, tc.lock, map[string]string{"package.json": `{"name":"app","dependencies":{"missing":"1.0.0"}}`})
			if len(roots) != 0 || len(issues) != 1 || !strings.Contains(issues[0], "dependency data may be incomplete") {
				t.Fatalf("invalid lockfile fell back or lacked diagnostic: roots=%d issues=%v", len(roots), issues)
			}
		})
	}
	for _, lock := range []string{"lockfileVersion: '5.4'\n", "lockfileVersion: '6.0'\n", "lockfileVersion: '9.0'\nimporters: {.: {}}\n"} {
		roots, issues := scanPnpmFixture(t, lock, nil)
		if len(roots) != 1 || len(issues) != 0 || len(roots[0].Children) != 0 {
			t.Fatalf("empty project rejected: roots=%v issues=%v", roots, issues)
		}
	}
}

func TestPnpmPackageKeyIdentity(t *testing.T) {
	for _, tc := range []struct{ key, major, name, version string }{
		{"/@scope/pkg/1.2.3_@scope/peer@2.0.0", "5", "@scope/pkg", "1.2.3"},
		{"/under_score@1.2.3(peer@2.0.0)", "6", "under_score", "1.2.3"},
		{"@under_score/pkg@1.2.3(peer@2.0.0)", "9", "@under_score/pkg", "1.2.3"},
	} {
		name, version := pnpmIdentity(tc.key, tc.major)
		if name != tc.name || pnpmVersion(version) != tc.version {
			t.Errorf("%s: got %s@%s", tc.key, name, version)
		}
	}
}

func TestPnpmIndependentNestedNpmProject(t *testing.T) {
	roots, issues := scanPnpmFixture(t, "lockfileVersion: '6.0'\n", map[string]string{
		"package.json":                  `{"name":"pnpm-root","version":"1.0.0"}`,
		"independent/package.json":      `{"name":"npm-project","version":"1.0.0","dependencies":{"lodash":"4.17.21"}}`,
		"independent/package-lock.json": `{"name":"npm-project","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"npm-project","version":"1.0.0","dependencies":{"lodash":"4.17.21"}},"node_modules/lodash":{"version":"4.17.21"}}}`,
	})
	if len(issues) != 0 || len(roots) != 2 {
		t.Fatalf("independent project skipped: roots=%d issues=%v", len(roots), issues)
	}
	found := false
	for _, root := range roots {
		root.ForEachNode(func(_, n *model.DepGraph) bool {
			found = found || n.Name == "lodash" && n.Version == "4.17.21"
			return true
		})
	}
	if !found {
		t.Fatal("nested npm project's dependency missing")
	}
}
