package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// This test always checks real CLI output. OSV_SCANNER enables online consumption.
func TestPackageLockSBOMOSV(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	root := filepath.Dir(thisFile)
	scanner := os.Getenv("OSV_SCANNER")
	if scanner == "1" {
		scanner = filepath.Join(root, "..", "osv-scanner", "osv-scanner.exe")
	}
	if scanner != "" {
		var err error
		scanner, err = filepath.Abs(scanner)
		if err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	cli := filepath.Join(dir, "scanner.exe")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-o", cli, ".")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	readFixture := func(name string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(root, "opensca/sca/javascript/testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	nested := readFixture("lockfile-nested.json")
	workspace := readFixture("lockfile-workspace.json")
	simple := "{\"name\":\"demo\",\"version\":\"1.0.0\",\"lockfileVersion\":1,\"dependencies\":{\"lodash\":{\"version\":\"4.17.21\"}}}"
	cases := []struct {
		name, data      string
		want            []string
		invalid, paired bool
	}{
		{"v1-lock-only", simple, []string{"pkg:npm/lodash@4.17.21"}, false, false},
		{"v2-nested-lock-only", strings.Replace(nested, "\"lockfileVersion\": 3", "\"lockfileVersion\": 2", 1), []string{"pkg:npm/lodash@4.17.20", "pkg:npm/lodash@4.17.21"}, false, false},
		{"v3-nested-lock-only", nested, []string{"pkg:npm/lodash@4.17.20", "pkg:npm/lodash@4.17.21"}, false, false},
		{"v3-nested-with-manifest", nested, []string{"pkg:npm/lodash@4.17.20", "pkg:npm/lodash@4.17.21"}, false, true},
		{"v2-workspace-lock-only", strings.Replace(workspace, "\"lockfileVersion\": 3", "\"lockfileVersion\": 2", 1), []string{"pkg:npm/lodash@4.17.21"}, false, false},
		{"v3-workspace-lock-only", workspace, []string{"pkg:npm/lodash@4.17.21"}, false, false},
		{"unknown-version", "{\"lockfileVersion\":4,\"packages\":{\"\":{}}}", nil, true, false},
		{"missing-root", "{\"lockfileVersion\":3,\"packages\":{\"node_modules/lodash\":{\"version\":\"4.17.21\"}}}", nil, true, false},
		{"null-package", "{\"lockfileVersion\":3,\"packages\":{\"\":{},\"node_modules/lodash\":null}}", nil, true, false},
		{"unresolved-required", "{\"lockfileVersion\":3,\"packages\":{\"\":{\"dependencies\":{\"lodash\":\"4.17.21\"}}}}", nil, true, true},
		{"invalid-json", "{", nil, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			project := filepath.Join(dir, tc.name)
			if err := os.MkdirAll(project, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(project, "package-lock.json"), []byte(tc.data), 0600); err != nil {
				t.Fatal(err)
			}
			if tc.paired {
				var lock struct{ Packages map[string]json.RawMessage }
				_ = json.Unmarshal([]byte(tc.data), &lock)
				manifest := lock.Packages[""]
				if len(manifest) == 0 {
					manifest = []byte("{\"name\":\"demo\"}")
				}
				if err := os.WriteFile(filepath.Join(project, "package.json"), manifest, 0600); err != nil {
					t.Fatal(err)
				}
			}
			bom := filepath.Join(project, "bom.cdx.json")
			config := filepath.Join(project, "config.json")
			if err := os.WriteFile(config, []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"-config", config, "-path", project, "-offline", "-deps-only", "-cache-dir", filepath.Join(dir, "cache"), "-log", filepath.Join(dir, "opensca.log"), "-out", bom}
			output, err := exec.CommandContext(ctx, cli, args...).CombinedOutput()
			if tc.invalid {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 3 {
					t.Fatalf("invalid input must exit 3: %v\n%s", err, output)
				}
			} else if err != nil {
				t.Fatalf("generate BOM: %v\n%s", err, output)
			}
			data, err := os.ReadFile(bom)
			if err != nil {
				t.Fatal(err)
			}
			var document struct {
				Components []struct{ PURL, Name, Type string }
				Packages   []struct {
					ExternalRefs []struct{ ReferenceLocator string }
				}
			}
			if err := json.Unmarshal(data, &document); err != nil {
				t.Fatal(err)
			}
			found := map[string]bool{}
			for _, c := range document.Components {
				if strings.Contains(tc.name, "workspace") && c.Name == "app" && (c.PURL != "" || c.Type != "application") {
					t.Fatalf("local workspace was exported as a registry dependency: %+v", c)
				}
				found[c.PURL] = true
			}
			for _, p := range document.Packages {
				for _, ref := range p.ExternalRefs {
					found[ref.ReferenceLocator] = true
				}
			}
			if tc.invalid {
				if len(document.Components) != 0 || len(document.Packages) != 0 {
					t.Fatalf("invalid lock produced packages: %s", data)
				}
				if !strings.Contains(string(data), "dependency data may be incomplete") {
					t.Fatalf("missing incomplete annotation: %s", data)
				}
				return
			}
			for _, purl := range tc.want {
				if !found[purl] {
					t.Fatalf("BOM omits %s: %s", purl, data)
				}
			}
			if scanner == "" {
				t.Log("BOM assertions passed; set OSV_SCANNER for online consumer check")
				return
			}
			resultPath := filepath.Join(project, "osv.json")
			scanCtx, scanCancel := context.WithTimeout(ctx, time.Minute)
			defer scanCancel()
			command := exec.CommandContext(scanCtx, scanner, "scan", "source", "--lockfile", bom, "--all-packages", "--format", "json", "--output-file", resultPath)
			output, err = command.CombinedOutput()
			if err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 1 {
					t.Fatalf("online OSV: %v\n%s", err, output)
				}
			}
			data, err = os.ReadFile(resultPath)
			if err != nil {
				t.Fatalf("OSV output: %v\n%s", err, output)
			}
			var result struct {
				Results []struct {
					Packages []struct {
						Package         struct{ PURL string }
						Vulnerabilities []struct{ ID string }
					}
				}
			}
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatal(err)
			}
			retained := map[string]bool{}
			vulnerable := map[string]bool{}
			for _, source := range result.Results {
				for _, p := range source.Packages {
					retained[p.Package.PURL] = true
					vulnerable[p.Package.PURL] = len(p.Vulnerabilities) > 0
				}
			}
			for _, purl := range tc.want {
				if !retained[purl] {
					t.Fatalf("OSV omits %s: %s", purl, data)
				}
				if purl == "pkg:npm/lodash@4.17.20" && !vulnerable[purl] {
					t.Fatalf("OSV missed known vulnerable lodash version: %s", data)
				}
			}
			t.Logf("online OSV retained %d expected packages; vulnerable lodash detected=%v", len(tc.want), vulnerable["pkg:npm/lodash@4.17.20"])
		})
	}
}
