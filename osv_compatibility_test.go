package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Dependency resolution always runs; external OSV consumer checks are opt-in.
func TestOSVCompatibility(t *testing.T) {
	scanner := os.Getenv("OSV_SCANNER")
	if scanner == "" {
		t.Log("OSV_SCANNER is unset; dependency resolution and PURL assertions still run, external scanner checks are skipped")
	} else if scanner == "1" {
		scanner = "../osv-scanner/osv-scanner.exe"
	} else {
		var err error
		scanner, err = filepath.Abs(scanner)
		if err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	binary := filepath.Join(dir, "opensca.exe")
	if out, err := exec.CommandContext(ctx, "go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	db := filepath.Join(dir, "db")
	writeDB := func(ecosystem string, records map[string]string) {
		t.Helper()
		p := filepath.Join(db, "osv-scalibr", ecosystem, "all.zip")
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		f, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		z := zip.NewWriter(f)
		for name, body := range records {
			w, err := z.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = w.Write([]byte(body)); err != nil {
				t.Fatal(err)
			}
		}
		if err := z.Close(); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	fixtureDB := map[string]map[string]string{
		"Maven": {"CVE-2021-44228.json": `{"schema_version":"1.6.0","id":"CVE-2021-44228","modified":"2024-01-01T00:00:00Z","published":"2021-12-10T00:00:00Z","affected":[{"package":{"ecosystem":"Maven","name":"org.apache.logging.log4j:log4j-core"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.0-beta9"},{"fixed":"2.15.0"}]}]}]}`},
	}
	issues := map[string]struct{ eco, name, version, id string }{
		"npm-scoped":              {"npm", "@acme/demo", "1.2.3", "OSV-TEST-1001"},
		"go-direct":               {"Go", "github.com/gin-gonic/gin", "v1.9.1", "OSV-TEST-1002"},
		"python-pinned":           {"PyPI", "requests", "2.31.0", "OSV-TEST-1003"},
		"composer-lock":           {"Packagist", "psr/log", "3.0.0", "OSV-TEST-1004"},
		"rubygems-lock":           {"RubyGems", "rack", "3.0.8", "OSV-TEST-1005"},
		"cargo-lock":              {"crates.io", "serde", "1.0.188", "OSV-TEST-1006"},
		"yarn-v1":                 {"npm", "lodash", "4.17.21", "OSV-TEST-1007"},
		"gradle-groovy":           {"Maven", "com.google.guava:guava", "32.1.3-jre", "OSV-TEST-1008"},
		"npm-workspaces-monorepo": {"npm", "lodash", "4.17.21", "OSV-TEST-1009"},
	}
	for _, issue := range issues {
		record := `{"schema_version":"1.6.0","id":"` + issue.id + `","modified":"2024-01-01T00:00:00Z","published":"2024-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"` + issue.eco + `","name":"` + issue.name + `"},"versions":["` + issue.version + `"]}]}`
		if fixtureDB[issue.eco] == nil {
			fixtureDB[issue.eco] = map[string]string{}
		}
		fixtureDB[issue.eco][issue.id+".json"] = record
	}
	for ecosystem, records := range fixtureDB {
		writeDB(ecosystem, records)
	}
	configPath := filepath.Join(dir, "config.json")
	write(configPath, `{"optional":{"dev":true}}`)
	scannerConfig := filepath.Join(dir, "osv-scanner.toml")
	write(scannerConfig, "")
	for _, version := range []string{"2.14.1", "2.17.1"} {
		t.Run(version, func(t *testing.T) {
			project := filepath.Join(dir, version)
			pom := `<project><groupId>example.local</groupId><artifactId>app</artifactId><version>1</version><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>` + version + `</version></dependency></dependencies></project>`
			write(filepath.Join(project, "pom.xml"), pom)
			repo := filepath.Join(dir, "m2")
			write(filepath.Join(repo, "org", "apache", "logging", "log4j", "log4j-core", version, "log4j-core-"+version+".pom"), `<project><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>`+version+`</version></project>`)
			bom := filepath.Join(project, "bom.cdx.json")
			args := []string{"-config", configPath, "-path", project, "-offline", "-dependencies-only", "-maven-repo", repo, "-cache-dir", filepath.Join(dir, "cache"), "-log", filepath.Join(dir, "opensca.log"), "-out", bom}
			for i := 0; i < 2; i++ {
				if out, err := exec.CommandContext(ctx, binary, args...).CombinedOutput(); err != nil {
					t.Fatalf("OpenSCA: %v\n%s", err, out)
				}
			}
			data, err := os.ReadFile(bom)
			if err != nil {
				t.Fatal(err)
			}
			var exported struct {
				Components []struct {
					PackageURL string `json:"purl"`
				} `json:"components"`
			}
			if err := json.Unmarshal(data, &exported); err != nil {
				t.Fatal(err)
			}
			if len(exported.Components) != 1 || exported.Components[0].PackageURL != "pkg:maven/org.apache.logging.log4j/log4j-core@"+version {
				t.Fatalf("unexpected components: %s", data)
			}
			if scanner == "" {
				return
			}
			output := filepath.Join(dir, version+".osv.json")
			cmd := exec.CommandContext(ctx, scanner, "scan", "source", "--offline", "--all-packages", "--config", scannerConfig, "--lockfile", bom, "--format", "json", "--output-file", output)
			cmd.Env = append(os.Environ(), "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="+db)
			log, scanErr := cmd.CombinedOutput()
			wantExit := 0
			if version == "2.14.1" {
				wantExit = 1
			}
			actualExit := 0
			if scanErr != nil {
				if exit, ok := scanErr.(*exec.ExitError); ok {
					actualExit = exit.ExitCode()
				} else {
					t.Fatal(scanErr)
				}
			}
			if actualExit != wantExit {
				t.Fatalf("OSV exit %d, want %d\n%s", actualExit, wantExit, log)
			}
			result, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(result), "org.apache.logging.log4j:log4j-core") {
				t.Fatalf("consumer lost package: %s", result)
			}
			if strings.Contains(string(result), `"id": "CVE-2021-44228"`) != (wantExit == 1) {
				t.Fatalf("unexpected vulnerability result: %s", result)
			}
		})
	}
	t.Run("maven-transitive", func(t *testing.T) {
		project := filepath.Join(dir, "maven-transitive")
		write(filepath.Join(project, "pom.xml"), `<project><groupId>example.local</groupId><artifactId>app</artifactId><version>1</version><dependencies><dependency><groupId>example.local</groupId><artifactId>wrapper</artifactId><version>1.0.0</version></dependency></dependencies></project>`)
		repo := filepath.Join(dir, "transitive-m2")
		write(filepath.Join(repo, "example", "local", "wrapper", "1.0.0", "wrapper-1.0.0.pom"), `<project><groupId>example.local</groupId><artifactId>wrapper</artifactId><version>1.0.0</version><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies></project>`)
		write(filepath.Join(repo, "org", "apache", "logging", "log4j", "log4j-core", "2.14.1", "log4j-core-2.14.1.pom"), `<project><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></project>`)
		bom := filepath.Join(project, "bom.cdx.json")
		args := []string{"-config", configPath, "-path", project, "-offline", "-dependencies-only", "-maven-repo", repo, "-cache-dir", filepath.Join(dir, "cache"), "-log", filepath.Join(dir, "opensca.log"), "-out", bom}
		if out, err := exec.CommandContext(ctx, binary, args...).CombinedOutput(); err != nil {
			t.Fatalf("OpenSCA transitive resolution: %v\n%s", err, out)
		}
		data, err := os.ReadFile(bom)
		if err != nil {
			t.Fatal(err)
		}
		var exported struct {
			Components []struct {
				PackageURL string `json:"purl"`
			} `json:"components"`
		}
		if err := json.Unmarshal(data, &exported); err != nil {
			t.Fatal(err)
		}
		found := map[string]bool{}
		for _, c := range exported.Components {
			found[c.PackageURL] = true
		}
		for _, want := range []string{"pkg:maven/example.local/wrapper@1.0.0", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"} {
			if !found[want] {
				t.Fatalf("transitive PURL %s missing from %s", want, data)
			}
		}
		if scanner == "" {
			return
		}
		outPath := filepath.Join(project, "osv.json")
		cmd := exec.CommandContext(ctx, scanner, "scan", "source", "--offline", "--all-packages", "--config", scannerConfig, "--lockfile", bom, "--format", "json", "--output-file", outPath)
		cmd.Env = append(os.Environ(), "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="+db)
		log, err := cmd.CombinedOutput()
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
			t.Fatalf("OSV missed transitive Log4Shell: %v\n%s", err, log)
		}
		result, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(result), "CVE-2021-44228") || !strings.Contains(string(result), "org.apache.logging.log4j:log4j-core") {
			t.Fatalf("unexpected transitive OSV result: %s", result)
		}
	})

	// Run real project manifests through OpenSCA before handing each BOM to
	// osv-scanner. The input lockfiles make these scenarios deterministic.
	scenarios := []struct {
		name, ecosystem, relpath, contents, wantPURL string
		unsupported                                  bool
	}{
		{"npm-scoped", "npm", "package.json", `{"name":"app","version":"1.0.0","dependencies":{"@acme/demo":"1.2.3"}}` + "\n", "pkg:npm/%40acme/demo@1.2.3", false},
		{"npm-workspaces-monorepo", "npm", "package.json", `{"name":"mono","version":"1.0.0","private":true,"workspaces":["packages/app"]}` + "\n", "pkg:npm/lodash@4.17.21", false},
		{"yarn-v1", "npm", "package.json", `{"name":"app","version":"1.0.0","dependencies":{"lodash":"4.17.21"}}` + "\n", "pkg:npm/lodash@4.17.21", false},
		{"go-direct", "Go", "go.mod", "module example.local/app\n\nrequire github.com/gin-gonic/gin v1.9.1\n", "pkg:golang/github.com/gin-gonic/gin@v1.9.1", false},
		{"gradle-groovy", "Maven", "build.gradle", "dependencies { implementation 'com.google.guava:guava:32.1.3-jre' }\n", "pkg:maven/com.google.guava/guava@32.1.3-jre", false},
		{"python-pinned", "PyPI", "requirements.txt", "requests==2.31.0\n", "pkg:pypi/requests@2.31.0", false},
		{"composer-lock", "Packagist", "composer.lock", `{"packages":[{"name":"psr/log","version":"3.0.0"}]}` + "\n", "pkg:composer/psr/log@3.0.0", false},
		{"rubygems-lock", "RubyGems", "Gemfile.lock", "GEM\n  specs:\n    rack (3.0.8)\n\nPLATFORMS\n  x64-mingw-ucrt\n\nDEPENDENCIES\n  rack\n", "pkg:gem/rack@3.0.8", false},
		{"cargo-lock", "crates.io", "Cargo.lock", "version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.188\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n", "pkg:cargo/serde@1.0.188", false},
		{"pnpm-v6-lockfile", "npm", "pnpm-lock.yaml", "lockfileVersion: '6.0'\n\nimporters:\n  .:\n    dependencies:\n      lodash:\n        specifier: 4.17.21\n        version: 4.17.21\n", "", true},
		{"nuget-packages-config", "NuGet", "packages.config", `<?xml version="1.0" encoding="utf-8"?><packages><package id="Newtonsoft.Json" version="13.0.1" targetFramework="net45" /></packages>`, "", true},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			project := filepath.Join(dir, scenario.name)
			write(filepath.Join(project, scenario.relpath), scenario.contents)
			if scenario.name == "npm-scoped" {
				write(filepath.Join(project, "package-lock.json"), `{"name":"app","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0","dependencies":{"@acme/demo":"1.2.3"}},"node_modules/@acme/demo":{"version":"1.2.3"}}}`)
			}
			if scenario.name == "composer-lock" {
				write(filepath.Join(project, "composer.json"), `{"name":"example/app","require":{"psr/log":"^3.0"}}`)
			}
			if scenario.name == "npm-workspaces-monorepo" {
				write(filepath.Join(project, "package-lock.json"), `{"name":"mono","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"mono","version":"1.0.0","workspaces":["packages/app"]},"packages/app":{"name":"app","version":"1.0.0","dependencies":{"lodash":"4.17.21"}},"node_modules/lodash":{"version":"4.17.21"}}}`)
				write(filepath.Join(project, "packages", "app", "package.json"), `{"name":"app","version":"1.0.0","dependencies":{"lodash":"4.17.21"}}`)
			}
			if scenario.name == "yarn-v1" {
				write(filepath.Join(project, "yarn.lock"), "# yarn lockfile v1\n\nlodash@4.17.21:\n  version \"4.17.21\"\n  resolved \"https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz\"\n")
			}
			if scenario.name == "gradle-groovy" {
				repo := filepath.Join(dir, "gradle-m2")
				write(filepath.Join(repo, "com", "google", "guava", "guava", "32.1.3-jre", "guava-32.1.3-jre.pom"), `<project><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>32.1.3-jre</version></project>`)
			}
			bom := filepath.Join(project, "bom.cdx.json")
			args := []string{"-config", configPath, "-path", project, "-offline", "-dependencies-only", "-cache-dir", filepath.Join(dir, "cache"), "-log", filepath.Join(dir, "opensca.log"), "-out", bom}
			if scenario.name == "gradle-groovy" {
				args = append(args, "-maven-repo", filepath.Join(dir, "gradle-m2"))
			}
			out, runErr := exec.CommandContext(ctx, binary, args...).CombinedOutput()
			if scenario.unsupported {
				exitErr, ok := runErr.(*exec.ExitError)
				if !ok || exitErr.ExitCode() != 3 {
					t.Fatalf("unsupported manifest should return diagnostic exit code 3 (err=%v): %s", runErr, out)
				}
			} else if runErr != nil {
				t.Fatalf("OpenSCA: %v\n%s", runErr, out)
			}
			data, err := os.ReadFile(bom)
			if err != nil {
				t.Fatal(err)
			}
			var exported struct {
				Components []struct {
					PackageURL string `json:"purl"`
				} `json:"components"`
				Dependencies []struct {
					Ref       string   `json:"ref"`
					DependsOn []string `json:"dependsOn"`
				} `json:"dependencies"`
				Properties []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"properties"`
			}
			if err := json.Unmarshal(data, &exported); err != nil {
				t.Fatal(err)
			}
			if scenario.unsupported {
				if len(exported.Components) != 0 {
					t.Fatalf("unsupported manifest unexpectedly resolved components: %s", data)
				}
				foundDiagnostic := false
				for _, property := range exported.Properties {
					foundDiagnostic = foundDiagnostic || property.Name == "opensca:diagnostic" && strings.Contains(property.Value, filepath.Base(scenario.relpath)) && strings.Contains(property.Value, "dependency data may be incomplete")
				}
				if !foundDiagnostic {
					t.Fatalf("unsupported manifest was not diagnosed: %s", data)
				}
				return
			}
			if scenario.name == "npm-workspaces-monorepo" {
				foundPURL, foundWorkspaceEdge := false, false
				for _, component := range exported.Components {
					foundPURL = foundPURL || component.PackageURL == scenario.wantPURL
				}
				for _, dependency := range exported.Dependencies {
					if dependency.Ref == "pkg:npm/app@1.0.0" {
						for _, child := range dependency.DependsOn {
							foundWorkspaceEdge = foundWorkspaceEdge || child == scenario.wantPURL
						}
					}
				}
				if !foundPURL || !foundWorkspaceEdge {
					t.Fatalf("workspace dependency or edge missing: %s", data)
				}
			} else if len(exported.Components) != 1 || exported.Components[0].PackageURL != scenario.wantPURL {
				t.Fatalf("unexpected components for %s: %s", scenario.name, data)
			}
			if scanner == "" {
				return
			}
			outPath := filepath.Join(project, "osv.json")
			cmd := exec.CommandContext(ctx, scanner, "scan", "source", "--offline", "--all-packages", "--config", scannerConfig, "--lockfile", bom, "--format", "json", "--output-file", outPath)
			cmd.Env = append(os.Environ(), "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="+db)
			log, err := cmd.CombinedOutput()
			if err != nil {
				if e, ok := err.(*exec.ExitError); !ok || e.ExitCode() != 1 {
					t.Fatalf("OSV did not detect the fixture advisory for %s: %v\n%s", scenario.name, err, log)
				}
			}
			result, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(result), scenario.wantPURL) {
				t.Fatalf("OSV result omits %s: %s", scenario.wantPURL, result)
			}
			if !strings.Contains(string(result), issues[scenario.name].id) {
				t.Fatalf("OSV did not match %s to its advisory: %s", scenario.name, result)
			}
		})
	}
	if scanner == "" {
		t.Run("cargo-duplicate-versions", func(t *testing.T) {
			t.Skip("set OSV_SCANNER to run external scanner compatibility checks")
		})
		t.Run("fixed-osv-database-hit-and-no-hit", func(t *testing.T) {
			t.Skip("set OSV_SCANNER to run fixed-database OSV matching checks")
		})
		return
	}
	t.Run("cargo-duplicate-versions", func(t *testing.T) {
		project := filepath.Join(dir, "cargo-duplicate-versions")
		lock := "version = 3\n\n[[package]]\nname = \"app\"\nversion = \"1.0.0\"\ndependencies = [\"serde 1.0.188\", \"serde 1.0.200\"]\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.188\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
		write(filepath.Join(project, "Cargo.lock"), lock)
		bom := filepath.Join(project, "bom.cdx.json")
		args := []string{"-config", configPath, "-path", project, "-offline", "-dependencies-only", "-cache-dir", filepath.Join(dir, "cache"), "-log", filepath.Join(dir, "opensca.log"), "-out", bom}
		if out, err := exec.CommandContext(ctx, binary, args...).CombinedOutput(); err != nil {
			t.Fatalf("OpenSCA lost duplicate Cargo identities: %v\n%s", err, out)
		}
		data, err := os.ReadFile(bom)
		if err != nil {
			t.Fatal(err)
		}
		var exported struct {
			Components []struct {
				PackageURL string `json:"purl"`
			} `json:"components"`
		}
		if err := json.Unmarshal(data, &exported); err != nil {
			t.Fatal(err)
		}
		found := map[string]bool{}
		for _, c := range exported.Components {
			if c.PackageURL != "" {
				found[c.PackageURL] = true
			}
		}
		for _, want := range []string{"pkg:cargo/serde@1.0.188", "pkg:cargo/serde@1.0.200"} {
			if !found[want] {
				t.Fatalf("lost %s: %s", want, data)
			}
		}
		outPath := filepath.Join(project, "osv.json")
		cmd := exec.CommandContext(ctx, scanner, "scan", "source", "--offline", "--all-packages", "--config", scannerConfig, "--lockfile", bom, "--format", "json", "--output-file", outPath)
		cmd.Env = append(os.Environ(), "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="+db)
		log, err := cmd.CombinedOutput()
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
			t.Fatalf("OSV missed duplicate-version advisory: %v\n%s", err, log)
		}
		result, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(result), "OSV-TEST-1006") || !strings.Contains(string(result), "serde@1.0.188") {
			t.Fatalf("unexpected Cargo scan: %s", result)
		}
	})
}
