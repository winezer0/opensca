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

// OSV is an independent consumer used only by this opt-in compatibility test.
func TestOSVCompatibility(t *testing.T) {
	scanner := os.Getenv("OPENSCA_TEST_OSV_SCANNER")
	if scanner == "" {
		t.Skip("set OPENSCA_TEST_OSV_SCANNER to run external consumer compatibility test")
	}
	if scanner == "1" {
		scanner = "../osv-scanner/osv-scanner.exe"
	}
	scanner, err := filepath.Abs(scanner)
	if err != nil {
		t.Fatal(err)
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
	dbPath := filepath.Join(db, "osv-scalibr", "Maven", "all.zip")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(f)
	w, err := z.Create("CVE-2021-44228.json")
	if err != nil {
		t.Fatal(err)
	}
	_, err = w.Write([]byte(`{"schema_version":"1.6.0","id":"CVE-2021-44228","modified":"2024-01-01T00:00:00Z","published":"2021-12-10T00:00:00Z","affected":[{"package":{"ecosystem":"Maven","name":"org.apache.logging.log4j:log4j-core"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.0-beta9"},{"fixed":"2.15.0"}]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
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
}
