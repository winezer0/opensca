package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type nugetTestBOM struct {
	Components []struct {
		Name, Type string
		Ref        string `json:"bom-ref"`
		PURL       string `json:"purl"`
	} `json:"components"`
	Dependencies []struct {
		Ref       string
		DependsOn []string
	} `json:"dependencies"`
	Properties []struct{ Name, Value string } `json:"properties"`
}

// Opt in explicitly; this starts the installed SDK with a temporary local-only
// NuGet feed. It never needs nuget.org or packages from the user's cache.
func TestNuGetLiveRestore(t *testing.T) {
	if os.Getenv("OPENSCA_TEST_LIVE_DOTNET") != "1" {
		t.Skip("set OPENSCA_TEST_LIVE_DOTNET=1 to run the real SDK/local-feed integration")
	}
	dotnet, err := exec.LookPath("dotnet")
	if err != nil {
		t.Fatal("live integration was requested but dotnet is unavailable: ", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	sdks, err := exec.CommandContext(ctx, dotnet, "--list-sdks").CombinedOutput()
	if err != nil {
		t.Fatalf("SDK detection: %v: %s", err, sdks)
	}
	versions := map[int]string{}
	for _, line := range strings.Split(string(sdks), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		version, _ := strconv.Atoi(strings.SplitN(fields[0], ".", 2)[0])
		if version >= 6 {
			versions[version] = fields[0]
		}
	}
	if len(versions) == 0 {
		t.Fatalf("live integration requires .NET SDK >=6; installed: %s", sdks)
	}
	t.Logf("real dotnet SDKs: %s", strings.TrimSpace(string(sdks)))
	for major, version := range versions {
		t.Run(fmt.Sprintf("sdk%d", major), func(t *testing.T) { runNuGetSDKFixture(t, ctx, major, version) })
	}
}

func runNuGetSDKFixture(t *testing.T, ctx context.Context, major int, sdkVersion string) {
	var err error
	dir := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		filename := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		return filename
	}
	feed := filepath.Join(dir, "feed")
	if err := os.MkdirAll(feed, 0700); err != nil {
		t.Fatal(err)
	}
	writeZip := func(filename string, records map[string]string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
			t.Fatal(err)
		}
		f, err := os.Create(filename)
		if err != nil {
			t.Fatal(err)
		}
		w := zip.NewWriter(f)
		for name, body := range records {
			entry, err := w.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = entry.Write([]byte(body)); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for _, pkg := range []struct{ name, version, dependencies string }{
		{"Local.Wrapper", "1.1.0", `<dependency id="Local.Leaf" version="[1.0.0,2.0.0)" />`},
		{"Local.Leaf", "1.0.0", ""}, {"Local.Extra", "1.0.0", ""}, {"Local.Extra", "2.0.0", ""},
	} {
		nuspec := fmt.Sprintf(`<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata><id>%s</id><version>%s</version><authors>OpenSCA Test</authors><description>Local-only dependency parser fixture</description><dependencies>%s</dependencies></metadata></package>`, pkg.name, pkg.version, pkg.dependencies)
		writeZip(filepath.Join(feed, pkg.name+"."+pkg.version+".nupkg"), map[string]string{pkg.name + ".nuspec": nuspec})
	}
	write("NuGet.Config", `<configuration><packageSources><clear /><add key="local" value="`+html.EscapeString(feed)+`" /></packageSources></configuration>`)
	write("global.json", `{"sdk":{"version":"`+sdkVersion+`","rollForward":"disable"}}`)
	central := `<Project><PropertyGroup><ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally></PropertyGroup><ItemGroup>
<PackageVersion Include="Local.Wrapper" Version="[1.0.0,2.0.0)" />
<PackageVersion Include="Local.Leaf" Version="[1.0.0]" />
<PackageVersion Include="Local.Extra" Version="1.0.0" Condition="'$(TargetFramework)' != 'netstandard2.1'" />
<PackageVersion Include="Local.Extra" Version="2.0.0" Condition="'$(TargetFramework)' == 'netstandard2.1'" />
</ItemGroup></Project>`
	write("Directory.Packages.props", central)
	frameworks := fmt.Sprintf("net%d.0;netstandard2.1", major)
	projectXML := `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFrameworks>` + frameworks + `</TargetFrameworks></PropertyGroup><ItemGroup><PackageReference Include="Local.Wrapper" /><PackageReference Include="Local.Extra" PrivateAssets="all" /><ProjectReference Include="../Child/Child.csproj" /></ItemGroup></Project>`
	project := write("App with spaces/App.csproj", projectXML)
	write("Child/Child.csproj", `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFrameworks>`+frameworks+`</TargetFrameworks></PropertyGroup><ItemGroup><PackageReference Include="Local.Leaf" /></ItemGroup></Project>`)
	conf := write("opensca-config.json", `{"optional":{"dynamic":"auto","dev":true}}`)
	binary := filepath.Join(dir, "opensca.exe")
	if out, err := exec.CommandContext(ctx, "go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, out)
	}
	cliEnv := append(os.Environ(), "NUGET_PACKAGES="+filepath.Join(dir, "package-cache"), "DOTNET_CLI_HOME="+filepath.Join(dir, "dotnet-home"), "DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=true")
	entry := project
	run := func(name string, offline bool, wantExit int) (nugetTestBOM, string) {
		t.Helper()
		bom := filepath.Join(dir, name+".cdx.json")
		args := []string{"-config", conf, "-path", entry, "-dependencies-only", "-cache-dir", filepath.Join(dir, "cache"), "-log", filepath.Join(dir, "opensca.log"), "-out", bom}
		if offline {
			args = append(args, "-offline")
		}
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Env = cliEnv
		out, err := cmd.CombinedOutput()
		actual := 0
		if err != nil {
			if exit, ok := err.(*exec.ExitError); ok {
				actual = exit.ExitCode()
			} else {
				t.Fatalf("CLI: %v: %s", err, out)
			}
		}
		if actual != wantExit {
			logs, _ := os.ReadFile(filepath.Join(dir, "opensca.log"))
			t.Fatalf("CLI exit=%d want=%d: %s\nlog:\n%s", actual, wantExit, out, logs)
		}
		data, err := os.ReadFile(bom)
		if err != nil {
			t.Fatal(err)
		}
		var result nugetTestBOM
		if err := json.Unmarshal(data, &result); err != nil {
			t.Fatal(err)
		}
		return result, bom
	}
	check := func(result nugetTestBOM, extraV1 bool) {
		t.Helper()
		found, edges := map[string]bool{}, map[string]bool{}
		child := ""
		for _, c := range result.Components {
			if c.PURL != "" {
				found[c.PURL] = true
			}
			if c.Name == "Child" && c.Type == "application" {
				child = c.Ref
				if c.PURL != "" {
					t.Fatal("ProjectReference received a public NuGet PURL: ", c.PURL)
				}
			}
		}
		for _, d := range result.Dependencies {
			for _, c := range d.DependsOn {
				edges[d.Ref+"->"+c] = true
			}
		}
		for _, p := range []string{"pkg:nuget/Local.Wrapper@1.1.0", "pkg:nuget/Local.Leaf@1.0.0", "pkg:nuget/Local.Extra@2.0.0"} {
			if !found[p] {
				t.Fatalf("missing resolved package %s: %+v", p, result)
			}
		}
		if found["pkg:nuget/Local.Extra@1.0.0"] != extraV1 {
			t.Fatalf("wrong per-framework versions: %v", found)
		}
		for _, edge := range []string{"pkg:nuget/Local.Wrapper@1.1.0->pkg:nuget/Local.Leaf@1.0.0", child + "->pkg:nuget/Local.Leaf@1.0.0"} {
			if child == "" || !edges[edge] {
				t.Fatalf("missing resolved edge %s: %+v", edge, result)
			}
		}
		if len(result.Properties) != 0 {
			t.Fatalf("successful restore unexpectedly diagnosed: %+v", result.Properties)
		}
	}
	initial, bom := run("restored", false, 0)
	check(initial, true)
	if _, err := os.Stat(filepath.Join(filepath.Dir(project), "obj", "project.assets.json")); err != nil {
		t.Fatal("restore did not generate assets: ", err)
	}
	reused, _ := run("offline-reuse", true, 0)
	check(reused, true)
	entry = write("Workspace.sln", "Project(\"{GUID}\") = \"App\", \"App with spaces\\App.csproj\", \"{APP}\"\nEndProject\nProject(\"{GUID}\") = \"Child\", \"Child\\Child.csproj\", \"{CHILD}\"\nEndProject\n")
	solution, _ := run("solution-offline", true, 0)
	check(solution, true)
	entry = project
	if scanner := os.Getenv("OSV_SCANNER"); scanner != "" {
		if scanner == "1" {
			scanner = "../osv-scanner/osv-scanner.exe"
		}
		scanner, err = filepath.Abs(scanner)
		if err != nil {
			t.Fatal(err)
		}
		db := filepath.Join(dir, "osv-db")
		writeZip(filepath.Join(db, "osv-scalibr", "NuGet", "all.zip"), map[string]string{"OSV-TEST-NUGET-RESTORE.json": `{"schema_version":"1.6.0","id":"OSV-TEST-NUGET-RESTORE","modified":"2024-01-01T00:00:00Z","published":"2024-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"NuGet","name":"Local.Leaf"},"versions":["1.0.0"]}]}`})
		output := filepath.Join(dir, "osv.json")
		scannerConfig := write("osv-scanner.toml", "")
		cmd := exec.CommandContext(ctx, scanner, "scan", "source", "--offline", "--all-packages", "--config", scannerConfig, "--lockfile", bom, "--format", "json", "--output-file", output)
		cmd.Env = append(os.Environ(), "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="+db)
		out, err := cmd.CombinedOutput()
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
			t.Fatalf("OSV missed restored transitive package: %v: %s", err, out)
		}
		data, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"pkg:nuget/Local.Wrapper@1.1.0", "pkg:nuget/Local.Leaf@1.0.0", "pkg:nuget/Local.Extra@1.0.0", "pkg:nuget/Local.Extra@2.0.0", "OSV-TEST-NUGET-RESTORE"} {
			if !strings.Contains(string(data), want) {
				t.Fatalf("OSV lost %s: %s", want, data)
			}
		}
	} else {
		t.Log("OSV_SCANNER is unset; real restore and graph checks ran, external OSV consumption skipped")
	}
	central = strings.Replace(central, `Version="1.0.0" Condition=`, `Version="2.0.0" Condition=`, 1)
	write("Directory.Packages.props", central)
	refreshed, _ := run("props-refreshed", false, 0)
	check(refreshed, false)
	write("Directory.Packages.props", strings.Replace(central, "</ItemGroup>", `<PackageVersion Include="Missing.Package" Version="1.0.0" /></ItemGroup>`, 1))
	write("App with spaces/App.csproj", strings.Replace(projectXML, `Include="Local.Wrapper"`, `Include="Missing.Package"`, 1))
	failed, _ := run("restore-failed", false, 3)
	diagnosed := false
	for _, p := range failed.Properties {
		diagnosed = diagnosed || strings.Contains(p.Value, "dotnet restore failed") && strings.Contains(p.Value, "dependency data may be incomplete")
	}
	if !diagnosed {
		t.Fatalf("restore failure was not surfaced in SBOM: %+v", failed)
	}
}
