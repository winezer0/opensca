package versionaudit

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"deps.dev/util/semver"
)

// TestSettingsValidatesAndRoutes checks configuration and cache identity.
func TestSettingsValidatesAndRoutes(t *testing.T) {
	t.Setenv("SCA_VERSION_DIRECTORY_OFFLINE", "true")
	t.Setenv("SCA_VERSION_DIRECTORY_CACHE", t.TempDir())
	t.Setenv("SCA_VERSION_REGISTRIES", `{"npm":"https://example.invalid"}`)
	settings, err := (Settings{}).Environment()
	if err != nil || !settings.Offline {
		t.Fatalf("settings=%#v err=%v", settings, err)
	}
	directory, err := settings.Directory()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := directory.Versions(context.Background(), Package{System: semver.NPM, Name: "example"}); err == nil {
		t.Fatal("offline cache miss succeeded")
	}
	before := CacheVersion("policy")
	t.Setenv("SCA_VERSION_REGISTRIES", `{"npm":"https://other.invalid"}`)
	if CacheVersion("policy") == before {
		t.Fatal("registry change reused analyzer cache")
	}
	for _, registries := range []map[string]string{{"npm": "file:///tmp/catalog"}, {"npm": "https://user:secret@example.invalid"}, {"npm": "https://example.invalid", "javascript": "https://other.invalid"}, {"unknown": "https://example.invalid"}} {
		if _, err := (Settings{Registries: registries}).Directory(); err == nil {
			t.Errorf("accepted invalid registries")
		}
	}
	t.Setenv("SCA_VERSION_DIRECTORY_OFFLINE", "invalid")
	if _, err := (Settings{}).Environment(); err == nil {
		t.Fatal("accepted invalid offline flag")
	}
}

// TestNuGetDiscoveryCachesEachPackage verifies service-index discovery and isolation.
func TestNuGetDiscoveryCachesEachPackage(t *testing.T) {
	var base string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/index.json":
			fmt.Fprintf(w, `{"resources":[{"@id":%q,"@type":"PackageBaseAddress/3.0.0"}]}`, base+"/flat/")
		case "/flat/first/index.json":
			fmt.Fprint(w, `{"versions":["1.0"]}`)
		case "/flat/second/index.json":
			fmt.Fprint(w, `{"versions":["2.0"]}`)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	base = server.URL
	directory := &CachedDirectory{CacheDir: t.TempDir(), Client: server.Client()}
	for i, name := range []string{"first", "second"} {
		got, err := directory.Versions(context.Background(), Package{System: semver.NuGet, Name: name, Registry: base + "/v3/index.json"})
		if err != nil || strings.Join(got, ",") != fmt.Sprintf("%d.0", i+1) {
			t.Fatalf("%s: %v %v", name, got, err)
		}
	}
	directory.Offline = true
	got, err := directory.Versions(context.Background(), Package{System: semver.NuGet, Name: "second", Registry: base + "/v3/index.json"})
	if err != nil || strings.Join(got, ",") != "2.0" {
		t.Fatalf("offline: %v %v", got, err)
	}
}
