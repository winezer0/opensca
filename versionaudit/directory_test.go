package versionaudit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"deps.dev/util/semver"
)

func TestDirectoryCacheAndOfflineFallback(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/fixture" {
			t.Errorf("request path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"versions":{"1.1.0":{},"1.9.0":{}}}`))
	}))
	defer server.Close()
	directory := &CachedDirectory{CacheDir: t.TempDir()}
	pkg := Package{System: semver.NPM, Name: "fixture", Registry: server.URL}
	request := Request{Package: pkg, Constraint: ">1.0.0 <2.0.0", Lower: Bound{Version: "1.0.0"}, Upper: Bound{Version: "2.0.0"}}
	want := []Candidate{{"1.1.0", PublishedEndpoint}, {"1.9.0", PublishedEndpoint}}
	for _, offline := range []bool{false, true} {
		directory.Offline = offline
		result, err := Resolve(context.Background(), request, directory)
		if err != nil || !reflect.DeepEqual(result.Candidates, want) {
			t.Fatalf("offline=%v: %#v, %v", offline, result, err)
		}
	}
	if calls != 1 {
		t.Fatalf("HTTP calls = %d, want 1", calls)
	}
	request.Package.Registry = server.URL + "/other"
	result, err := Resolve(context.Background(), request, directory)
	want = []Candidate{{"1.0.0", BoundaryFallback}, {"2.0.0", BoundaryFallback}}
	if err != nil || !reflect.DeepEqual(result.Candidates, want) || result.DirectoryError == nil {
		t.Fatalf("offline miss = %#v, %v", result, err)
	}
	if calls != 1 {
		t.Fatalf("offline cache miss issued HTTP request")
	}
}

func TestDecodeDirectories(t *testing.T) {
	for _, tc := range []struct {
		kind, data string
		want       []string
	}{
		{"npm", `{"versions":{"1.0.0":{}}}`, []string{"1.0.0"}},
		{"pypi", `{"releases":{"1!1.0":[]}}`, []string{"1!1.0"}},
		{"nuget", `{"versions":["1.0.0"]}`, []string{"1.0.0"}},
		{"gem", `[{"number":"1.0"}]`, []string{"1.0"}},
		{"cargo", `{"versions":[{"num":"1.0.0"}]}`, []string{"1.0.0"}},
		{"composer", `{"packages":{"vendor/pkg":[{"version":"v1.0.0"}]}}`, []string{"v1.0.0"}},
		{"maven", `<metadata><versioning><versions><version>1.0</version></versions></versioning></metadata>`, []string{"1.0"}},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			got, err := decodeDirectory(tc.kind, []byte(tc.data))
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("decode = %#v, %v", got, err)
			}
		})
	}
}

func TestDirectoryFailureDoesNotLookLikeEmptyReleaseList(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		status     int
	}{
		{"malformed", `{"versions":`, http.StatusOK},
		{"missing field", `{}`, http.StatusOK},
		{"http failure", ``, http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.data))
			}))
			defer server.Close()
			directory := &CachedDirectory{}
			_, err := directory.Versions(context.Background(), Package{System: semver.NPM, Name: "fixture", Registry: server.URL})
			if err == nil {
				t.Fatal("directory failure was accepted as empty")
			}
		})
	}
}
