package versionaudit

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"deps.dev/util/semver"
)

type testDirectory struct {
	versions []string
	err      error
	calls    int
}

func (d *testDirectory) Versions(context.Context, Package) ([]string, error) {
	d.calls++
	return d.versions, d.err
}

func TestResolve(t *testing.T) {
	base := Request{Package: Package{System: semver.NPM, Name: "fixture"}, Constraint: ">1.0.0 <2.0.0", Lower: Bound{Version: "1.0.0"}, Upper: Bound{Version: "2.0.0"}}
	for _, tc := range []struct {
		name         string
		change       func(*Request)
		versions     []string
		directoryErr error
		want         []Candidate
		wantError    bool
		wantCalls    int
	}{
		{name: "published endpoints exclude open boundaries", versions: []string{"2.0.0", "1.9.0", "1.0.0", "1.1.0", "bad"}, want: []Candidate{{"1.1.0", PublishedEndpoint}, {"1.9.0", PublishedEndpoint}}, wantCalls: 1},
		{name: "unavailable directory falls back outside open interval", directoryErr: errors.New("offline"), want: []Candidate{{"1.0.0", BoundaryFallback}, {"2.0.0", BoundaryFallback}}, wantCalls: 1},
		{name: "empty directory does not fallback", wantCalls: 1},
		{name: "successful directory with no matching release", versions: []string{"3.0.0"}, wantCalls: 1},
		{name: "singleton candidate deduplicated", versions: []string{"1.1.0", "1.1.0"}, want: []Candidate{{"1.1.0", PublishedEndpoint}}, wantCalls: 1},
		{name: "actual evidence wins", change: func(r *Request) { r.ActualVersion = "1.5.0" }, want: []Candidate{{"1.5.0", Actual}}},
		{name: "exact declaration wins", change: func(r *Request) { r.Exact = "1.3.0" }, want: []Candidate{{"1.3.0", DeclaredExact}}},
		{name: "actual wildcard rejected", change: func(r *Request) { r.ActualVersion = "1.*" }, wantError: true},
		{name: "exact range rejected", change: func(r *Request) { r.Exact = ">=1.0.0" }, wantError: true},
		{name: "contradictory bounds rejected", change: func(r *Request) { r.Lower.Version = "3.0.0" }, wantError: true},
		{name: "invalid constraint rejected", change: func(r *Request) { r.Constraint = ">oops" }, wantError: true},
		{name: "single lower fallback", change: func(r *Request) { r.Constraint = ">1.0.0"; r.Upper = Bound{} }, directoryErr: errors.New("offline"), want: []Candidate{{"1.0.0", BoundaryFallback}}, wantCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := base
			if tc.change != nil {
				tc.change(&request)
			}
			directory := &testDirectory{versions: tc.versions, err: tc.directoryErr}
			got, err := Resolve(context.Background(), request, directory)
			if (err != nil) != tc.wantError {
				t.Fatalf("Resolve error = %v", err)
			}
			if !reflect.DeepEqual(got.Candidates, tc.want) {
				t.Fatalf("candidates = %#v, want %#v", got.Candidates, tc.want)
			}
			if directory.calls != tc.wantCalls {
				t.Fatalf("directory calls = %d, want %d", directory.calls, tc.wantCalls)
			}
			if tc.directoryErr != nil && !errors.Is(got.DirectoryError, tc.directoryErr) {
				t.Fatalf("directory diagnostic lost: %v", got.DirectoryError)
			}
		})
	}
}

func TestPythonVersionOrdering(t *testing.T) {
	directory := &testDirectory{versions: []string{"1.9", "1.10", "1!1.0", "2!1.0"}}
	got, err := Resolve(context.Background(), Request{Package: Package{System: semver.PyPI}, Constraint: ">=1.0,<2!0.0"}, directory)
	want := []Candidate{{"1.9", PublishedEndpoint}, {"1!1.0", PublishedEndpoint}}
	if err != nil || !reflect.DeepEqual(got.Candidates, want) {
		t.Fatalf("Resolve = %#v, %v", got, err)
	}
}

func TestCancellationNeverFallsBack(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := Resolve(ctx, Request{Lower: Bound{Version: "1.0.0"}}, nil)
	if !errors.Is(err, context.Canceled) || len(got.Candidates) != 0 {
		t.Fatalf("Resolve = %#v, %v", got, err)
	}
}
