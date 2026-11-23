package versionaudit

import (
	"context"
	"reflect"
	"testing"
)

// TestDeclarations exercises native constraints before graph integration.
func TestDeclarations(t *testing.T) {
	tests := []struct {
		ecosystem, raw string
		want           []Candidate
	}{
		{"npm", ">1.0 <2.0", []Candidate{{"1.0", BoundaryFallback}, {"2.0", BoundaryFallback}}},
		{"pypi", ">1.0,<2.0", []Candidate{{"1.0", BoundaryFallback}, {"2.0", BoundaryFallback}}},
		{"pypi", ">=1!1.0,>=9.0", []Candidate{{"1!1.0", BoundaryFallback}}},
		{"nuget", "(1.0,2.0)", []Candidate{{"1.0", BoundaryFallback}, {"2.0", BoundaryFallback}}},
		{"maven", "(1.0,2.0)", []Candidate{{"1.0", BoundaryFallback}, {"2.0", BoundaryFallback}}},
		{"maven", "[1.5]", []Candidate{{"1.5", DeclaredExact}}},
		{"nuget", "1.5", []Candidate{{"1.5", BoundaryFallback}}},
		{"composer", ">=1.0 <2.0", []Candidate{{"1.0", BoundaryFallback}, {"2.0", BoundaryFallback}}},
		{"bundler", ">=1.0, <2.0", []Candidate{{"1.0", BoundaryFallback}, {"2.0", BoundaryFallback}}},
		{"pypi", "^1.2.3", []Candidate{{"1.2.3", BoundaryFallback}}},
		{"pypi", "~1.2", []Candidate{{"1.2", BoundaryFallback}}},
		{"cargo", "1.2", []Candidate{{"1.2", BoundaryFallback}}},
		{"npm", ">=1.0 <2.0 || >=3.0 <=4.0", []Candidate{{"1.0", BoundaryFallback}, {"4.0", BoundaryFallback}}},
		{"npm", "1.0 || 3.0", []Candidate{{"1.0", BoundaryFallback}, {"3.0", BoundaryFallback}}},
		{"maven", "[1.0,2.0),[3.0,4.0]", []Candidate{{"1.0", BoundaryFallback}, {"4.0", BoundaryFallback}}},
		{"composer", "1.0 - 2.0", []Candidate{{"1.0", BoundaryFallback}, {"2.0", BoundaryFallback}}},

		{"pypi", "!=1.0", nil},
		{"pypi", "*", nil},
		{"pypi", "1.*", nil},
		{"maven", "]1.0,2.0[", []Candidate{{"1.0", BoundaryFallback}, {"2.0", BoundaryFallback}}},
		{"maven", "1.+", nil},
	}
	for _, tt := range tests {
		t.Run(tt.ecosystem+tt.raw, func(t *testing.T) {
			got, err := ResolveDeclaration(context.Background(), Declaration{Ecosystem: tt.ecosystem, Name: "example", Constraint: tt.raw}, nil)
			if err != nil || !reflect.DeepEqual(got.Candidates, tt.want) {
				t.Fatalf("got %#v, %v; want %#v", got, err, tt.want)
			}
		})
	}
}

// TestDeclarationRejectsConflictingPins verifies full-expression validation.
func TestDeclarationRejectsConflictingPins(t *testing.T) {
	for _, raw := range []string{"==1.0,==2.0", ">=2.0,<=1.0", "==1.0,>=2.0", ">=bad"} {
		if _, err := ParseDeclaration(Declaration{Ecosystem: "pypi", Constraint: raw}); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
}

// TestDynamicMavenSelectors compares published releases without creating fallback ceilings.
func TestDynamicMavenSelectors(t *testing.T) {
	for _, raw := range []string{"1.+", "]1.0,2.0[", "latest.release"} {
		directory := &testDirectory{versions: []string{"1.0", "1.1", "1.9", "2.0-SNAPSHOT", "2.0"}}
		result, err := ResolveDeclaration(context.Background(), Declaration{Ecosystem: "maven", Name: "example:example", Constraint: raw}, directory)
		want := []Candidate{{"1.0", PublishedEndpoint}, {"1.9", PublishedEndpoint}}
		if raw == "]1.0,2.0[" {
			want = []Candidate{{"1.1", PublishedEndpoint}, {"2.0-SNAPSHOT", PublishedEndpoint}}
		}
		if raw == "latest.release" {
			want = []Candidate{{"1.0", PublishedEndpoint}, {"2.0", PublishedEndpoint}}
		}
		if err != nil || !reflect.DeepEqual(result.Candidates, want) {
			t.Fatalf("%s: %#v %v", raw, result, err)
		}
	}
}

// TestLegacyConstraintRecognition rejects symbolic ranges as exact versions.
func TestLegacyConstraintRecognition(t *testing.T) {
	for _, raw := range []string{"1.x", "1.*", ">1.0", "[1,2)", "1.+", "latest.release"} {
		if !IsConstraint(raw) {
			t.Errorf("unrecognized %q", raw)
		}
	}
	for _, raw := range []string{"1.10", "1!1.0", "1.0.post1", "v1.2.3", "1.0-SNAPSHOT"} {
		if IsConstraint(raw) {
			t.Errorf("concrete version marked unresolved: %q", raw)
		}
	}
}

// TestNativePublishedSelection preserves ecosystem meaning for unadorned minimum declarations.
func TestNativePublishedSelection(t *testing.T) {
	for _, tt := range []struct {
		ecosystem, raw string
		want           []Candidate
	}{
		{"nuget", "1.0", []Candidate{{"1.0", PublishedEndpoint}, {"2.0", PublishedEndpoint}}},
		{"cargo", "1.0", []Candidate{{"1.0", PublishedEndpoint}, {"1.9", PublishedEndpoint}}},
		{"composer", "~1.0", []Candidate{{"1.0", PublishedEndpoint}, {"1.9", PublishedEndpoint}}},
	} {
		result, err := ResolveDeclaration(context.Background(), Declaration{Ecosystem: tt.ecosystem, Name: "example", Constraint: tt.raw}, &testDirectory{versions: []string{"0.9", "1.0", "1.9", "2.0"}})
		if err != nil || !reflect.DeepEqual(result.Candidates, tt.want) {
			t.Fatalf("%s %s: %#v %v", tt.ecosystem, tt.raw, result, err)
		}
	}
}
