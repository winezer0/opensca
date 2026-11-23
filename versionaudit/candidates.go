// Package versionaudit selects concrete audit candidates without treating a
// dependency declaration as evidence of an installed version.
package versionaudit

import (
	"context"
	"fmt"
	"sort"

	"deps.dev/util/semver"
)

// Source identifies the evidence behind a candidate version.
type Source string

const (
	Actual            Source = "actual"
	DeclaredExact     Source = "declared_exact"
	PublishedEndpoint Source = "published_endpoint"
	BoundaryFallback  Source = "boundary_fallback"
)

// Candidate is a concrete version to submit to exact-version matching.
type Candidate struct {
	Version string `json:"version"`
	Source  Source `json:"source"`
}

// Directory supplies all published versions for a package. A successful empty
// response differs from an unavailable directory and must not trigger fallback.
type Directory interface {
	Versions(context.Context, Package) ([]string, error)
}

// Package identifies a package within its configured registry.
type Package struct {
	System   semver.System
	Name     string
	Registry string
}

// Bound records a literal boundary after ecosystem-specific parsing. Empty
// versions represent unbounded sides; Inclusive controls directory filtering.
type Bound struct {
	Version   string
	Inclusive bool
}

// Request separates resolved evidence from declaration constraints. Constraint
// and bounds must be produced by the ecosystem parser, before normalization
// discards operators. Exact is set only for syntax that pins one version.
type Request struct {
	Package       Package
	ActualVersion string
	Exact         string
	Constraint    string
	Lower         Bound
	Upper         Bound
}

// Result retains candidate provenance and a recoverable directory diagnostic.
type Result struct {
	Candidates     []Candidate
	DirectoryError error
}

// Resolve prefers actual evidence, then explicit pins, then published endpoints.
// An unavailable directory falls back to literal bounds, even for open bounds,
// according to the audit policy. Cancellation never triggers this fallback.
func Resolve(ctx context.Context, request Request, directory Directory) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if request.ActualVersion != "" {
		return one(request, request.ActualVersion, Actual)
	}
	if request.Exact != "" {
		return one(request, request.Exact, DeclaredExact)
	}
	match, err := matcher(request)
	if err != nil {
		return Result{}, fmt.Errorf("invalid dependency constraint: %w", err)
	}
	if err := validateBounds(request); err != nil {
		return Result{}, err
	}
	var versions []string
	directoryErr := fmt.Errorf("version directory unavailable")
	if directory != nil {
		versions, directoryErr = directory.Versions(ctx, request.Package)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if directoryErr != nil {
		return fallback(request, directoryErr), nil
	}
	return endpoints(request, match, versions), nil
}

// one returns a validated single version with provenance.
func one(request Request, version string, source Source) (Result, error) {
	if err := validVersion(request.Package.System, version); err != nil {
		return Result{}, fmt.Errorf("invalid concrete version: %w", err)
	}
	return Result{Candidates: []Candidate{{Version: version, Source: source}}}, nil
}

// validateBounds rejects contradictory or nonconcrete literal bounds.
func validateBounds(request Request) error {
	for _, bound := range []Bound{request.Lower, request.Upper} {
		if bound.Version == "" {
			continue
		}
		if err := validVersion(request.Package.System, bound.Version); err != nil {
			return fmt.Errorf("invalid declaration boundary: %w", err)
		}
	}
	if request.Lower.Version == "" || request.Upper.Version == "" {
		return nil
	}
	cmp := compare(request.Package.System, request.Lower.Version, request.Upper.Version)
	if cmp > 0 || cmp == 0 && (!request.Lower.Inclusive || !request.Upper.Inclusive) {
		return fmt.Errorf("contradictory declaration boundaries")
	}
	return nil
}

// fallback retains only literal boundaries when directory access fails.
func fallback(request Request, err error) Result {
	result := Result{DirectoryError: err}
	for _, bound := range []Bound{request.Lower, request.Upper} {
		if bound.Version != "" {
			result.Candidates = appendUnique(result.Candidates, bound.Version, BoundaryFallback)
		}
	}
	return result
}

// endpoints chooses the native minimum and maximum matching releases.
func endpoints(request Request, match func(string) bool, versions []string) Result {
	var matched []string
	for _, version := range versions {
		if validVersion(request.Package.System, version) == nil && match(version) {
			matched = append(matched, version)
		}
	}
	if len(matched) == 0 {
		return Result{}
	}
	sort.Slice(matched, func(i, j int) bool {
		cmp := compare(request.Package.System, matched[i], matched[j])
		if cmp == 0 {
			return matched[i] < matched[j]
		}
		return cmp < 0
	})
	result := Result{Candidates: []Candidate{{Version: matched[0], Source: PublishedEndpoint}}}
	result.Candidates = appendUnique(result.Candidates, matched[len(matched)-1], PublishedEndpoint)
	return result
}

// appendUnique deduplicates candidate versions while preserving endpoint order.
func appendUnique(items []Candidate, version string, source Source) []Candidate {
	for _, item := range items {
		if item.Version == version {
			return items
		}
	}
	return append(items, Candidate{Version: version, Source: source})
}
