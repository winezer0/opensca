package versionaudit

import (
	"context"
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"deps.dev/util/semver"
	pep440 "github.com/aquasecurity/go-pep440-version"
)

// Declaration retains manifest syntax until audit candidate selection completes.
// Actual versions must be passed separately; a bare NuGet or Cargo declaration
// is not an exact pin.
type Declaration struct {
	Ecosystem     string
	Name          string
	Registry      string
	Constraint    string
	ActualVersion string
}

// System maps ecosystem identities to their version semantics.
func System(ecosystem string) (semver.System, bool) {
	switch strings.ToLower(ecosystem) {
	case "npm", "javascript":
		return semver.NPM, true
	case "pypi", "python", "poetry":
		return semver.PyPI, true
	case "nuget", "dotnet":
		return semver.NuGet, true
	case "gem", "bundler", "rubygems", "ruby", "cocoapods":
		return semver.RubyGems, true
	case "composer", "php", "packagist":
		return semver.Composer, true
	case "maven", "java", "gradle", "ivy", "sbt":
		return semver.Maven, true
	case "cargo", "rust", "crates.io":
		return semver.Cargo, true
	case "go", "golang":
		return semver.Go, true
	}
	return 0, false
}

// ResolveDeclaration parses an ecosystem declaration and selects candidates.
func ResolveDeclaration(ctx context.Context, declaration Declaration, directory Directory) (Result, error) {
	request, err := ParseDeclaration(declaration)
	if err != nil {
		return Result{}, err
	}
	return Resolve(ctx, request, directory)
}

// ParseDeclaration extracts literal boundaries without inventing adjacent or
// next-major versions. Implicit caret/tilde ceilings are used for matching by
// the ecosystem library, but are not manufactured for directory-failure fallback.
func ParseDeclaration(declaration Declaration) (Request, error) {
	system, supported := System(declaration.Ecosystem)
	if !supported {
		return Request{}, fmt.Errorf("unsupported version semantics: %s", declaration.Ecosystem)
	}
	r := Request{Package: Package{System: system, Name: declaration.Name, Registry: declaration.Registry}, ActualVersion: declaration.ActualVersion}
	if r.ActualVersion != "" {
		return r, nil
	}
	raw := strings.TrimSpace(declaration.Constraint)
	if raw == "" {
		return Request{}, fmt.Errorf("dependency declaration has no version")
	}
	r.Constraint = raw
	if system == semver.PyPI && raw == "*" {
		r.Constraint = ""
		return r, nil
	}
	if system == semver.PyPI && strings.Contains(raw, "*") && !strings.ContainsAny(raw, "<>=!~^, ") {
		r.Constraint = "==" + raw
		return r, nil
	}
	if system == semver.Maven {
		if strings.HasPrefix(raw, "]") {
			raw = "(" + raw[1:]
		}
		if strings.HasSuffix(raw, "[") {
			raw = raw[:len(raw)-1] + ")"
		}
		r.Constraint = raw
	}
	if system == semver.PyPI && strings.HasPrefix(raw, "(") && strings.HasSuffix(raw, ")") {
		raw = strings.TrimSpace(raw[1 : len(raw)-1])
		r.Constraint = raw
	}
	if (system == semver.NuGet || system == semver.Maven) && (strings.HasPrefix(raw, "[") || strings.HasPrefix(raw, "(")) {
		return interval(r, raw)
	}
	if system == semver.Maven && (strings.HasSuffix(raw, "+") || strings.HasPrefix(raw, "latest.")) {
		if _, err := matcher(r); err != nil {
			return Request{}, err
		}
		return r, nil
	}
	if err := validVersion(system, raw); err == nil {
		switch system {
		case semver.NuGet, semver.Cargo, semver.Go:
			r.Lower = Bound{Version: raw, Inclusive: true}
		default:
			r.Exact = raw
		}
		return r, nil
	}
	if system == semver.PyPI && (strings.HasPrefix(raw, "^") || strings.HasPrefix(raw, "~") && !strings.HasPrefix(raw, "~=")) {
		lower := strings.TrimSpace(raw[1:])
		upper, err := poetryCeiling(lower, raw[0])
		if err != nil {
			return Request{}, err
		}
		r.Lower = Bound{Version: lower, Inclusive: true}
		r.Constraint = ">=" + lower + ",<" + upper
		return r, nil
	}
	if strings.Contains(raw, "|") {
		if _, err := matcher(r); err != nil {
			return Request{}, err
		}
		parts := strings.Split(strings.ReplaceAll(raw, "||", "|"), "|")
		for i, part := range parts {
			branch, err := ParseDeclaration(Declaration{Ecosystem: declaration.Ecosystem, Name: declaration.Name, Registry: declaration.Registry, Constraint: part})
			if err != nil {
				return Request{}, err
			}
			if branch.Exact != "" {
				branch.Lower = Bound{Version: branch.Exact, Inclusive: true}
				branch.Upper = branch.Lower
			}
			if i == 0 {
				r.Lower, r.Upper = branch.Lower, branch.Upper
			} else {
				r.Lower = outerBound(system, r.Lower, branch.Lower, true)
				r.Upper = outerBound(system, r.Upper, branch.Upper, false)
			}

		}
		return r, nil
	}
	if parts := strings.Split(raw, " - "); len(parts) == 2 {
		r.Lower = Bound{Version: strings.TrimSpace(parts[0]), Inclusive: true}
		r.Upper = Bound{Version: strings.TrimSpace(parts[1]), Inclusive: true}
		if _, err := matcher(r); err != nil {
			return Request{}, err
		}
		return r, validateBounds(r)
	}
	for _, token := range declarationTokens.FindAllStringSubmatch(raw, -1) {
		op, value := token[1], token[2]
		if err := validVersion(system, value); err != nil {
			continue
		}
		switch op {
		case "==", "===", "=":
			if r.Exact != "" && compare(system, r.Exact, value) != 0 {
				return Request{}, fmt.Errorf("conflicting exact versions")
			}
			r.Exact = value
		case ">", ">=", "^", "~", "~>", "~=":
			r.Lower = tighter(system, r.Lower, Bound{Version: value, Inclusive: op != ">"}, true)
		case "<", "<=":
			r.Upper = tighter(system, r.Upper, Bound{Version: value, Inclusive: op == "<="}, false)
		}
	}
	// Parse the entire expression, not just the tokens extracted for fallback.
	if _, err := matcher(r); err != nil {
		return Request{}, err
	}
	if err := validateBounds(r); err != nil {
		return Request{}, err
	}
	if r.Exact != "" {
		match, _ := matcher(r)
		if !match(r.Exact) {
			return Request{}, fmt.Errorf("exact version violates declaration")
		}
	}
	return r, nil
}

// poetryCeiling translates Poetry operators into PEP 440 matching boundaries.
func poetryCeiling(raw string, operator byte) (string, error) {
	v, err := pep440.Parse(raw)
	if err != nil {
		return "", err
	}
	base := v.BaseVersion()
	epoch := ""
	if before, after, ok := strings.Cut(base, "!"); ok {
		epoch, base = before+"!", after
	}
	parts := strings.Split(base, ".")
	index := 0
	if operator == '~' && len(parts) > 1 {
		index = 1
	}
	if operator == '^' {
		index = len(parts) - 1
		for i, part := range parts {
			if strings.Trim(part, "0") != "" {
				index = i
				break
			}
		}
	}
	number, ok := new(big.Int).SetString(parts[index], 10)
	if !ok {
		return "", fmt.Errorf("invalid Poetry release")
	}
	parts[index] = number.Add(number, big.NewInt(1)).String()
	for i := index + 1; i < len(parts); i++ {
		parts[i] = "0"
	}
	return epoch + strings.Join(parts, "."), nil
}

var declarationTokens = regexp.MustCompile(`(===|==|~=|~>|>=|<=|!=|>|<|=|\^|~)\s*([^\s,|]+)`)

// tighter intersects explicit boundaries with native version comparison.
func tighter(system semver.System, old, next Bound, lower bool) Bound {
	if old.Version == "" {
		return next
	}
	cmp := compare(system, next.Version, old.Version)
	if lower && cmp > 0 || !lower && cmp < 0 {
		return next
	}
	if cmp == 0 {
		old.Inclusive = old.Inclusive && next.Inclusive
	}
	return old
}

// interval parses interval syntax while retaining literal endpoints.
func interval(r Request, raw string) (Request, error) {
	if len(raw) < 3 || !strings.ContainsAny(raw[len(raw)-1:], ")]") {
		return Request{}, fmt.Errorf("invalid interval")
	}
	inside := raw[1 : len(raw)-1]
	parts := strings.Split(inside, ",")
	if len(parts) == 1 && raw[0] == '[' && raw[len(raw)-1] == ']' {
		r.Exact = strings.TrimSpace(parts[0])
		if err := validVersion(r.Package.System, r.Exact); err != nil {
			return Request{}, err
		}
		return r, nil
	}
	if len(parts) != 2 {
		matches := intervalTokens.FindAllString(raw, -1)
		if len(matches) < 2 {
			return Request{}, fmt.Errorf("invalid compound interval")
		}
		if strings.Join(matches, ",") != strings.ReplaceAll(raw, " ", "") {
			return Request{}, fmt.Errorf("invalid compound interval")
		}
		if _, err := matcher(r); err != nil {
			return Request{}, err
		}
		for i, item := range matches {
			branch, err := interval(Request{Package: r.Package, Constraint: item}, item)
			if err != nil {
				return Request{}, err
			}
			if branch.Exact != "" {
				branch.Lower = Bound{Version: branch.Exact, Inclusive: true}
				branch.Upper = branch.Lower
			}
			if i == 0 {
				r.Lower, r.Upper = branch.Lower, branch.Upper
			} else {
				r.Lower = outerBound(r.Package.System, r.Lower, branch.Lower, true)
				r.Upper = outerBound(r.Package.System, r.Upper, branch.Upper, false)
			}
		}
		return r, nil
	}
	r.Lower = Bound{Version: strings.TrimSpace(parts[0]), Inclusive: raw[0] == '['}
	r.Upper = Bound{Version: strings.TrimSpace(parts[1]), Inclusive: raw[len(raw)-1] == ']'}
	if _, err := matcher(r); err != nil {
		return Request{}, err
	}
	return r, validateBounds(r)
}

// outerBound computes a union envelope while preserving unbounded sides.
func outerBound(system semver.System, old, next Bound, lower bool) Bound {
	if old.Version == "" || next.Version == "" {
		return Bound{}
	}
	cmp := compare(system, next.Version, old.Version)
	if lower && cmp < 0 || !lower && cmp > 0 {
		return next
	}
	if cmp == 0 {
		old.Inclusive = old.Inclusive || next.Inclusive
	}
	return old
}

var intervalTokens = regexp.MustCompile(`[\[(][^\[\]()]*[\])]`)
