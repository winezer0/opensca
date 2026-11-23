package versionaudit

import (
	"fmt"
	"regexp"
	"strings"

	"deps.dev/util/semver"
	pep440 "github.com/aquasecurity/go-pep440-version"
	composer "github.com/shyim/go-version"
)

// matcher compiles native constraints into a release predicate.
func matcher(request Request) (func(string) bool, error) {
	if request.Package.System == semver.Maven {
		raw := request.Constraint
		if raw == "latest.release" || raw == "latest.integration" || strings.HasSuffix(raw, "+") {
			prefix := strings.TrimSuffix(raw, "+")
			return func(value string) bool {
				if validVersion(semver.Maven, value) != nil {
					return false
				}
				if raw == "latest.release" {
					return !strings.HasSuffix(strings.ToUpper(value), "-SNAPSHOT")
				}
				return raw == "latest.integration" || strings.HasPrefix(value, prefix)
			}, nil
		}
	}
	if request.Package.System == semver.Composer {
		c, err := composer.NewConstraint(request.Constraint)
		if err != nil {
			return nil, err
		}
		return func(raw string) bool { v, err := composer.NewVersion(raw); return err == nil && c.Check(v) }, nil
	}
	if request.Package.System == semver.PyPI {
		if request.Constraint == "" {
			return func(raw string) bool { v, err := pep440.Parse(raw); return err == nil && !v.IsPreRelease() }, nil
		}
		specifiers, err := pep440.NewSpecifiers(request.Constraint)
		if err != nil {
			return nil, err
		}
		return func(raw string) bool {
			value, err := pep440.Parse(raw)
			return err == nil && specifiers.Check(value)
		}, nil
	}
	constraint, err := request.Package.System.ParseConstraint(request.Constraint)
	if err != nil {
		return nil, err
	}
	return func(raw string) bool {
		value, err := request.Package.System.Parse(raw)
		return err == nil && constraint.MatchVersion(value)
	}, nil
}

// validVersion rejects declaration syntax before parsing a concrete version.
func validVersion(system semver.System, raw string) error {
	if raw == "" || system == semver.Maven && (strings.HasSuffix(raw, "+") || strings.HasPrefix(raw, "latest.")) || wildcardVersion.MatchString(raw) || strings.ContainsAny(raw, "${}[](),*^~<>=@ \t\r\n") {
		return fmt.Errorf("version is not concrete")
	}
	if system == semver.Composer {
		_, err := composer.NewVersion(raw)
		return err
	}
	if system == semver.PyPI {
		_, err := pep440.Parse(raw)
		return err
	}
	v, err := system.Parse(raw)
	if err == nil && v.IsWildcard() {
		return fmt.Errorf("version is not concrete")
	}
	return err
}

// compare orders valid versions with their ecosystem semantics.
func compare(system semver.System, a, b string) int {
	if system == semver.Composer {
		left, _ := composer.NewVersion(a)
		right, _ := composer.NewVersion(b)
		return left.Compare(right)
	}
	if system == semver.PyPI {
		left, _ := pep440.Parse(a)
		right, _ := pep440.Parse(b)
		return left.Compare(right)
	}
	return system.Compare(a, b)
}

var wildcardVersion = regexp.MustCompile(`(?i)(^|\.)(x)(\.|-|$)`)

// IsConstraint recognizes unresolved syntax emitted by legacy parser paths.
func IsConstraint(raw string) bool {
	return strings.ContainsAny(raw, "[](),*^~<>= ") || wildcardVersion.MatchString(raw) || strings.HasPrefix(raw, "latest.") || strings.HasSuffix(raw, "+")
}
