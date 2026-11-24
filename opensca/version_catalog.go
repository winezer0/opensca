package opensca

import (
	"context"
	"fmt"

	"github.com/xmirrorsecurity/opensca-cli/v3/internal/versionaudit"
)

// VersionDirectory supplies published releases without exposing internal policy types.
// Ecosystem names use deps.dev's native system names, such as NPM, Maven and PyPI.
type VersionDirectory interface {
	Versions(ctx context.Context, ecosystem, name, registry string) ([]string, error)
}

type versionDirectoryAdapter struct{ source VersionDirectory }

// Versions translates internal package identity to the public catalog protocol.
func (adapter versionDirectoryAdapter) Versions(ctx context.Context, pkg versionaudit.Package) ([]string, error) {
	return adapter.source.Versions(ctx, fmt.Sprint(pkg.System), pkg.Name, pkg.Registry)
}
