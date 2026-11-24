package opensca

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/xmirrorsecurity/opensca-cli/v3/internal/versionaudit"
)

type directoryProbe struct {
	identity []string
	err      error
	context  context.Context
}

// Versions captures the public protocol while returning configured directory evidence.
func (probe *directoryProbe) Versions(ctx context.Context, ecosystem, name, registry string) ([]string, error) {
	probe.identity = []string{ecosystem, name, registry}
	probe.context = ctx
	return []string{"1.0", "1.9"}, probe.err
}

// TestVersionDirectoryProtocol preserves package routing, cancellation and errors.
func TestVersionDirectoryProtocol(t *testing.T) {
	for _, failure := range []error{nil, context.Canceled} {
		probe := &directoryProbe{err: failure}
		system, _ := versionaudit.System("npm")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		versions, err := (versionDirectoryAdapter{source: probe}).Versions(ctx, versionaudit.Package{
			System: system, Name: "@scope/pkg", Registry: "https://registry.example",
		})
		if !reflect.DeepEqual(probe.identity, []string{"NPM", "@scope/pkg", "https://registry.example"}) || probe.context != ctx {
			t.Fatalf("catalog identity=%v context=%v", probe.identity, probe.context)
		}
		if !reflect.DeepEqual(versions, []string{"1.0", "1.9"}) || !errors.Is(err, failure) {
			t.Fatalf("directory evidence=%v error=%v", versions, err)
		}
	}
}
