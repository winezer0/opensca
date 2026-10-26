package model

import (
	"context"
	"sort"
	"sync"
)

type diagnosticsKey struct{}
type Diagnostics struct {
	mu     sync.Mutex
	issues map[string]bool
}

func WithDiagnostics(ctx context.Context) (context.Context, *Diagnostics) {
	d := &Diagnostics{issues: map[string]bool{}}
	return context.WithValue(ctx, diagnosticsKey{}, d), d
}
func AddDiagnostic(ctx context.Context, issue string) {
	if d, ok := ctx.Value(diagnosticsKey{}).(*Diagnostics); ok {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.issues[issue] = true
	}
}
func (d *Diagnostics) List() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := []string{}
	for issue := range d.issues {
		out = append(out, issue)
	}
	sort.Strings(out)
	return out
}
