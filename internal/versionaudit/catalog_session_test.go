package versionaudit

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

type sessionCatalog struct {
	calls atomic.Int32
	err   error
}

// Versions counts bounded shared requests.
func (c *sessionCatalog) Versions(context.Context, Package) ([]string, error) {
	c.calls.Add(1)
	return []string{"1.0"}, c.err
}

// TestCatalogSessionSharesSuccessAndFailure verifies per-scan request reuse.
func TestCatalogSessionSharesSuccessAndFailure(t *testing.T) {
	for _, directoryErr := range []error{nil, errors.New("unavailable")} {
		source := &sessionCatalog{err: directoryErr}
		session := &catalogSession{directory: source}
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				versions, err := session.Versions(context.Background(), Package{Name: "example"})
				if !errors.Is(err, directoryErr) || len(versions) != 1 || versions[0] != "1.0" {
					t.Errorf("response=%v,%v", versions, err)
				}
				versions[0] = "mutated"
			}()
		}
		wg.Wait()
		if source.calls.Load() != 1 {
			t.Fatalf("catalog requests=%d", source.calls.Load())
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := session.Versions(ctx, Package{Name: "other"}); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel error=%v", err)
		}
	}
}
