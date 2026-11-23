package versionaudit

import (
	"context"
	"sync"
)

// catalogSession prevents repeated network requests for one package within a scan.
type catalogSession struct {
	directory Directory
	mu        sync.Mutex
	entries   map[Package]*catalogEntry
}

type catalogEntry struct {
	done     chan struct{}
	versions []string
	err      error
}

// Versions shares a catalog request and respects each waiting caller's cancellation.
func (s *catalogSession) Versions(ctx context.Context, pkg Package) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.entries == nil {
		s.entries = make(map[Package]*catalogEntry)
	}
	entry, exists := s.entries[pkg]
	if !exists {
		entry = &catalogEntry{done: make(chan struct{})}
		s.entries[pkg] = entry
	}
	s.mu.Unlock()
	if !exists {
		entry.versions, entry.err = s.directory.Versions(ctx, pkg)
		close(entry.done)
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-entry.done:
		return append([]string(nil), entry.versions...), entry.err
	}
}
