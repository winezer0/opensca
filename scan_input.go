package main

import (
	"github.com/xmirrorsecurity/opensca-cli/v3/cmd/config"
	"path/filepath"
	"strings"
)

func scanIgnorePatterns() []string {
	cfg := config.Conf()
	patterns := append([]string(nil), cfg.Optional.Ignore...)
	root, err := filepath.Abs(cfg.Path)
	if err != nil {
		return patterns
	}
	paths := strings.Split(cfg.Output, ",")
	paths = append(paths, cfg.CacheDir)
	for _, path := range paths {
		if path == "" {
			continue
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(root, abs)
		if err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			patterns = append(patterns, "/"+filepath.ToSlash(rel))
		}
	}
	return patterns
}
