package versionaudit

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"deps.dev/util/semver"
)

// Settings configures catalog access separately from dependency build networking.
type Settings struct {
	Offline    bool              `json:"offline"`
	CacheDir   string            `json:"cache_dir,omitempty"`
	Registries map[string]string `json:"registries,omitempty"`
}

// Environment applies administrator-provided overrides shared by all scan paths.
func (s Settings) Environment() (Settings, error) {
	if value, ok := os.LookupEnv("SCA_VERSION_DIRECTORY_OFFLINE"); ok {
		offline, err := strconv.ParseBool(value)
		if err != nil {
			return s, fmt.Errorf("invalid SCA_VERSION_DIRECTORY_OFFLINE")
		}
		s.Offline = offline
	}
	if value := os.Getenv("SCA_VERSION_DIRECTORY_CACHE"); value != "" {
		s.CacheDir = value
	}
	if value := os.Getenv("SCA_VERSION_REGISTRIES"); value != "" {
		if err := json.Unmarshal([]byte(value), &s.Registries); err != nil {
			return s, fmt.Errorf("invalid SCA_VERSION_REGISTRIES")
		}
	}
	if s.CacheDir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return s, err
		}
		s.CacheDir = filepath.Join(base, "tanspec", "version-directory")
	}
	return s, nil
}

// Directory constructs catalog access with explicit registry routing.
func (s Settings) Directory() (Directory, error) {
	seen := map[semver.System]bool{}
	for ecosystem, registry := range s.Registries {
		system, ok := System(ecosystem)
		if !ok {
			return nil, fmt.Errorf("unsupported version registry ecosystem: %s", ecosystem)
		}
		if seen[system] {
			return nil, fmt.Errorf("duplicate version registry ecosystem")
		}
		seen[system] = true
		name := "example"
		if system == semver.Maven {
			name = "example:example"
		}
		if _, _, err := directoryURL(Package{System: system, Name: name, Registry: registry}); err != nil {
			return nil, err
		}
	}
	return &catalogSession{directory: configuredDirectory{settings: s, cache: &CachedDirectory{CacheDir: s.CacheDir, Offline: s.Offline}}}, nil
}

type configuredDirectory struct {
	settings Settings
	cache    *CachedDirectory
}

// Versions routes a package to its configured ecosystem registry.
func (d configuredDirectory) Versions(ctx context.Context, pkg Package) ([]string, error) {
	for ecosystem, registry := range d.settings.Registries {
		system, ok := System(ecosystem)
		if ok && pkg.System == system {
			pkg.Registry = registry
			break
		}
	}
	return d.cache.Versions(ctx, pkg)
}

// CacheVersion invalidates analyzer snapshots when catalog routing or freshness changes.
func CacheVersion(policy string) string {
	value := os.Getenv("SCA_VERSION_DIRECTORY_OFFLINE") + "|" + os.Getenv("SCA_VERSION_DIRECTORY_CACHE") + "|" + os.Getenv("SCA_VERSION_REGISTRIES") + "|" + time.Now().UTC().Format("2006-01-02")
	return fmt.Sprintf("%s-%x", policy, sha256.Sum256([]byte(value)))
}
