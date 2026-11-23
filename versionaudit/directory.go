package versionaudit

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"deps.dev/util/semver"
)

const maxDirectoryBytes = 16 << 20

// CachedDirectory reads reusable metadata before making a bounded registry
// request. Offline prevents HTTP requests but still permits cached metadata.
type CachedDirectory struct {
	CacheDir string
	Offline  bool
	Client   *http.Client
	MaxAge   time.Duration
}

type cacheRecord struct {
	Fetched  time.Time `json:"fetched"`
	Versions []string  `json:"versions"`
}

// Versions reads a configured registry's published release directory.
func (d *CachedDirectory) Versions(ctx context.Context, pkg Package) ([]string, error) {
	endpoint, kind, err := directoryURL(pkg)
	if pkg.System == semver.NuGet && strings.HasSuffix(strings.ToLower(pkg.Registry), "/index.json") {
		endpoint = pkg.Registry
	}
	if err != nil {
		return nil, err
	}
	key := fmt.Sprintf("%x.json", sha256.Sum256([]byte(endpoint+"|"+pkg.Name)))
	path := filepath.Join(d.CacheDir, key)
	if versions, ok := d.cached(path); ok {
		return versions, nil
	}
	if d.Offline {
		return nil, fmt.Errorf("published version directory unavailable offline")
	}
	client := d.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	data, err := readDirectory(ctx, client, endpoint)
	if err != nil {
		return nil, err
	}
	if kind == "nuget" && strings.HasSuffix(strings.ToLower(pkg.Registry), "/index.json") {
		endpoint, err = nugetBaseAddress(pkg.Registry, data)
		if err != nil {
			return nil, err
		}
		data, err = readDirectory(ctx, client, strings.TrimRight(endpoint, "/")+"/"+url.PathEscape(strings.ToLower(pkg.Name))+"/index.json")
		if err != nil {
			return nil, err
		}
	}

	versions, err := decodeDirectory(kind, data)
	if err != nil {
		return nil, fmt.Errorf("invalid published version directory: %w", err)
	}
	if d.CacheDir != "" {
		d.save(path, versions)
	}
	return versions, nil
}

// cached reads a bounded metadata record and enforces freshness online.
func (d *CachedDirectory) cached(path string) ([]string, bool) {
	if d.CacheDir == "" {
		return nil, false
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxDirectoryBytes+1))
	var record cacheRecord
	if err != nil || len(data) > maxDirectoryBytes || json.Unmarshal(data, &record) != nil || record.Versions == nil {
		return nil, false
	}
	age := d.MaxAge
	if age <= 0 {
		age = 24 * time.Hour
	}
	if !d.Offline && time.Since(record.Fetched) > age {
		return nil, false
	}
	return record.Versions, true
}

// save attempts to cache metadata without failing an otherwise valid scan.
func (d *CachedDirectory) save(path string, versions []string) {
	if os.MkdirAll(d.CacheDir, 0700) != nil {
		return
	}
	data, err := json.Marshal(cacheRecord{Fetched: time.Now().UTC(), Versions: versions})
	if err != nil {
		return
	}
	file, err := os.CreateTemp(d.CacheDir, "directory-*")
	if err != nil {
		return
	}
	name := file.Name()
	defer os.Remove(name)
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr == nil && closeErr == nil {
		_ = os.Rename(name, path)
	}
}

// directoryURL builds a configured ecosystem catalog URL.
func directoryURL(pkg Package) (string, string, error) {
	registry := strings.TrimRight(pkg.Registry, "/")
	var suffix, kind string
	switch pkg.System {
	case semver.NPM:
		if registry == "" {
			registry = "https://registry.npmjs.org"
		}
		suffix, kind = "/"+url.PathEscape(pkg.Name), "npm"
	case semver.PyPI:
		if registry == "" {
			registry = "https://pypi.org"
		}
		suffix, kind = "/pypi/"+url.PathEscape(pkg.Name)+"/json", "pypi"
	case semver.NuGet:
		// Registry is a PackageBaseAddress, not a NuGet service-index URL.
		if registry == "" {
			registry = "https://api.nuget.org/v3-flatcontainer"
		}
		suffix, kind = "/"+url.PathEscape(strings.ToLower(pkg.Name))+"/index.json", "nuget"
	case semver.RubyGems:
		if registry == "" {
			registry = "https://rubygems.org"
		}
		suffix, kind = "/api/v1/versions/"+url.PathEscape(pkg.Name)+".json", "gem"
	case semver.Composer:
		if registry == "" {
			registry = "https://repo.packagist.org"
		}
		suffix, kind = "/p2/"+escapedPath(pkg.Name)+".json", "composer"
	case semver.Cargo:
		if registry == "" {
			registry = "https://crates.io"
		}
		suffix, kind = "/api/v1/crates/"+url.PathEscape(pkg.Name), "cargo"
	case semver.Maven:
		if registry == "" {
			registry = "https://repo.maven.apache.org/maven2"
		}
		parts := strings.Split(pkg.Name, ":")
		if len(parts) != 2 {
			return "", "", fmt.Errorf("Maven package must use group:artifact identity")
		}
		suffix, kind = "/"+escapedPath(strings.ReplaceAll(parts[0], ".", "/"))+"/"+url.PathEscape(parts[1])+"/maven-metadata.xml", "maven"
	default:
		return "", "", fmt.Errorf("published version directory unsupported for ecosystem")
	}
	base, err := url.Parse(registry)
	if err != nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") || base.RawQuery != "" || base.Fragment != "" || base.User != nil {
		return "", "", fmt.Errorf("invalid version registry URL")
	}
	return registry + suffix, kind, nil
}

// escapedPath escapes each package path segment separately.
func escapedPath(path string) string {
	parts := strings.Split(path, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}

// decodeDirectory decodes a supported catalog response.
func decodeDirectory(kind string, data []byte) ([]string, error) {
	versions := []string{}
	if kind == "maven" {
		var doc struct {
			XMLName  xml.Name `xml:"metadata"`
			Versions []string `xml:"versioning>versions>version"`
		}
		err := xml.Unmarshal(data, &doc)
		return append(versions, doc.Versions...), err
	}
	if kind == "gem" {
		var doc []struct {
			Number string `json:"number"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, err
		}
		if doc == nil {
			return nil, fmt.Errorf("missing versions")
		}
		for _, item := range doc {
			versions = append(versions, item.Number)
		}
		return versions, nil
	}
	var doc struct {
		Versions json.RawMessage            `json:"versions"`
		Releases map[string]json.RawMessage `json:"releases"`
		Packages map[string][]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	switch kind {
	case "npm":
		var releases map[string]json.RawMessage
		if err := json.Unmarshal(doc.Versions, &releases); err != nil {
			return nil, err
		}
		if releases == nil {
			return nil, fmt.Errorf("missing versions")
		}
		for version := range releases {
			versions = append(versions, version)
		}
	case "pypi":
		if doc.Releases == nil {
			return nil, fmt.Errorf("missing releases")
		}
		for version := range doc.Releases {
			versions = append(versions, version)
		}
	case "nuget":
		if err := json.Unmarshal(doc.Versions, &versions); err != nil {
			return nil, err
		}
		if versions == nil {
			return nil, fmt.Errorf("missing versions")
		}
	case "cargo":
		var releases []struct {
			Number string `json:"num"`
		}
		if err := json.Unmarshal(doc.Versions, &releases); err != nil {
			return nil, err
		}
		if releases == nil {
			return nil, fmt.Errorf("missing versions")
		}
		for _, release := range releases {
			versions = append(versions, release.Number)
		}
	case "composer":
		if doc.Packages == nil {
			return nil, fmt.Errorf("missing packages")
		}
		for _, releases := range doc.Packages {
			for _, release := range releases {
				versions = append(versions, release.Version)
			}
		}
	}
	return versions, nil
}

// readDirectory enforces the same transport limits for catalogs and discovery.
func readDirectory(ctx context.Context, client *http.Client, endpoint string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid registry request")
	}
	request.Header.Set("Accept", "application/json, application/xml")
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("published version directory request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("published version directory returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxDirectoryBytes+1))
	if err != nil || len(data) > maxDirectoryBytes {
		return nil, fmt.Errorf("published version directory exceeds read limit or cannot be read")
	}
	return data, nil
}

// nugetBaseAddress discovers the package catalog without changing registry host.
func nugetBaseAddress(registry string, data []byte) (string, error) {
	var index struct {
		Resources []struct {
			ID   string `json:"@id"`
			Type string `json:"@type"`
		} `json:"resources"`
	}
	if err := json.Unmarshal(data, &index); err != nil {
		return "", fmt.Errorf("invalid NuGet service index")
	}
	origin, _ := url.Parse(registry)
	for _, resource := range index.Resources {
		if !strings.HasPrefix(resource.Type, "PackageBaseAddress/") {
			continue
		}
		target, err := url.Parse(resource.ID)
		if err != nil || target.Host != origin.Host || target.Scheme != origin.Scheme || target.User != nil || target.RawQuery != "" || target.Fragment != "" {
			return "", fmt.Errorf("invalid NuGet catalog resource")
		}
		return target.String(), nil
	}
	return "", fmt.Errorf("NuGet service index has no package catalog")
}
