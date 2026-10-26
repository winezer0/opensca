package java

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/xmirrorsecurity/opensca-cli/v3/cmd/config"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
)

func localRepository() (string, error) {
	cfg := config.Conf().Java
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	path := cfg.LocalRepository
	if path == "" {
		path = os.Getenv("MAVEN_REPO_LOCAL")
	}
	if path == "" {
		settings := cfg.Settings
		if settings == "" {
			settings = filepath.Join(home, ".m2", "settings.xml")
		}
		data, err := os.ReadFile(settings)
		if err == nil {
			var s struct {
				Local string `xml:"localRepository"`
			}
			if err := xml.Unmarshal(data, &s); err != nil {
				return "", fmt.Errorf("read Maven settings: %w", err)
			}
			path = strings.TrimSpace(s.Local)
		} else if !os.IsNotExist(err) || cfg.Settings != "" {
			return "", err
		}
	}
	if path == "" {
		path = filepath.Join(home, ".m2", "repository")
	}
	path = strings.ReplaceAll(path, "${user.home}", home)
	path = os.Expand(path, func(k string) string { return os.Getenv(strings.TrimPrefix(k, "env.")) })
	return filepath.Abs(path)
}

func readPomFile(path string) *Pom {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	p := ReadPomAt(f, path)
	if p != nil {
		p.File = model.NewFile(path, path)
	}
	return p
}

func loadFromM2(group, artifact, version string) *Pom {
	for _, part := range []string{group, artifact, version} {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "/\\:$") {
			return nil
		}
	}
	repo, err := localRepository()
	if err != nil {
		return nil
	}
	p := readPomFile(filepath.Join(repo, filepath.FromSlash(strings.ReplaceAll(group, ".", "/")), artifact, version, artifact+"-"+version+".pom"))
	if p != nil && p.GAV() == (PomDependency{GroupId: group, ArtifactId: artifact, Version: version}).GAV() {
		return p
	}
	return nil
}

func relativeParent(dep PomDependency) *Pom {
	if dep.Define == nil || dep.RelativePath == "" || dep.Define.File.Abspath() == "" {
		return nil
	}
	path := filepath.Join(filepath.Dir(dep.Define.File.Abspath()), dep.RelativePath)
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		path = filepath.Join(path, "pom.xml")
	}
	p := readPomFile(path)
	if p == nil {
		return nil
	}
	p.Update(&p.PomDependency)
	if !matchesParent(p, dep) {
		return nil
	}
	return p
}

// Resolve identity before checking a local parent. CI-friendly versions can
// still contain properties inherited from that parent; defer that comparison
// until inheritance, while always rejecting a different group or artifact.
func matchesParent(p *Pom, dep PomDependency) bool {
	identity := p.PomDependency
	p.Update(&identity)
	if identity.GroupId != dep.GroupId || identity.ArtifactId != dep.ArtifactId {
		return false
	}
	return identity.Version == dep.Version || strings.Contains(identity.Version, "${") || strings.Contains(dep.Version, "${")
}
