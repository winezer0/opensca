package javascript

// The version-specific layouts follow MurphySec's module/pnpm parsers.
// This adapter builds OpenSCA graphs directly, including optional dependencies,
// workspace links and peer-specific snapshots, without invoking npm or pnpm.
import (
	"context"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
	"gopkg.in/yaml.v3"
)

type pnpmRef string

func (r *pnpmRef) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode && n.Tag != "!!null" {
		*r = pnpmRef(n.Value)
		return nil
	}
	if n.Kind == yaml.MappingNode {
		var dep struct {
			Version string `yaml:"version"`
		}
		if err := n.Decode(&dep); err != nil {
			return err
		}
		*r = pnpmRef(dep.Version)
		return nil
	}
	return fmt.Errorf("dependency must be a version or a version object")
}

type pnpmImporter struct {
	Dependencies         map[string]pnpmRef `yaml:"dependencies"`
	DevDependencies      map[string]pnpmRef `yaml:"devDependencies"`
	OptionalDependencies map[string]pnpmRef `yaml:"optionalDependencies"`
}

type pnpmPackage struct {
	Name                 string             `yaml:"name"`
	Version              string             `yaml:"version"`
	Dependencies         map[string]pnpmRef `yaml:"dependencies"`
	OptionalDependencies map[string]pnpmRef `yaml:"optionalDependencies"`
}

type pnpmLock struct {
	Version      string `yaml:"lockfileVersion"`
	pnpmImporter `yaml:",inline"`
	Importers    map[string]*pnpmImporter `yaml:"importers"`
	Packages     map[string]*pnpmPackage  `yaml:"packages"`
	Snapshots    map[string]*pnpmPackage  `yaml:"snapshots"`
}

func isPnpmLock(relpath string) bool {
	return path.Base(strings.ReplaceAll(relpath, `\`, "/")) == "pnpm-lock.yaml"
}

// pnpmKeys keeps traversal and output deterministic, independent of YAML order.
func pnpmKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func pnpmVersion(s string) string {
	if i := strings.IndexAny(s, "(_"); i >= 0 {
		return s[:i]
	}
	return s
}

// pnpmIdentity accepts /@scope/name/1.0 (v5), /@scope/name@1.0 (v6),
// and @scope/name@1.0 (v9), preserving peer suffixes for snapshot lookup.
func pnpmIdentity(key string, major string) (string, string) {
	key = strings.TrimPrefix(key, "/")
	if major == "5" {
		start := 0
		if strings.HasPrefix(key, "@") {
			start = strings.Index(key, "/") + 1
		}
		if i := strings.Index(key[start:], "/") + start; i > start {
			return key[:i], key[i+1:]
		}
	} else {
		base := key
		if i := strings.Index(base, "("); i >= 0 {
			base = base[:i]
		}
		if i := strings.LastIndex(base, "@"); i > 0 {
			return key[:i], key[i+1:]
		}
	}
	return "", ""
}

func readPnpmLock(ctx context.Context, file *model.File, manifests map[string]*PackageJson) (*model.DepGraph, []string, error) {
	var lock pnpmLock
	var parseErr error
	err := file.OpenReader(func(reader io.Reader) {
		const maxSize = 32 << 20
		data, e := io.ReadAll(io.LimitReader(reader, maxSize+1))
		if e != nil {
			parseErr = e
			return
		}
		if len(data) > maxSize {
			parseErr = fmt.Errorf("lockfile exceeds 32 MiB")
			return
		}
		parseErr = yaml.Unmarshal(data, &lock)
	})
	if err != nil {
		return nil, nil, err
	}
	if parseErr != nil {
		return nil, nil, parseErr
	}
	major := strings.SplitN(lock.Version, ".", 2)[0]
	if major != "5" && major != "6" && major != "9" {
		return nil, nil, fmt.Errorf("unsupported lockfileVersion %q (supported: 5, 6, 9)", lock.Version)
	}
	if lock.Importers == nil {
		// A valid empty single-project v5/v6 lockfile can omit all dep maps.
		if major == "9" {
			return nil, nil, fmt.Errorf("missing importers")
		}
		lock.Importers = map[string]*pnpmImporter{".": &lock.pnpmImporter}
	}
	root, err := buildPnpmGraph(ctx, file, &lock, major, manifests)
	return root, pnpmKeys(lock.Importers), err
}

func buildPnpmGraph(ctx context.Context, file *model.File, lock *pnpmLock, major string, manifests map[string]*PackageJson) (*model.DepGraph, error) {
	dir := path.Dir(strings.ReplaceAll(file.Relpath(), `\`, "/"))
	root := &model.DepGraph{Path: file.Relpath(), Project: true}
	if js := manifests[dir]; js != nil {
		root.Name, root.Version = js.Name, js.Version
	}
	importers := map[string]*model.DepGraph{}
	for _, key := range pnpmKeys(lock.Importers) {
		if lock.Importers[key] == nil || path.IsAbs(key) || path.Clean(key) == ".." || strings.HasPrefix(path.Clean(key), "../") {
			return nil, fmt.Errorf("invalid importer %q", key)
		}
		clean := path.Clean(key)
		if importers[clean] != nil {
			return nil, fmt.Errorf("duplicate importer %q", key)
		}
		n := root
		if clean != "." {
			n = &model.DepGraph{Name: clean, Project: true, Path: path.Join(dir, clean, "package.json")}
			if js := manifests[path.Join(dir, clean)]; js != nil {
				n.Name, n.Version = js.Name, js.Version
			}
			root.AppendChild(n)
		}
		importers[clean] = n
	}
	entries := lock.Packages
	if major == "9" {
		entries = lock.Snapshots
	}
	nodes := map[string]*model.DepGraph{}
	for _, key := range pnpmKeys(entries) {
		pkg := entries[key]
		if pkg == nil {
			return nil, fmt.Errorf("null package %q", key)
		}
		name, version := pnpmIdentity(key, major)
		if name == "" || version == "" || strings.ContainsAny(pnpmVersion(version), ":/") {
			return nil, fmt.Errorf("unsupported package source %q", key)
		}
		meta := pkg
		if major == "9" {
			meta = lock.Packages[name+"@"+pnpmVersion(version)]
			if meta == nil {
				return nil, fmt.Errorf("snapshot %q has no package metadata", key)
			}
		}
		if meta.Name != "" {
			name = meta.Name
		}
		if meta.Version != "" {
			version = meta.Version
		}
		version = pnpmVersion(version)
		_, versionErr := semver.NewVersion(version)
		if name == "" || versionErr != nil || model.Purl("", name, version, model.Lan_JavaScript) == "" {
			return nil, fmt.Errorf("unsupported package identity %q", key)
		}
		nodes[key] = &model.DepGraph{Name: name, Version: version, Develop: true,
			Path: file.Relpath() + "/" + key}
	}
	resolve := func(name, version, importer string) (*model.DepGraph, error) {
		if strings.HasPrefix(version, "link:") || strings.HasPrefix(version, "workspace:") {
			target := strings.TrimPrefix(strings.TrimPrefix(version, "link:"), "workspace:")
			if n := importers[path.Join(importer, target)]; n != nil {
				return n, nil
			}
			return nil, fmt.Errorf("unresolved workspace %s@%s in %s", name, version, importer)
		}
		version = strings.TrimPrefix(version, "npm:")
		candidates := []string{version, "/" + version, name + "@" + version, "/" + name + "@" + version, "/" + name + "/" + version}
		for _, key := range candidates {
			if n := nodes[key]; n != nil {
				return n, nil
			}
		}
		return nil, fmt.Errorf("unresolved dependency %s@%s in %s", name, version, importer)
	}
	// Save production seeds separately so shared production/dev packages receive
	// the correct scope regardless of importer ordering.
	var production []*model.DepGraph
	connect := func(parent *model.DepGraph, deps map[string]pnpmRef, importer string, prod bool) error {
		for _, name := range pnpmKeys(deps) {
			if err := ctx.Err(); err != nil {
				return err
			}
			child, err := resolve(name, string(deps[name]), importer)
			if err != nil {
				return err
			}
			parent.AppendChild(child)
			if prod {
				production = append(production, child)
			}
		}
		return nil
	}
	for _, key := range pnpmKeys(lock.Importers) {
		i := lock.Importers[key]
		n := importers[path.Clean(key)]
		for _, deps := range []map[string]pnpmRef{i.Dependencies, i.OptionalDependencies} {
			if err := connect(n, deps, key, true); err != nil {
				return nil, err
			}
		}
		if err := connect(n, i.DevDependencies, key, false); err != nil {
			return nil, err
		}
	}
	for _, key := range pnpmKeys(entries) {
		for _, deps := range []map[string]pnpmRef{entries[key].Dependencies, entries[key].OptionalDependencies} {
			if err := connect(nodes[key], deps, ".", false); err != nil {
				return nil, err
			}
		}
	}
	seen := map[*model.DepGraph]bool{}
	for len(production) > 0 {
		n := production[0]
		production = production[1:]
		if seen[n] {
			continue
		}
		seen[n], n.Develop = true, false
		// Importer dev dependencies must not become production through a link.
		if !n.Project {
			production = append(production, n.Children...)
		}
	}
	// OpenSCA's detail exporter walks each graph node once. Represent every
	// edge with its own occurrence; repeated nodes are leaves whose outgoing
	// edges have already been emitted elsewhere. This also terminates cycles.
	copyNode := func(n *model.DepGraph) *model.DepGraph {
		return &model.DepGraph{Name: n.Name, Version: n.Version, Path: n.Path, Project: n.Project, Develop: n.Develop}
	}
	result := copyNode(root)
	type pair struct{ source, target *model.DepGraph }
	queue := []pair{{root, result}}
	seen = map[*model.DepGraph]bool{root: true}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		for _, child := range p.source.Children {
			n := copyNode(child)
			// Scope belongs to this occurrence. Keep a shared runtime package's
			// development path so DepGraph.Flush does not discard that edge.
			n.Develop = n.Develop || p.target.Develop
			p.target.AppendChild(n)
			if !seen[child] {
				seen[child] = true
				queue = append(queue, pair{child, n})
			}
		}
	}
	return result, nil
}

// scanPnpm handles independent projects and workspaces before npm fallback.
// Even an invalid lockfile claims its directory: fallback must not turn an
// unresolved pnpm project into apparently complete npm-registry output.
func scanPnpm(ctx context.Context, files map[string]*model.File, manifests map[string]*PackageJson, call model.ResCallback) map[string]bool {
	claimed := map[string]bool{}
	for _, dir := range pnpmKeys(files) {
		file := files[dir]
		root, importers, err := readPnpmLock(ctx, file, manifests)
		claimed[dir] = true
		if err != nil {
			for jsdir := range manifests {
				if strings.HasPrefix(jsdir, dir+"/") || dir == "." {
					claimed[jsdir] = true
				}
			}
			model.AddDiagnostic(ctx, fmt.Sprintf("invalid %s: %v; dependency data may be incomplete", file.Relpath(), err))
			continue
		}
		for _, importer := range importers {
			claimed[path.Join(dir, importer)] = true
		}
		call(file, root)
	}
	return claimed
}
