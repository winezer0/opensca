package nuget

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
)

type assetsLibrary struct {
	Type           string `json:"type"`
	Path           string `json:"path"`
	MSBuildProject string `json:"msbuildProject"`
}

type assetsTargetPackage struct {
	Type         string            `json:"type"`
	Dependencies map[string]string `json:"dependencies"`
}

type assetsFramework struct {
	TargetAlias  string `json:"targetAlias"`
	Dependencies map[string]struct {
		Target string `json:"target"`
	} `json:"dependencies"`
}

type assetsRestoreFramework struct {
	TargetAlias       string `json:"targetAlias"`
	ProjectReferences map[string]struct {
		ProjectPath string `json:"projectPath"`
	} `json:"projectReferences"`
}

type assetsDocument struct {
	Version   int                                        `json:"version"`
	Targets   map[string]map[string]*assetsTargetPackage `json:"targets"`
	Libraries map[string]*assetsLibrary                  `json:"libraries"`
	Project   struct {
		Version string `json:"version"`
		Restore struct {
			ProjectName string                            `json:"projectName"`
			ProjectPath string                            `json:"projectPath"`
			Frameworks  map[string]assetsRestoreFramework `json:"frameworks"`
		} `json:"restore"`
		Frameworks map[string]assetsFramework `json:"frameworks"`
	} `json:"project"`
	Logs []struct {
		Level, Code, Message string
	} `json:"logs"`
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// SDK 8 assets can use long target monikers while project metadata uses TFMs.
// SDK 10 uses short TFMs in both places. RID suffixes are handled by callers.
func frameworkKey(name string) string {
	name = strings.ToLower(name)
	kind, version, long := strings.Cut(name, ",version=v")
	if !long {
		return name
	}
	switch kind {
	case ".netstandard":
		return "netstandard" + version
	case ".netframework":
		return "net" + strings.ReplaceAll(version, ".", "")
	case ".netcoreapp":
		major, _ := strconv.Atoi(strings.SplitN(version, ".", 2)[0])
		if major >= 5 {
			return "net" + version
		}
		return "netcoreapp" + version
	}
	return name
}

func readAssets(r io.Reader, file *model.File, project *model.File) (*model.DepGraph, error) {
	const maxSize = 64 << 20
	data, err := io.ReadAll(io.LimitReader(r, maxSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSize {
		return nil, fmt.Errorf("project.assets.json exceeds 64 MiB")
	}
	var doc assetsDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if (doc.Version != 3 && doc.Version != 4) || len(doc.Targets) == 0 || len(doc.Project.Frameworks) == 0 {
		return nil, fmt.Errorf("invalid assets schema/version %d or missing targets/frameworks", doc.Version)
	}
	for _, log := range doc.Logs {
		if strings.EqualFold(log.Level, "Error") {
			return nil, fmt.Errorf("restore error %s in project.assets.json: %.300s", log.Code, log.Message)
		}
	}
	if project != nil && doc.Project.Restore.ProjectPath != "" && !strings.EqualFold(filepath.Base(fromMSBuildPath(doc.Project.Restore.ProjectPath)), filepath.Base(project.Abspath())) {
		return nil, fmt.Errorf("assets belong to another project: %s", doc.Project.Restore.ProjectPath)
	}
	root := &model.DepGraph{Name: doc.Project.Restore.ProjectName, Version: doc.Project.Version, Path: file.Relpath(), Project: true}
	if project != nil {
		root.Path = project.Relpath()
		if root.Name == "" {
			root.Name = strings.TrimSuffix(filepath.Base(project.Abspath()), filepath.Ext(project.Abspath()))
		}
	}
	for _, target := range sortedKeys(doc.Targets) {
		if err := appendAssetsTarget(root, &doc, target, file.Relpath()); err != nil {
			return nil, fmt.Errorf("target %s: %w", target, err)
		}
	}
	return root, nil
}

func appendAssetsTarget(root *model.DepGraph, doc *assetsDocument, target, source string) error {
	packages := doc.Targets[target]
	if packages == nil {
		return fmt.Errorf("null target")
	}
	nodes, byName := map[string]*model.DepGraph{}, map[string]*model.DepGraph{}
	projectPaths := map[*model.DepGraph]string{}
	for _, key := range sortedKeys(packages) {
		pkg, lib := packages[key], doc.Libraries[key]
		if pkg == nil || lib == nil || pkg.Type != lib.Type || (pkg.Type != "package" && pkg.Type != "project") {
			return fmt.Errorf("invalid or missing library metadata for %q", key)
		}
		name, version, ok := strings.Cut(key, "/")
		if !ok || name == "" || (pkg.Type == "package" && !packageID.MatchString(name)) || !packageVersion.MatchString(version) {
			return fmt.Errorf("invalid resolved identity %q", key)
		}
		n := &model.DepGraph{Name: name, Version: version, Project: pkg.Type == "project", Language: model.Lan_DotNet,
			Path: source + "/" + target + "/" + key}
		lower := strings.ToLower(name)
		if byName[lower] != nil {
			return fmt.Errorf("ambiguous resolved package %q", name)
		}
		nodes[key], byName[lower] = n, n
		if n.Project {
			projectPaths[n] = lib.MSBuildProject
			if projectPaths[n] == "" {
				projectPaths[n] = lib.Path
			}
		}
	}
	for _, key := range sortedKeys(packages) {
		for _, name := range sortedKeys(packages[key].Dependencies) {
			child := byName[strings.ToLower(name)]
			if child == nil {
				return fmt.Errorf("unresolved dependency %q in %q", name, key)
			}
			nodes[key].AppendChild(child)
		}
	}
	base := strings.SplitN(target, "/", 2)[0]
	framework, found := doc.Project.Frameworks[base]
	if !found {
		for _, key := range sortedKeys(doc.Project.Frameworks) {
			if frameworkKey(key) == frameworkKey(base) || frameworkKey(doc.Project.Frameworks[key].TargetAlias) == frameworkKey(base) {
				framework, found = doc.Project.Frameworks[key], true
				break
			}
		}
	}
	if !found {
		return fmt.Errorf("missing project framework metadata")
	}
	var direct []*model.DepGraph
	for _, name := range sortedKeys(framework.Dependencies) {
		dep := framework.Dependencies[name]
		if dep.Target != "" && !strings.EqualFold(dep.Target, "Package") && !strings.EqualFold(dep.Target, "Project") {
			return fmt.Errorf("unsupported dependency target %q for %s", dep.Target, name)
		}
		n := byName[strings.ToLower(name)]
		if n == nil {
			return fmt.Errorf("unresolved direct dependency %q", name)
		}
		direct = append(direct, n)
	}
	restoreFrameworkFound := false
	for _, key := range sortedKeys(doc.Project.Restore.Frameworks) {
		f := doc.Project.Restore.Frameworks[key]
		if frameworkKey(key) != frameworkKey(base) && frameworkKey(f.TargetAlias) != frameworkKey(base) && key != framework.TargetAlias {
			continue
		}
		restoreFrameworkFound = true
		for _, ref := range sortedKeys(f.ProjectReferences) {
			projectPath := f.ProjectReferences[ref].ProjectPath
			if projectPath == "" {
				projectPath = ref
			}
			var matched *model.DepGraph
			for _, pkgKey := range sortedKeys(nodes) {
				n := nodes[pkgKey]
				if !n.Project || projectPaths[n] == "" {
					continue
				}
				libPath := fromMSBuildPath(projectPaths[n])
				if !filepath.IsAbs(libPath) {
					libPath = filepath.Join(filepath.Dir(fromMSBuildPath(doc.Project.Restore.ProjectPath)), libPath)
				}
				if strings.EqualFold(filepath.Clean(libPath), filepath.Clean(fromMSBuildPath(projectPath))) {
					matched = n
					break
				}
			}
			if matched == nil {
				return fmt.Errorf("unresolved project reference %q", projectPath)
			}
			direct = append(direct, matched)
		}
	}
	if len(projectPaths) > 0 && !restoreFrameworkFound {
		return fmt.Errorf("missing restore framework/project-reference metadata")
	}
	// Emit occurrences rather than shared pointers: the detail exporter visits
	// each pointer once. Repeated leaves preserve shared and cyclic edges.
	seen := map[*model.DepGraph]bool{}
	type pair struct{ from, to *model.DepGraph }
	var queue []pair
	appendNode := func(parent, node *model.DepGraph, direct bool) {
		copy := &model.DepGraph{Name: node.Name, Version: node.Version, Project: node.Project, Language: node.Language, Path: node.Path, Direct: direct}
		parent.AppendChild(copy)
		if !seen[node] {
			seen[node] = true
			queue = append(queue, pair{node, copy})
		}
	}
	for _, n := range direct {
		appendNode(root, n, true)
	}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		for _, child := range p.from.Children {
			appendNode(p.to, child, false)
		}
	}
	return nil
}

func fromMSBuildPath(s string) string { return filepath.FromSlash(strings.ReplaceAll(s, `\`, "/")) }
