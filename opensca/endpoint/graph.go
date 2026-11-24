// Package endpoint expands unresolved declarations before PURL generation.
package endpoint

import (
	"context"
	"fmt"

	"github.com/xmirrorsecurity/opensca-cli/v3/internal/versionaudit"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
)

// Expand preserves graph identity and expands range nodes into audit candidates.
// Candidates have no inferred transitive edges: a declaration is insufficient
// evidence for the dependency graph of either selected release.
func Expand(ctx context.Context, root *model.DepGraph, directory versionaudit.Directory) []*model.DepGraph {
	if root == nil {
		return nil
	}
	variants := map[*model.DepGraph][]*model.DepGraph{}
	var original []*model.DepGraph
	queue := []*model.DepGraph{root}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		if n == nil {
			continue
		}
		if _, ok := variants[n]; ok {
			continue
		}
		variants[n] = candidates(ctx, n, directory)
		original = append(original, n)
		queue = append(queue, n.Children...)
	}
	for _, n := range original {
		for _, candidate := range variants[n] {
			if candidate.VersionSource == "unresolved" || candidate.VersionSource == string(versionaudit.PublishedEndpoint) || candidate.VersionSource == string(versionaudit.BoundaryFallback) {
				continue
			}
			connect(candidate, n.Children, variants)
		}
	}
	return variants[root]
}

// candidates resolves one declaration while retaining manifest evidence.
func candidates(ctx context.Context, n *model.DepGraph, directory versionaudit.Directory) []*model.DepGraph {
	base := clone(n)
	if n.Project || n.Name == "" {
		return []*model.DepGraph{base}
	}
	declaration := n.DeclaredVersion
	if declaration == "" && versionaudit.IsConstraint(n.Version) {
		declaration = n.Version
	}
	if declaration == "" {
		if base.VersionSource == "" {
			base.VersionSource = string(versionaudit.Actual)
			if base.Version == "" {
				base.VersionSource = "unresolved"
			}
		}
		return []*model.DepGraph{base}
	}
	name := n.Name
	if n.Language == model.Lan_Java {
		name = n.Vendor + ":" + n.Name
	}
	result, err := versionaudit.ResolveDeclaration(ctx, versionaudit.Declaration{Ecosystem: string(n.Language), Name: name, Constraint: declaration}, directory)
	if err != nil || len(result.Candidates) == 0 {
		base.Version, base.PackageURL = "", ""
		base.VersionSource = "unresolved"
		base.Issues = append(base.Issues, fmt.Sprintf("component has no valid PURL: %s@", name))
		return []*model.DepGraph{base}
	}
	var nodes []*model.DepGraph
	for _, item := range result.Candidates {
		node := clone(n)
		node.Version, node.VersionSource, node.PackageURL = item.Version, string(item.Source), ""
		nodes = append(nodes, node)
	}
	return nodes
}

// clone copies metadata without copying graph indexes or edges.
func clone(n *model.DepGraph) *model.DepGraph {
	return &model.DepGraph{PackageURL: n.PackageURL, PackageType: n.PackageType, Classifier: n.Classifier, Project: n.Project,
		DeclaredVersion: n.DeclaredVersion, VersionSource: n.VersionSource, Vendor: n.Vendor, Name: n.Name, Version: n.Version,
		Language: n.Language, Path: n.Path, Licenses: append([]string(nil), n.Licenses...), Issues: append([]string(nil), n.Issues...),
		Develop: n.Develop, Direct: n.Direct, DirectKnown: n.DirectKnown}
}

// connect binds candidate nodes using the original graph's verified edges.
func connect(parent *model.DepGraph, children []*model.DepGraph, variants map[*model.DepGraph][]*model.DepGraph) {
	for _, child := range children {
		for _, target := range variants[child] {
			parent.AppendChild(target)
		}
	}
}
