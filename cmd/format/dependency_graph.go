package format

import "github.com/xmirrorsecurity/opensca-cli/v3/cmd/detail"

type dependencyGraphEdge struct {
	Parent *detail.DepDetailGraph
	Child  *detail.DepDetailGraph
}

func dependencyGraphNodes(root *detail.DepDetailGraph) []*detail.DepDetailGraph {
	if root == nil {
		return nil
	}

	var nodes []*detail.DepDetailGraph
	visited := map[*detail.DepDetailGraph]bool{}
	queue := []*detail.DepDetailGraph{root}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		if node == nil || visited[node] {
			continue
		}
		visited[node] = true
		nodes = append(nodes, node)
		queue = append(queue, node.Children...)
	}
	return nodes
}

// dependencyGraphEdges projects the detail tree onto named SBOM components.
// Unnamed nodes are structural, so edges pass through them to the nearest
// named descendants. The root remains a parent even when it has no name.
func dependencyGraphEdges(root *detail.DepDetailGraph) []dependencyGraphEdge {
	if root == nil {
		return nil
	}

	var edges []dependencyGraphEdge
	seenEdges := map[dependencyGraphEdge]bool{}
	for _, parent := range dependencyGraphNodes(root) {
		if parent != root && parent.Name == "" {
			continue
		}

		pending := append([]*detail.DepDetailGraph(nil), parent.Children...)
		seenAnonymous := map[*detail.DepDetailGraph]bool{}
		for len(pending) > 0 {
			child := pending[0]
			pending = pending[1:]
			if child == nil {
				continue
			}
			if child.Name == "" {
				if !seenAnonymous[child] {
					seenAnonymous[child] = true
					pending = append(pending, child.Children...)
				}
				continue
			}
			if child == parent {
				continue
			}
			// Flat manifests can identify directness without identifying the
			// exact parent of transitive modules. Do not emit those modules as
			// direct project dependencies.
			if parent == root && child.DirectKnown && !child.Direct {
				continue
			}
			edge := dependencyGraphEdge{Parent: parent, Child: child}
			if !seenEdges[edge] {
				seenEdges[edge] = true
				edges = append(edges, edge)
			}
		}
	}

	return edges
}
