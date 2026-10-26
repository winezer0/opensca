package tool

import (
	"context"
	"encoding/json"
	"sort"
	"testing"

	"github.com/xmirrorsecurity/opensca-cli/v3/opensca"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/logs"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/sca"
)

func Diff(a, b *model.DepGraph) bool {
	// Compare complete node/edge sets. A tree rendering omits shared edges and
	// depends on traversal order; anonymous parser containers carry no identity.
	signature := func(root *model.DepGraph) string {
		set := map[string]bool{}
		key := func(n *model.DepGraph) string {
			if n.Name == "" {
				return "ROOT"
			}
			b, _ := json.Marshal([]any{n.Vendor, n.Name, n.Version, n.Develop})
			return string(b)
		}
		root.ForEachNode(func(_, n *model.DepGraph) bool {
			if n.Name != "" {
				set["node:"+key(n)] = true
			}
			pending := append([]*model.DepGraph(nil), n.Children...)
			seen := map[*model.DepGraph]bool{}
			for len(pending) > 0 {
				c := pending[0]
				pending = pending[1:]
				if seen[c] {
					continue
				}
				seen[c] = true
				if c.Name == "" {
					pending = append(pending, c.Children...)
				} else {
					set["edge:"+key(n)+"->"+key(c)] = true
				}
			}
			return true
		})
		lines := []string{}
		for s := range set {
			lines = append(lines, s)
		}
		sort.Strings(lines)
		b, _ := json.Marshal(lines)
		return string(b)
	}
	actual, expected := signature(a), signature(b)
	if actual != expected {
		var aa, bb []string
		_ = json.Unmarshal([]byte(actual), &aa)
		_ = json.Unmarshal([]byte(expected), &bb)
		am, bm := map[string]bool{}, map[string]bool{}
		for _, s := range aa {
			am[s] = true
		}
		for _, s := range bb {
			bm[s] = true
		}
		for _, s := range aa {
			if !bm[s] {
				logs.Debug("unexpected: ", s)
			}
		}
		for _, s := range bb {
			if !am[s] {
				logs.Debug("missing: ", s)
			}
		}
	}
	return actual != expected
}

func Dep3(vendor, name, version string, children ...*model.DepGraph) *model.DepGraph {
	root := &model.DepGraph{
		Vendor:  vendor,
		Name:    name,
		Version: version,
	}
	for _, c := range children {
		root.AppendChild(c)
	}
	return root
}

func DevDep3(vendor, name, version string, children ...*model.DepGraph) *model.DepGraph {
	root := Dep3(vendor, name, version, children...)
	root.Develop = true
	return root
}

func Dep(name, version string, children ...*model.DepGraph) *model.DepGraph {
	return Dep3("", name, version, children...)
}

func DevDep(name, version string, children ...*model.DepGraph) *model.DepGraph {
	return DevDep3("", name, version, children...)
}

type TaskCase struct {
	Path   string
	Result *model.DepGraph
}

func RunTaskCase(t *testing.T, sca ...sca.Sca) func(cases []TaskCase) {
	return func(cases []TaskCase) {
		for _, c := range cases {
			t.Run(c.Path, func(t *testing.T) {
				r := opensca.RunTask(context.Background(), &opensca.TaskArg{
					DataOrigin: c.Path,
					Sca:        sca,
				})
				if r.Error != nil {
					t.Fatal(r.Error)
				}
				result := &model.DepGraph{}
				for _, dep := range r.Deps {
					result.AppendChild(dep)
				}
				if Diff(result, c.Result) {
					logs.Debugf("%s\nres:\n%sstd:\n%s", c.Path, result.Tree(false, true), c.Result.Tree(false, true))
					t.Error("dependency graph differs from fixture")
				}
			})
		}
	}
}
