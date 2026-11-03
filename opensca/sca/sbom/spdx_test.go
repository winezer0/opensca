package sbom

import (
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"testing"

	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
)

func TestParseSpdxDependencyRelationships(t *testing.T) {
	doc := model.SpdxDocument{
		SPDXVersion: "SPDX-2.3",
		Packages: []model.SpdxPackage{
			{SPDXID: "SPDXRef-root", Name: "root"},
			{SPDXID: "SPDXRef-direct", Name: "direct"},
			{SPDXID: "SPDXRef-indirect", Name: "indirect"},
		},
		Relationships: []model.Relationship{
			{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: "SPDXRef-root"},
			{SPDXElementID: "SPDXRef-root", RelationshipType: "DEPENDS_ON", RelatedSPDXElement: "SPDXRef-direct"},
			{SPDXElementID: "SPDXRef-indirect", RelationshipType: "DEPENDENCY_OF", RelatedSPDXElement: "SPDXRef-direct"},
			{SPDXElementID: "SPDXRef-direct", RelationshipType: "CONTAINS", RelatedSPDXElement: "SPDXRef-missing"},
		},
	}
	jsonData, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	xmlData, err := xml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	tagValue := []byte("" +
		"SPDXVersion: SPDX-2.3\n" +
		"PackageName: root\nSPDXID: SPDXRef-root\n" +
		"PackageName: direct\nSPDXID: SPDXRef-direct\n" +
		"PackageName: indirect\nSPDXID: SPDXRef-indirect\n" +
		"Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-root\n" +
		"Relationship: SPDXRef-root DEPENDS_ON SPDXRef-direct\n" +
		"Relationship: SPDXRef-indirect DEPENDENCY_OF SPDXRef-direct\n" +
		"Relationship: SPDXRef-direct CONTAINS SPDXRef-missing\n")

	cases := []struct {
		name  string
		data  []byte
		parse func(*model.File) *model.DepGraph
	}{
		{name: "tag-value", data: tagValue, parse: ParseSpdx},
		{name: "json", data: jsonData, parse: ParseSpdxJson},
		{name: "xml", data: xmlData, parse: ParseSpdxXml},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input.spdx")
			if err := os.WriteFile(path, tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			root := tc.parse(model.NewFile(path, "input.spdx"))
			assertSpdxDependencyGraph(t, root)
		})
	}
}

func assertSpdxDependencyGraph(t *testing.T, root *model.DepGraph) {
	t.Helper()
	rootPackage := findSpdxPackage(root, "root")
	direct := findSpdxPackage(root, "direct")
	indirect := findSpdxPackage(root, "indirect")
	if rootPackage == nil || direct == nil || indirect == nil {
		t.Fatalf("parsed packages missing: root=%v direct=%v indirect=%v", rootPackage, direct, indirect)
	}
	if !containsSpdxChild(rootPackage, direct) {
		t.Fatal("root-to-direct dependency relationship missing")
	}
	if !containsSpdxChild(direct, indirect) {
		t.Fatal("direct-to-indirect dependency relationship missing")
	}
}

func findSpdxPackage(root *model.DepGraph, name string) *model.DepGraph {
	queue := []*model.DepGraph{root}
	visited := map[*model.DepGraph]bool{}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current == nil || visited[current] {
			continue
		}
		visited[current] = true
		if current.Name == name {
			return current
		}
		queue = append(queue, current.Children...)
	}
	return nil
}

func containsSpdxChild(parent, child *model.DepGraph) bool {
	for _, candidate := range parent.Children {
		if candidate == child {
			return true
		}
	}
	return false
}
