package format

import (
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/xmirrorsecurity/opensca-cli/v3/cmd/detail"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
)

func TestSpdxDocPreservesDirectAndIndirectDependencies(t *testing.T) {
	root := component("root")
	root.ID = "root"
	root.Project = true
	direct := component("direct")
	direct.ID = "direct"
	indirect := component("indirect")
	indirect.ID = "indirect"
	anonymous := &detail.DepDetailGraph{Children: []*detail.DepDetailGraph{direct}}
	root.Children = []*detail.DepDetailGraph{anonymous}
	direct.Children = []*detail.DepDetailGraph{indirect}

	doc := spdxDoc(Report{DepDetailGraph: root})
	assertSpdxGraph(t, doc)

	var tagValue strings.Builder
	if err := doc.WriteSpdx(&tagValue); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tagValue.String(), "Relationship: SPDXRef-root DEPENDS_ON SPDXRef-direct") ||
		!strings.Contains(tagValue.String(), "Relationship: SPDXRef-direct DEPENDS_ON SPDXRef-indirect") {
		t.Fatalf("tag-value SPDX lost dependency relationships:\n%s", tagValue.String())
	}

	jsonData, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var jsonDoc model.SpdxDocument
	if err := json.Unmarshal(jsonData, &jsonDoc); err != nil {
		t.Fatal(err)
	}
	assertSpdxGraph(t, &jsonDoc)

	xmlData, err := xml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var xmlDoc model.SpdxDocument
	if err := xml.Unmarshal(xmlData, &xmlDoc); err != nil {
		t.Fatal(err)
	}
	assertSpdxGraph(t, &xmlDoc)
}

func TestSpdxDocNamesAnonymousProjectRoot(t *testing.T) {
	root := &detail.DepDetailGraph{ID: "root"}
	direct := component("direct")
	direct.ID = "direct"
	root.Children = []*detail.DepDetailGraph{direct}

	doc := spdxDoc(Report{TaskInfo: TaskInfo{AppName: "demo-app"}, DepDetailGraph: root})
	if len(doc.Packages) != 2 || doc.Packages[0].Name != "demo-app" {
		t.Fatalf("anonymous project root was not represented as a package: %+v", doc.Packages)
	}
	if len(doc.DocumentDescribes) != 1 || doc.DocumentDescribes[0] != "SPDXRef-root" {
		t.Fatalf("document does not describe its project root: %+v", doc.DocumentDescribes)
	}
	if !hasSpdxRelation(doc, "root", "direct") {
		t.Fatal("anonymous project root lost its direct dependency")
	}
}

func TestSpdxDocUsesKnownDirectnessForFlatGraph(t *testing.T) {
	root := component("root")
	root.ID = "root"
	root.Project = true
	direct := component("direct")
	direct.ID, direct.Direct, direct.DirectKnown = "direct", true, true
	indirect := component("indirect")
	indirect.ID, indirect.DirectKnown = "indirect", true
	root.Children = []*detail.DepDetailGraph{direct, indirect}

	doc := spdxDoc(Report{DepDetailGraph: root})
	if !hasSpdxRelation(doc, "root", "direct") {
		t.Fatal("root-to-direct relationship missing")
	}
	if hasSpdxRelation(doc, "root", "indirect") {
		t.Fatal("known indirect component was emitted as a direct dependency")
	}
	if len(doc.Packages) != 3 {
		t.Fatalf("got %d packages, want project, direct, and indirect", len(doc.Packages))
	}
}

func assertSpdxGraph(t *testing.T, doc *model.SpdxDocument) {
	t.Helper()
	if len(doc.DocumentDescribes) != 1 || doc.DocumentDescribes[0] != "SPDXRef-root" {
		t.Fatalf("document root not described: %+v", doc.DocumentDescribes)
	}
	if !hasSpdxRelation(doc, "root", "direct") {
		t.Fatal("root-to-direct relationship missing")
	}
	if !hasSpdxRelation(doc, "direct", "indirect") {
		t.Fatal("direct-to-indirect relationship missing")
	}
	if len(doc.Packages) != 3 {
		t.Fatalf("got %d packages, want root, direct and indirect", len(doc.Packages))
	}
}

func hasSpdxRelation(doc *model.SpdxDocument, parent, child string) bool {
	for _, relation := range doc.Relationships {
		if relation.SPDXElementID == "SPDXRef-"+parent &&
			relation.RelationshipType == "DEPENDS_ON" &&
			relation.RelatedSPDXElement == "SPDXRef-"+child {
			return true
		}
	}
	return false
}
