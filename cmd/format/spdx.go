package format

import (
	"encoding/json"
	"encoding/xml"
	"io"
	"strings"

	"github.com/xmirrorsecurity/opensca-cli/v3/cmd/detail"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
)

func Spdx(report Report, out string) {
	outWrite(out, func(w io.Writer) error {
		return spdxDoc(report).WriteSpdx(w)
	})
}

func SpdxJson(report Report, out string) {
	outWrite(out, func(w io.Writer) error {
		return json.NewEncoder(w).Encode(spdxDoc(report))
	})
}

func SpdxXml(report Report, out string) {
	outWrite(out, func(w io.Writer) error {
		return xml.NewEncoder(w).Encode(spdxDoc(report))
	})
}

func spdxDoc(report Report) *model.SpdxDocument {

	doc := model.NewSpdxDocument(report.TaskInfo.AppName)
	root := report.DepDetailGraph
	if root == nil {
		return doc
	}

	packageIDs := map[*detail.DepDetailGraph]string{}
	usedIDs := map[string]bool{}
	described := map[string]bool{}
	for _, n := range dependencyGraphNodes(root) {
		if n == nil || (n != root && n.Name == "") {
			continue
		}

		id := strings.TrimPrefix(strings.TrimSpace(n.ID), "SPDXRef-")
		if id == "" || usedIDs[id] {
			id = detail.ID()
		}
		usedIDs[id] = true
		packageIDs[n] = id

		name := n.Name
		if n == root && name == "" {
			name = report.TaskInfo.AppName
			if name == "" {
				name = "scanned-project"
			}
		}

		if n == root || n.Project {
			ref := "SPDXRef-" + id
			if !described[ref] {
				doc.DocumentDescribes = append(doc.DocumentDescribes, ref)
				described[ref] = true
			}
		}

		lics := make([]string, 0, len(n.Licenses))
		for _, lic := range n.Licenses {
			lics = append(lics, lic.ShortName)
		}
		doc.AddPackage(id, n.Vendor, name, n.Version, model.Language(n.Language), lics)
	}

	for _, edge := range dependencyGraphEdges(root) {
		parentID, parentOK := packageIDs[edge.Parent]
		childID, childOK := packageIDs[edge.Child]
		if parentOK && childOK {
			doc.AddRelation(parentID, childID)
		}
	}

	return doc
}
