package format

import (
	"encoding/json"
	"encoding/xml"
	"io"

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

	report.DepDetailGraph.ForEach(func(n *detail.DepDetailGraph) bool {

		if n.Name == "" {
			return true
		}

		// 项目自身作为被描述的主体。SPDX 2.3 的 documentDescribes 就是干这个的：
		// 没有它，消费者看到的是 67 个互不相关的包，不知道哪一个是根。
		if n == report.DepDetailGraph || n.Project {
			doc.DocumentDescribes = append(doc.DocumentDescribes, "SPDXRef-"+n.ID)
		}

		lics := []string{}
		for _, lic := range n.Licenses {
			lics = append(lics, lic.ShortName)
		}
		doc.AddPackage(n.ID, n.Vendor, n.Name, n.Version, model.Language(n.Language), lics)

		for _, c := range n.Children {
			if c.Name == "" {
				continue
			}
			doc.AddRelation(n.ID, c.ID)
		}

		return true
	})

	return doc
}
