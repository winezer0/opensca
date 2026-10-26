package model

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"text/template"
	"time"
)

type SpdxDocument struct {
	Namespace     string         `json:"documentNamespace" xml:"documentNamespace"`
	SPDXVersion   string         `json:"spdxVersion" xml:"spdxVersion"`
	SPDXID        string         `json:"SPDXID" xml:"SPDXID"`
	DocumentName  string         `json:"name" xml:"name"`
	CreationInfo  CreationInfo   `json:"creationInfo" xml:"creationInfo"`
	Packages      []SpdxPackage  `json:"packages" xml:"packages"`
	Relationships []Relationship `json:"relationships" xml:"relationships"`
	// DocumentDescribes 指向被描述的主体（项目自身）。
	// SPDX 2.3 里它是可选的，但缺了它消费者只能看到一堆互不相关的包。
	DocumentDescribes []string `json:"documentDescribes,omitempty" xml:"documentDescribes,omitempty"`
}

type SpdxPackage struct {
	SPDXID   string `json:"SPDXID" xml:"SPDXID"`
	Name     string `json:"name" xml:"name"`
	Version  string `json:"versionInfo,omitempty" xml:"versionInfo,omitempty"`
	Supplier string `json:"supplier,omitempty" xml:"supplier,omitempty"`
	// omitempty：purl 生成不出来的包（例如语言未知）不能写成空
	// referenceLocator，那是一条非法 externalRef，严格校验器会直接拒绝。
	ExternalRefs []ExternalRef `json:"externalRefs,omitempty" xml:"externalRefs,omitempty"`
	// 从文件中解析的许可证名称不符合spdx规范
	LicenseConcluded string `json:"-" xml:"-"`
}

type CreationInfo struct {
	Created  string   `json:"created,omitempty" xml:"created,omitempty"`
	Creators []string `json:"creators,omitempty" xml:"creators,omitempty"`
}

type Relationship struct {
	SPDXElementID      string `json:"spdxElementId" xml:"spdxElementId"`
	RelatedSPDXElement string `json:"relatedSpdxElement" xml:"relatedSpdxElement"`
	RelationshipType   string `json:"relationshipType" xml:"relationshipType"`
}

type ExternalRef struct {
	ReferenceCategory string `json:"referenceCategory" xml:"referenceCategory"`
	ReferenceLocator  string `json:"referenceLocator" xml:"referenceLocator"`
	ReferenceType     string `json:"referenceType" xml:"referenceType"`
}

func NewSpdxDocument(name string) *SpdxDocument {
	return &SpdxDocument{
		SPDXVersion: "SPDX-2.3",
		SPDXID:      "SPDXRef-DOCUMENT",
		// documentNamespace 必须是全局唯一的 URI。原来是写死的 "ftp://spdx"，
		// 两份不同项目的 SPDX 会撞在同一个命名空间上，SPDX 校验器按重复处理。
		// 后缀用随机值而不是时间戳：Windows 上连续两次 time.Now() 可能拿到同一个
		// 纳秒值（时钟精度约 100ns 且会被向上取整），同一进程内连出两份文档就重了。
		Namespace:    fmt.Sprintf("https://opensca.dev/spdx/%s-%s", url.PathEscape(name), uniqueToken()),
		DocumentName: name,
		CreationInfo: CreationInfo{Created: time.Now().Format("2006-01-02T15:04:05Z"), Creators: []string{"Tool: opensca-cli"}},
	}
}

// uniqueToken 返回 16 位十六进制随机串，用作 documentNamespace 的唯一后缀。
func uniqueToken() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}
	return strconv.FormatInt(time.Now().UnixNano(), 16)
}

func (doc *SpdxDocument) AddPackage(id, vendor, name, version string, language Language, lics []string) {
	var pkg = SpdxPackage{
		SPDXID:           "SPDXRef-" + id,
		Name:             assert(name),
		Version:          assert(version),
		LicenseConcluded: assert(strings.Join(lics, " OR ")),
	}
	// 空 purl 不写 externalRef：purl 是 SBOM 消费者识别包的唯一依据，
	// 写成 referenceLocator:"" 会让整份文档变成非法 SPDX。
	if purl := Purl(vendor, name, version, language); purl != "" {
		pkg.ExternalRefs = []ExternalRef{{
			ReferenceCategory: "PACKAGE-MANAGER",
			ReferenceType:     "purl",
			ReferenceLocator:  purl,
		}}
	}
	if vendor != "" {
		pkg.Supplier = "Organization: " + vendor
	}
	doc.Packages = append(doc.Packages, pkg)
}

func (doc *SpdxDocument) AddRelation(parentId, childId string) {
	doc.Relationships = append(doc.Relationships, Relationship{
		SPDXElementID:      "SPDXRef-" + parentId,
		RelatedSPDXElement: "SPDXRef-" + childId,
		RelationshipType:   "DEPENDS_ON",
	})
}

func (doc *SpdxDocument) WriteSpdx(w io.Writer) error {
	tmpl, err := template.New("tagValue").Parse(spdxtpl)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, doc)
}

func assert(s string) string {
	if s != "" {
		return s
	}
	return "NOASSERTION"
}

const spdxtpl = `SPDXVersion: {{ .SPDXVersion }}
SPDXID: {{ .SPDXID }}
DocumentName: {{ .DocumentName }}
DocumentNamespace: {{ .Namespace }}
Created: {{ .CreationInfo.Created }}
{{ range .CreationInfo.Creators -}}
Creator: {{ . }}
{{ end }}
{{- range .Packages }}
PackageName: {{ .Name }}
SPDXID: {{ .SPDXID }}
PackageVersion: {{ .Version }}
{{- if .Supplier }}
PackageSupplier: {{ .Supplier }}
{{- end }}
{{- range .ExternalRefs	}}
ExternalRef: {{ .ReferenceCategory }} {{ .ReferenceType }} {{ .ReferenceLocator }}
{{- end }}
# PackageLicenseConcluded: {{ .LicenseConcluded }}
{{ end }}
{{- range .Relationships }}
Relationship: {{ .SPDXElementID }} {{ .RelationshipType }} {{ .RelatedSPDXElement }}
{{- end }}
{{- range .DocumentDescribes }}
Relationship: SPDXRef-DOCUMENT DESCRIBES {{ . }}
{{- end }}
`
