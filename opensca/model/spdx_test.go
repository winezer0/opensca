package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAddPackageWritesPurl(t *testing.T) {
	doc := NewSpdxDocument("demo")
	doc.AddPackage("a1", "git.imgo.tv/bs", "gomod-utils", "v1.0.30-beta3", Lan_Golang, nil)

	if len(doc.Packages) != 1 {
		t.Fatalf("got %d packages, want 1", len(doc.Packages))
	}
	refs := doc.Packages[0].ExternalRefs
	if len(refs) != 1 || refs[0].ReferenceType != "purl" {
		t.Fatalf("expected one purl reference, got %+v", refs)
	}
	if refs[0].ReferenceLocator != "pkg:golang/git.imgo.tv/bs/gomod-utils@v1.0.30-beta3" {
		t.Fatalf("unexpected purl: %q", refs[0].ReferenceLocator)
	}
}

// 项目自身通常没有 version / vendor。以前这里会写出一条
// referenceLocator 为空的 externalRef，整份文档因此不合法。
func TestAddPackageOmitsEmptyPurl(t *testing.T) {
	doc := NewSpdxDocument("demo")
	doc.AddPackage("root", "", "inott-epg/inott-epg-go", "", Language(""), nil)

	if len(doc.Packages) != 1 {
		t.Fatalf("got %d packages, want 1", len(doc.Packages))
	}
	pkg := doc.Packages[0]
	if len(pkg.ExternalRefs) != 0 {
		t.Fatalf("empty purl must not produce an externalRef, got %+v", pkg.ExternalRefs)
	}
	if pkg.Supplier != "" {
		t.Fatalf("empty vendor must not produce a supplier, got %q", pkg.Supplier)
	}

	// 序列化后也不能出现空字符串的 locator
	data, err := json.Marshal(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"externalRefs"`) {
		t.Fatalf("empty externalRefs must be omitted from JSON: %s", data)
	}
}

func TestDocumentNamespaceIsUnique(t *testing.T) {
	a := NewSpdxDocument("demo")
	b := NewSpdxDocument("demo")
	if a.Namespace == b.Namespace {
		t.Fatalf("documentNamespace must differ per document, both are %q", a.Namespace)
	}
	if !strings.HasPrefix(a.Namespace, "https://") {
		t.Fatalf("documentNamespace must be a URI, got %q", a.Namespace)
	}
	if a.SPDXVersion != "SPDX-2.3" {
		t.Fatalf("spdxVersion = %q, want SPDX-2.3", a.SPDXVersion)
	}
}

func TestTagValueTemplateWritesDocumentDescribes(t *testing.T) {
	doc := NewSpdxDocument("demo")
	doc.AddPackage("root", "", "demo", "1.0.0", Lan_Golang, nil)
	doc.DocumentDescribes = []string{"SPDXRef-root"}

	var sb strings.Builder
	if err := doc.WriteSpdx(&sb); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	// tag-value 里没有 DocumentDescribes 这个 tag，只能写成 DESCRIBES 关系。
	// 写成 "DocumentDescribes: xxx" 会让 osv-scanner 直接报
	// "received unknown tag DocumentDescribes in CreationInfo section"。
	if !strings.Contains(out, "Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-root") {
		t.Fatalf("tag-value output missing DESCRIBES relationship:\n%s", out)
	}
	if strings.Contains(out, "DocumentDescribes:") {
		t.Fatalf("tag-value output must not emit a DocumentDescribes tag:\n%s", out)
	}
	if !strings.Contains(out, "SPDXVersion: SPDX-2.3") {
		t.Fatalf("tag-value output missing version:\n%s", out)
	}
}
