package model

import (
	"strings"

	packageurl "github.com/package-url/packageurl-go"
)

type Language string

const (
	Lan_None       Language = ""
	Lan_Java       Language = "Java"
	Lan_JavaScript Language = "JavaScript"
	Lan_Php        Language = "Php"
	Lan_Ruby       Language = "Ruby"
	Lan_Golang     Language = "Golang"
	Lan_Rust       Language = "Rust"
	Lan_Erlang     Language = "Erlang"
	Lan_Python     Language = "Python"
	Lan_DotNet     Language = "DotNet"
)

var purlRmap = map[string]Language{
	"cargo":    Lan_Rust,
	"composer": Lan_Php,
	"gem":      Lan_Ruby,
	"golang":   Lan_Golang,
	"maven":    Lan_Java,
	"npm":      Lan_JavaScript,
	"pypi":     Lan_Python,
	"hex":      Lan_Erlang,
	"nuget":    Lan_DotNet,
}

var purlMap = map[Language]string{}

func init() {
	for k, v := range purlRmap {
		purlMap[v] = k
	}
}

func Purl(vendor, name, version string, language Language) string {
	return QualifiedPurl(vendor, name, version, language, "", "")
}

// QualifiedPurl never invents an ecosystem or an unresolved version.
func QualifiedPurl(vendor, name, version string, language Language, typ, classifier string) string {
	pkg := purlMap[language]
	if pkg == "" || name == "" || version == "" || strings.ContainsAny(version, "${}[](),*^~<>= ") {
		return ""
	}
	if language != Lan_Java && vendor == "" {
		if i := strings.LastIndex(name, "/"); i >= 0 {
			vendor, name = name[:i], name[i+1:]
		}
	}
	if language == Lan_Java && vendor == "" {
		return ""
	}
	q := map[string]string{}
	if typ != "" && typ != "jar" {
		q["type"] = typ
	}
	if classifier != "" {
		q["classifier"] = classifier
	}
	p := packageurl.NewPackageURL(pkg, vendor, name, version, packageurl.QualifiersFromMap(q), "")
	return CanonicalPurl(p.ToString())
}

// CanonicalPurl validates a complete identity and requires a concrete version.
func CanonicalPurl(raw string) string {
	p, err := packageurl.FromString(raw)
	if err != nil || p.Type == "" || p.Name == "" || p.Version == "" || strings.ContainsAny(p.Version, "${}[](),*^~<>= ") {
		return ""
	}
	if p.Type == "maven" && p.Namespace == "" {
		return ""
	}
	return p.ToString()
}

func ParsePurl(purl string) (vendor, name, version string, language Language) {
	if CanonicalPurl(purl) == "" {
		return
	}
	p, err := packageurl.FromString(purl)
	if err != nil {
		return
	}
	language = purlRmap[p.Type]
	name, version = p.Name, p.Version
	if language == Lan_Java {
		vendor = p.Namespace
	} else if p.Namespace != "" {
		name = p.Namespace + "/" + name
	}
	return
}
