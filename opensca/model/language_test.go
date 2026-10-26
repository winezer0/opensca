package model

import "testing"

func TestPurlIdentity(t *testing.T) {
	for _, tc := range []struct {
		vendor, name, version string
		language              Language
		want                  string
	}{
		{"org.example", "a", "1.0", Lan_Java, "pkg:maven/org.example/a@1.0"},
		{"", "@scope/a", "1.0", Lan_JavaScript, "pkg:npm/%40scope/a@1.0"},
		{"", "github.com/a/b", "v1.0.0", Lan_Golang, "pkg:golang/github.com/a/b@v1.0.0"},
		{"", "Newtonsoft.Json", "13.0.1", Lan_DotNet, "pkg:nuget/Newtonsoft.Json@13.0.1"},
		{"", "a", "1", Lan_None, ""}, {"", "a", "1", Lan_Java, ""}, {"g", "a", "${v}", Lan_Java, ""},
	} {
		if got := Purl(tc.vendor, tc.name, tc.version, tc.language); got != tc.want {
			t.Errorf("Purl(%+v) = %q", tc, got)
		}
	}
	q := QualifiedPurl("g", "a", "1", Lan_Java, "test-jar", "tests")
	if q != "pkg:maven/g/a@1?classifier=tests&type=test-jar" {
		t.Fatal(q)
	}
	v, n, ver, lan := ParsePurl(q)
	if v != "g" || n != "a" || ver != "1" || lan != Lan_Java {
		t.Fatal(v, n, ver, lan)
	}
	if CanonicalPurl("pkg:/a@1") != "" {
		t.Fatal("accepted invalid type")
	}
	_, name, version, language := ParsePurl("pkg:nuget/Newtonsoft.Json@13.0.1")
	if name != "Newtonsoft.Json" || version != "13.0.1" || language != Lan_DotNet {
		t.Fatal(name, version, language)
	}
}
