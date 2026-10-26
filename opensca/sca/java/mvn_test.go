package java

import (
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
	"strings"
	"testing"
)

func TestMavenOutputFormats(t *testing.T) {
	for _, tail := range []string{"", "[INFO] ------------------------------------------------------------------------\n", "[INFO] --- dependency:3.8.1:tree (default-cli) @ other ---\n[INFO] g:other:jar:1\n"} {
		out := "\x1b[0m[INFO] --- dependency:3.8.1:tree (default-cli) @ app ---\n[INFO] g:app:jar:1\n[INFO] +- g:lib:jar:1:compile\n[INFO] \\- g:lib:jar:tests:1:test\n" + tail
		r := parseMvnOutput([]byte(out), "app", "pom.xml")
		if r == nil || !r.Project || r.Path != "pom.xml" || len(r.Children) != 2 {
			t.Fatalf("unexpected root: %+v", r)
		}
		for _, n := range r.Children {
			if n.Language != model.Lan_Java || n.Version != "1" {
				t.Fatalf("invalid identity: %+v", n)
			}
		}
		if r.Children[0] == r.Children[1] || r.Children[1].Classifier != "tests" || !r.Children[1].Develop {
			t.Fatal("classifier/scope lost")
		}
	}
}

func TestParentIdentityProperties(t *testing.T) {
	p := ReadPom(strings.NewReader(`<project><groupId>g</groupId><artifactId>parent</artifactId><version>${revision}</version><properties><revision>1</revision></properties></project>`))
	if !matchesParent(p, PomDependency{GroupId: "g", ArtifactId: "parent", Version: "1"}) {
		t.Fatal("resolved parent version rejected")
	}
	if matchesParent(p, PomDependency{GroupId: "g", ArtifactId: "parent", Version: "2"}) {
		t.Fatal("different concrete version accepted")
	}
	if matchesParent(p, PomDependency{GroupId: "other", ArtifactId: "parent", Version: "${revision}"}) {
		t.Fatal("different group accepted")
	}
}
