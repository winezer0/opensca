package java

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xmirrorsecurity/opensca-cli/v3/cmd/config"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
)

func writePom(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
}
func javaConfig(t *testing.T) {
	t.Helper()
	before := *config.Conf()
	t.Cleanup(func() { *config.Conf() = before })
	config.Conf().Offline = true
	config.Conf().Java = config.JavaConfig{}
	config.Conf().CacheDir = t.TempDir()
}
func TestLocalRepositorySettingsFallback(t *testing.T) {
	javaConfig(t)
	settings := filepath.Join(t.TempDir(), "settings.xml")
	writePom(t, settings, "<settings/>")
	config.Conf().Java.Settings = settings
	t.Setenv("MAVEN_REPO_LOCAL", "")
	got, err := localRepository()
	home, _ := os.UserHomeDir()
	if err != nil || got != filepath.Join(home, ".m2", "repository") {
		t.Fatal(got, err)
	}
	repo := t.TempDir()
	writePom(t, settings, "<settings><localRepository>"+repo+"</localRepository></settings>")
	got, err = localRepository()
	if err != nil || got != repo {
		t.Fatal(got, err)
	}
	config.Conf().Java.LocalRepository = t.TempDir()
	if got, _ = localRepository(); got != config.Conf().Java.LocalRepository {
		t.Fatal(got)
	}
}
func TestOfflineParentAndTransitiveMetadata(t *testing.T) {
	javaConfig(t)
	repo := t.TempDir()
	config.Conf().Java.LocalRepository = repo
	writePom(t, filepath.Join(repo, "g", "parent", "1", "parent-1.pom"), `<project><groupId>g</groupId><artifactId>parent</artifactId><version>1</version><properties><v>2</v></properties></project>`)
	writePom(t, filepath.Join(repo, "g", "a", "2", "a-2.pom"), `<project><groupId>g</groupId><artifactId>a</artifactId><version>2</version><dependencies><dependency><groupId>g</groupId><artifactId>b</artifactId><version>3</version><scope>runtime</scope></dependency></dependencies></project>`)
	writePom(t, filepath.Join(repo, "g", "b", "3", "b-3.pom"), `<project><groupId>g</groupId><artifactId>b</artifactId><version>3</version></project>`)
	p := ReadPom(strings.NewReader(`<project><parent><groupId>g</groupId><artifactId>parent</artifactId><version>1</version><relativePath/></parent><artifactId>app</artifactId><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>${v}</version></dependency></dependencies></project>`))
	ctx, diags := model.WithDiagnostics(context.Background())
	var root *model.DepGraph
	ParsePoms(ctx, []*Pom{p}, nil, func(_ *Pom, r *model.DepGraph) { root = r })
	if len(diags.List()) != 0 || root == nil || len(root.Children) != 1 || root.Children[0].Version != "2" || len(root.Children[0].Children) != 1 {
		t.Fatalf("root=%+v diags=%v", root, diags.List())
	}
}
func TestRelativeParentOutsideScan(t *testing.T) {
	javaConfig(t)
	dir := t.TempDir()
	parent := filepath.Join(dir, "pom.xml")
	writePom(t, parent, `<project><groupId>g</groupId><artifactId>parent</artifactId><version>1</version></project>`)
	child := filepath.Join(dir, "child", "pom.xml")
	writePom(t, child, `<project><parent><groupId>g</groupId><artifactId>parent</artifactId><version>1</version></parent><artifactId>child</artifactId></project>`)
	p := readPomFile(child)
	if relativeParent(p.Parent) == nil {
		t.Fatal("default relativePath not resolved")
	}
	p.Parent.RelativePath = ".."
	if relativeParent(p.Parent) == nil {
		t.Fatal("directory relativePath")
	}
	p.Parent.Version = "2"
	if relativeParent(p.Parent) != nil {
		t.Fatal("accepted mismatched coordinates")
	}
	p = ReadPomAt(strings.NewReader(`<project><parent><groupId>g</groupId><artifactId>parent</artifactId><version>1</version><relativePath/></parent><artifactId>child</artifactId></project>`), child)
	if relativeParent(p.Parent) != nil {
		t.Fatal("explicit empty relativePath must disable filesystem lookup")
	}
}
func TestProfilesUseActivationAndOverride(t *testing.T) {
	javaConfig(t)
	config.Conf().Java.JDK = "21.0.1"
	data := `<project><groupId>g</groupId><artifactId>app</artifactId><version>1</version><properties><x>base</x></properties><profiles><profile><id>old</id><activation><jdk>1.8</jdk></activation><properties><x>old</x></properties></profile><profile><id>default</id><activation><activeByDefault>true</activeByDefault></activation><properties><x>default</x></properties></profile><profile><id>new</id><activation><jdk>[17,)</jdk><property><name>enable</name></property></activation><properties><x>new</x></properties></profile></profiles></project>`
	p := ReadPom(strings.NewReader(data))
	if p.Properties["x"].Value != "default" {
		t.Fatal(p.Properties)
	}
	config.Conf().Java.Properties = map[string]string{"enable": "true"}
	p = ReadPom(strings.NewReader(data))
	if p.Properties["x"].Value != "new" {
		t.Fatal(p.Properties)
	}
	config.Conf().Java.Profiles = []string{"old"}
	config.Conf().Java.Properties = nil
	p = ReadPom(strings.NewReader(data))
	if p.Properties["x"].Value != "old" {
		t.Fatal(p.Properties)
	}
	config.Conf().Java.Properties = map[string]string{"x": "user"}
	p = ReadPom(strings.NewReader(data))
	if p.Properties["x"].Value != "user" {
		t.Fatal(p.Properties)
	}
}
