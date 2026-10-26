package nuget

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
)

type projectReference struct {
	Include         string `xml:"Include,attr"`
	Update          string `xml:"Update,attr"`
	Condition       string `xml:"Condition,attr"`
	Version         string `xml:"Version,attr"`
	VersionElement  string `xml:"Version"`
	Override        string `xml:"VersionOverride,attr"`
	OverrideElement string `xml:"VersionOverride"`
}

type msbuildProject struct {
	XMLName        xml.Name `xml:"Project"`
	PropertyGroups []struct {
		Condition  string `xml:"Condition,attr"`
		Properties []struct {
			XMLName   xml.Name
			Condition string `xml:"Condition,attr"`
			Value     string `xml:",chardata"`
		} `xml:",any"`
	} `xml:"PropertyGroup"`
	ItemGroups []struct {
		Condition string             `xml:"Condition,attr"`
		Packages  []projectReference `xml:"PackageReference"`
		Versions  []projectReference `xml:"PackageVersion"`
		Projects  []projectReference `xml:"ProjectReference"`
	} `xml:"ItemGroup"`
}

type projectInfo struct {
	File                 *model.File
	Properties           map[string]string
	Packages             []projectReference
	Projects             []projectReference
	Central              map[string]string
	Inputs               []string
	HasPackageReferences bool
}

var propertyPattern = regexp.MustCompile(`\$\(([^)]+)\)`)

func expandProperty(s string, properties map[string]string) string {
	for i := 0; i < 16; i++ {
		next := propertyPattern.ReplaceAllStringFunc(s, func(ref string) string {
			if value, ok := properties[strings.ToLower(ref[2:len(ref)-1])]; ok {
				return value
			}
			return ref
		})
		if next == s {
			break
		}
		s = next
	}
	return strings.TrimSpace(s)
}

func readProjectXML(filename string) (*msbuildProject, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	const maxSize = 4 << 20
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSize {
		return nil, fmt.Errorf("MSBuild XML exceeds 4 MiB")
	}
	var p msbuildProject
	if err := xml.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func nearestProps(dir, name string) string {
	for {
		filename := filepath.Join(dir, name)
		if info, err := os.Stat(filename); err == nil && !info.IsDir() {
			return filename
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func inspectProject(file *model.File) (*projectInfo, error) {
	dir := filepath.Dir(file.Abspath())
	info := &projectInfo{File: file, Properties: map[string]string{
		"msbuildprojectdirectory": dir, "msbuildprojectname": strings.TrimSuffix(filepath.Base(file.Abspath()), filepath.Ext(file.Abspath())),
	}, Central: map[string]string{}, Inputs: []string{file.Abspath()}}
	applyProperties := func(p *msbuildProject, filename string) {
		info.Properties["msbuildthisfiledirectory"] = filepath.Dir(filename) + string(filepath.Separator)
		for _, group := range p.PropertyGroups {
			if group.Condition != "" {
				continue
			}
			for _, property := range group.Properties {
				if property.Condition == "" {
					info.Properties[strings.ToLower(property.XMLName.Local)] = expandProperty(property.Value, info.Properties)
				}
			}
		}
	}
	for _, name := range []string{"Directory.Build.props", "Directory.Packages.props"} {
		if filename := nearestProps(dir, name); filename != "" {
			info.Inputs = append(info.Inputs, filename)
			p, err := readProjectXML(filename)
			if err != nil {
				return nil, fmt.Errorf("reading %s: %w", filename, err)
			}
			applyProperties(p, filename)
			for _, group := range p.ItemGroups {
				if group.Condition != "" {
					continue
				}
				for _, v := range group.Versions {
					if v.Condition == "" {
						info.Central[strings.ToLower(v.Include)] = expandProperty(firstValue(v.Version, v.VersionElement), info.Properties)
					}
				}
			}
		}
	}
	p, err := readProjectXML(file.Abspath())
	if err != nil {
		return nil, err
	}
	applyProperties(p, file.Abspath())
	for _, group := range p.ItemGroups {
		info.HasPackageReferences = info.HasPackageReferences || len(group.Packages) != 0
		if group.Condition != "" {
			continue
		}
		for _, pkg := range group.Packages {
			if pkg.Include != "" && pkg.Condition == "" {
				info.Packages = append(info.Packages, pkg)
			}
		}
		for _, ref := range group.Projects {
			if ref.Include != "" && ref.Condition == "" {
				info.Projects = append(info.Projects, ref)
			}
		}
	}
	return info, nil
}

func firstValue(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func (info *projectInfo) assetsPath() string {
	dir := firstValue(info.Properties["msbuildprojectextensionspath"], info.Properties["baseintermediateoutputpath"], "obj")
	dir = fromMSBuildPath(expandProperty(dir, info.Properties))
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(filepath.Dir(info.File.Abspath()), dir)
	}
	return filepath.Join(dir, "project.assets.json")
}

// Static fallback deliberately does not emulate MSBuild conditions/imports or
// turn a requested range into a resolved version. The caller reports incomplete
// dependency data whenever this fallback is used.
func (info *projectInfo) fallbackGraph() *model.DepGraph {
	root := &model.DepGraph{Name: info.Properties["msbuildprojectname"], Version: info.Properties["version"], Path: info.File.Relpath(), Project: true}
	seen := map[string]bool{}
	for _, pkg := range info.Packages {
		name := expandProperty(pkg.Include, info.Properties)
		version := firstValue(pkg.Override, pkg.OverrideElement, pkg.Version, pkg.VersionElement)
		if version == "" && strings.EqualFold(info.Properties["managepackageversionscentrally"], "true") {
			version = info.Central[strings.ToLower(name)]
		}
		version = expandProperty(version, info.Properties)
		// NuGet's single version syntax is a minimum constraint; only assets
		// establish the actual resolved version. Do not attach a registry PURL.
		key := strings.ToLower(name) + "@" + version
		if name == "" || seen[key] {
			continue
		}
		seen[key] = true
		n := &model.DepGraph{Name: name, Direct: true, Language: model.Lan_DotNet}
		// A singleton range is the one static syntax that pins an exact version.
		if strings.HasPrefix(version, "[") && strings.HasSuffix(version, "]") {
			pinned := strings.TrimSuffix(strings.TrimPrefix(version, "["), "]")
			if packageID.MatchString(name) && packageVersion.MatchString(pinned) {
				n.Version = pinned
			}
		}
		root.AppendChild(n)
	}
	for _, ref := range info.Projects {
		filename := fromMSBuildPath(expandProperty(ref.Include, info.Properties))
		root.AppendChild(&model.DepGraph{Name: strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename)), Path: filename, Project: true, Direct: true})
	}
	return root
}

func isProjectFile(filename string) bool {
	switch strings.ToLower(filepath.Ext(filename)) {
	case ".csproj", ".fsproj", ".vbproj":
		return true
	}
	return false
}

var solutionProject = regexp.MustCompile(`(?im)^\s*Project\([^\r\n]*?\)\s*=\s*"[^"]*"\s*,\s*"([^"]+)"`)

func solutionProjects(file *model.File) ([]*model.File, error) {
	data, err := os.ReadFile(file.Abspath())
	if err != nil {
		return nil, err
	}
	var result []*model.File
	for _, match := range solutionProject.FindAllStringSubmatch(string(data), -1) {
		name := fromMSBuildPath(match[1])
		if !isProjectFile(name) {
			continue
		}
		absolute := filepath.Clean(filepath.Join(filepath.Dir(file.Abspath()), name))
		result = append(result, model.NewFile(absolute, filepath.Join(filepath.Dir(file.Relpath()), name)))
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("solution contains no supported .NET projects")
	}
	return result, nil
}
