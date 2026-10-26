package nuget

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"

	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
)

type Sca struct{}

func (Sca) Language() model.Language { return model.Lan_DotNet }

func (Sca) Filter(relpath string) bool {
	return strings.EqualFold(path.Base(strings.ReplaceAll(relpath, `\`, "/")), "packages.config") ||
		isProjectFile(relpath) || strings.EqualFold(path.Ext(relpath), ".sln") || isAssetsFile(relpath)
}

func (Sca) Sca(ctx context.Context, parent *model.File, files []*model.File, call model.ResCallback) {
	scanNuget(ctx, files, call, restoreProject)
}

var packageID = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
var packageVersion = regexp.MustCompile(`^[0-9]+(\.[0-9]+){0,3}(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

// Like MurphySec's packages.config reader, read installed package identities
// directly. The manifest is a flat inventory; it does not encode package edges.
func parsePackagesConfig(r io.Reader, relpath string) (*model.DepGraph, error) {
	const maxSize = 4 << 20
	data, err := io.ReadAll(io.LimitReader(r, maxSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSize {
		return nil, fmt.Errorf("packages.config exceeds 4 MiB")
	}
	var doc struct {
		XMLName  xml.Name `xml:"packages"`
		Packages []struct {
			ID      string `xml:"id,attr"`
			Version string `xml:"version,attr"`
			Develop bool   `xml:"developmentDependency,attr"`
		} `xml:"package"`
	}
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	root := &model.DepGraph{Project: true, Path: relpath}
	seen := map[string]*model.DepGraph{}
	for _, pkg := range doc.Packages {
		if !packageID.MatchString(pkg.ID) || !packageVersion.MatchString(pkg.Version) || model.Purl("", pkg.ID, pkg.Version, model.Lan_DotNet) == "" {
			return nil, fmt.Errorf("invalid installed package %q version %q", pkg.ID, pkg.Version)
		}
		key := strings.ToLower(pkg.ID) + "@" + strings.ToLower(pkg.Version)
		if previous := seen[key]; previous != nil {
			previous.Develop = previous.Develop && pkg.Develop
			continue
		}
		n := &model.DepGraph{Name: pkg.ID, Version: pkg.Version, Develop: pkg.Develop, Language: model.Lan_DotNet}
		seen[key] = n
		root.AppendChild(n)
	}
	return root, nil
}
