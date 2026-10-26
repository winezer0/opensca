package nuget

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/xmirrorsecurity/opensca-cli/v3/cmd/config"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
)

func pathKey(filename string) string {
	filename = filepath.Clean(filename)
	if runtime.GOOS == "windows" {
		filename = strings.ToLower(filename)
	}
	return filename
}

func isAssetsFile(filename string) bool {
	return strings.EqualFold(filepath.Base(fromMSBuildPath(filename)), "project.assets.json")
}

func assetsFile(info *projectInfo) *model.File {
	filename := info.assetsPath()
	rel, err := filepath.Rel(filepath.Dir(info.File.Abspath()), filename)
	if err != nil {
		rel = filename
	}
	return model.NewFile(filename, filepath.Join(filepath.Dir(info.File.Relpath()), rel))
}

func loadAssets(file, project *model.File) (*model.DepGraph, error) {
	var root *model.DepGraph
	var parseErr error
	err := file.OpenReader(func(r io.Reader) { root, parseErr = readAssets(r, file, project) })
	if err != nil {
		return nil, err
	}
	return root, parseErr
}

func loadProjectAssets(info *projectInfo, file *model.File) (*model.DepGraph, error) {
	assetStat, err := os.Stat(file.Abspath())
	if err != nil {
		return nil, err
	}
	for _, input := range info.Inputs {
		if stat, err := os.Stat(input); err == nil && stat.ModTime().After(assetStat.ModTime()) {
			return nil, fmt.Errorf("project.assets.json predates project input %s", filepath.Base(input))
		}
	}
	return loadAssets(file, info.File)
}

func scanNuget(ctx context.Context, files []*model.File, call model.ResCallback, restore restoreFunc) {
	projects, assets, inventories := map[string]*model.File{}, map[string]*model.File{}, map[string]*model.File{}
	var solutions []*model.File
	for _, file := range files {
		switch {
		case isProjectFile(file.Relpath()):
			projects[pathKey(file.Abspath())] = file
		case isAssetsFile(file.Relpath()):
			assets[pathKey(file.Abspath())] = file
		case strings.EqualFold(filepath.Ext(file.Relpath()), ".sln"):
			solutions = append(solutions, file)
		case strings.EqualFold(filepath.Base(fromMSBuildPath(file.Relpath())), "packages.config"):
			inventories[pathKey(file.Abspath())] = file
		}
	}
	for _, solution := range solutions {
		members, err := solutionProjects(solution)
		if err != nil {
			model.AddDiagnostic(ctx, fmt.Sprintf("invalid %s: %v; dependency data may be incomplete", solution.Relpath(), err))
			continue
		}
		for _, member := range members {
			projects[pathKey(member.Abspath())] = member
		}
	}
	usedAssets := map[string]bool{}
	for _, key := range sortedKeys(projects) {
		if ctx.Err() != nil {
			return
		}
		project := projects[key]
		info, err := inspectProject(project)
		if err != nil {
			model.AddDiagnostic(ctx, fmt.Sprintf("invalid %s: %v; dependency data may be incomplete", project.Relpath(), err))
			continue
		}
		// Legacy projects use packages.config as their installed inventory.
		if inventories[pathKey(filepath.Join(filepath.Dir(project.Abspath()), "packages.config"))] != nil && !info.HasPackageReferences {
			continue
		}
		file := assetsFile(info)
		usedAssets[pathKey(file.Abspath())] = true
		root, assetErr := loadProjectAssets(info, file)
		if assetErr == nil {
			call(project, root)
			continue
		}
		mode := config.Conf().Optional.Dynamic
		reason := ""
		switch {
		case config.Conf().Offline:
			reason = "offline mode disables dotnet restore"
		case mode == config.DynamicOff:
			reason = "dynamic:off disables dotnet restore"
		case mode != "" && mode != config.DynamicAuto && mode != config.DynamicOn:
			reason = fmt.Sprintf("invalid dynamic mode %q", mode)
		default:
			if err := restore(ctx, project.Abspath()); err != nil {
				reason = err.Error()
			} else {
				// A successful incremental restore may validate existing assets
				// without rewriting their timestamp when inputs changed harmlessly.
				root, err = loadAssets(file, project)
				if err == nil {
					call(project, root)
					continue
				}
				reason = fmt.Sprintf("dotnet restore produced no usable assets: %v", err)
			}
		}
		model.AddDiagnostic(ctx, fmt.Sprintf("NuGet resolution incomplete for %s: %s; assets: %v; using static PackageReference inventory; dependency data may be incomplete", project.Relpath(), reason, assetErr))
		call(project, info.fallbackGraph())
	}
	for _, key := range sortedKeys(assets) {
		if usedAssets[key] {
			continue
		}
		file := assets[key]
		root, err := loadAssets(file, nil)
		if err != nil {
			model.AddDiagnostic(ctx, fmt.Sprintf("invalid %s: %v; dependency data may be incomplete", file.Relpath(), err))
			continue
		}
		call(file, root)
	}
	for _, key := range sortedKeys(inventories) {
		file := inventories[key]
		var root *model.DepGraph
		var parseErr error
		err := file.OpenReader(func(r io.Reader) { root, parseErr = parsePackagesConfig(r, file.Relpath()) })
		if err == nil {
			err = parseErr
		}
		if err != nil {
			model.AddDiagnostic(ctx, fmt.Sprintf("invalid %s: %v; dependency data may be incomplete", file.Relpath(), err))
			continue
		}
		call(file, root)
	}
}
