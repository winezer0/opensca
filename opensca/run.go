package opensca

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/winezer0/opensca/versionaudit"
	"github.com/xmirrorsecurity/opensca-cli/v3/cmd/config"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/endpoint"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/logs"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/sca"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/sca/cache"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/sca/filter"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/sca/sbom"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/walk"
)

var taskRunGate = make(chan struct{}, 1)

// TaskArg configures an OpenSCA dependency analysis task.
type TaskArg struct {
	// auto: project directories exclude SBOMs; explicit SBOM files are accepted.
	InputType string

	// DataOrigin is the local path or URL to analyze.
	DataOrigin string
	// Name is the display name and defaults to the final path segment.
	Name string
	// Timeout limits task execution in seconds.
	Timeout int
	// Sca selects parsers; an empty slice uses the default parser set.
	Sca []sca.Sca

	// ExtractFileFilter optionally filters files before parser selection.
	ExtractFileFilter walk.ExtractFileFilter
	// IgnoreFileFilter skips files that match the supplied filter.
	IgnoreFileFilter walk.ExtractFileFilter
	// ResCallFunc receives each parser result.
	ResCallFunc model.ResCallback
	// CacheDir is the task-scoped metadata cache directory.
	CacheDir string
	// VersionDirectory optionally supplies a configured published-version catalog.
	VersionDirectory versionaudit.Directory
}

type TaskResult struct {
	Diagnostics []string
	// Arg contains the normalized task arguments.
	Arg *TaskArg
	// Deps contains the discovered dependency graphs.
	Deps []*model.DepGraph
	// Error reports task execution failures.
	Error error
	// Start is the task start time.
	Start time.Time
	// End is the task end time.
	End time.Time
	// Size is the total scanned input size.
	Size int64
}

// RunTask runs a dependency analysis task.
func RunTask(ctx context.Context, arg *TaskArg) (result TaskResult) {
	if ctx == nil {
		ctx = context.Background()
	}
	if arg == nil {
		arg = &TaskArg{DataOrigin: "./"}
	}
	result.Start = time.Now()
	select {
	case taskRunGate <- struct{}{}:
		defer func() { <-taskRunGate }()
	case <-ctx.Done():
		result.Error = ctx.Err()
		result.End = time.Now()
		result.Arg = arg
		return result
	}
	restoreCacheDir := cache.SetTaskCacheDir(arg.CacheDir)
	defer restoreCacheDir()
	ctx, diagnostics := model.WithDiagnostics(ctx)
	var resultMu sync.Mutex
	directory := arg.VersionDirectory
	if directory == nil {
		settings := config.Conf().VersionAudit
		settings.Offline = settings.Offline || config.Conf().Offline
		settings, err := settings.Environment()
		if err != nil {
			result.Error = err
			return
		}
		directory, err = settings.Directory()
		if err != nil {
			result.Error = err
			return
		}
	}
	defer func() {
		result.Diagnostics = diagnostics.List()
		if ctx.Err() != nil {
			result.Error = ctx.Err()
		}
		result.End = time.Now()
		result.Arg = arg
	}()

	if arg.ExtractFileFilter == nil {
		arg.ExtractFileFilter = filter.CompressFile
	}

	if arg.Name == "" {
		arg.Name = filepath.Base(arg.DataOrigin)
	}

	if arg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(arg.Timeout)*time.Second)
		if cancel != nil {
			defer cancel()
		}
	}

	if len(arg.Sca) == 0 {
		input := arg.InputType
		if input == "" {
			input = "auto"
		}
		if input != "auto" && input != "project" && input != "sbom" {
			result.Error = fmt.Errorf("invalid input type %q", input)
			return
		}
		allowSBOM := input == "sbom"
		if input == "auto" {
			if fi, err := os.Stat(arg.DataOrigin); err == nil && !fi.IsDir() {
				allowSBOM = true
			}
		}
		for _, parser := range sca.AllSca {
			_, isSBOM := parser.(sbom.Sca)
			if (input == "sbom" && !isSBOM) || (isSBOM && !allowSBOM) {
				continue
			}
			arg.Sca = append(arg.Sca, parser)
		}
	}

	result.Size, result.Error = walk.Walk(ctx, arg.Name, arg.DataOrigin, func(relpath string) bool {
		if arg.ExtractFileFilter != nil && arg.ExtractFileFilter(relpath) {
			return true
		}

		for _, sca := range arg.Sca {
			if sca.Filter(relpath) {
				return true
			}
		}

		return false

	}, arg.IgnoreFileFilter, func(parent *model.File, files []*model.File) {

		for _, sca := range arg.Sca {

			fs := []*model.File{}
			for _, f := range files {
				if sca.Filter(f.Relpath()) {
					fs = append(fs, f)
				}
			}

			if len(fs) == 0 {
				continue
			}

			scaType := reflect.TypeOf(sca).String()
			logs.Debugf("start sca:%s file:%s files:%v", scaType, parent, fs)

			defer func() {
				if err := recover(); err != nil {
					model.AddDiagnostic(ctx, fmt.Sprintf("parser panic: %s: %v", scaType, err))
					logs.Errorf("sca:%s file:%s err:%v", scaType, parent, err)
				}
			}()

			sca.Sca(ctx, parent, fs, func(file *model.File, root ...*model.DepGraph) {
				for _, dep := range root {
					if dep == nil {
						continue
					}
					count := 0
					dep.ForEachNode(func(p, n *model.DepGraph) bool { count++; return true })
					logs.Infof("file:%s deps:%d language:%s", file.Relpath(), count, sca.Language())
					dep.Build(false, sca.Language())
					for _, resolved := range endpoint.Expand(ctx, dep, directory) {
						resultMu.Lock()
						result.Deps = append(result.Deps, resolved)
						resultMu.Unlock()
						if arg.ResCallFunc != nil {
							arg.ResCallFunc(file, resolved)
						}
					}
				}
			})

			logs.Debugf("end sca:%s file:%s", scaType, parent)
		}

	})
	return result
}
