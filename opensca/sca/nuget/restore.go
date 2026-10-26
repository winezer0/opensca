package nuget

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/logs"
)

type restoreFunc func(context.Context, string) error

type tailOutput struct {
	mu   sync.Mutex
	data []byte
}

func (b *tailOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	const limit = 16 << 10
	n := len(p)
	if len(p) > limit {
		p = p[len(p)-limit:]
	}
	b.data = append(b.data, p...)
	if len(b.data) > limit {
		b.data = b.data[len(b.data)-limit:]
	}
	return n, nil
}

// Like MurphySec, use NuGet/MSBuild's own restore evaluation. Reading assets
// afterwards preserves resolved versions and the graph, unlike dotnet list.
func restoreProject(ctx context.Context, project string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dotnet, err := exec.LookPath("dotnet")
	if err != nil {
		return fmt.Errorf("dotnet SDK unavailable: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	args := []string{"restore", project, "--verbosity", "minimal", "--disable-parallel", "-p:NuGetAudit=false"}
	cmd := exec.CommandContext(ctx, dotnet, args...)
	cmd.Dir = filepath.Dir(project)
	cmd.Env = append(os.Environ(), "DOTNET_CLI_TELEMETRY_OPTOUT=1", "DOTNET_NOLOGO=1", "DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1")
	cmd.WaitDelay = 2 * time.Second
	output := &tailOutput{}
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Run(); err != nil {
		logs.Debugf("dotnet restore output for %s: %s", project, string(output.data))
		if ctx.Err() != nil {
			return fmt.Errorf("dotnet restore canceled or timed out: %w", ctx.Err())
		}
		return fmt.Errorf("dotnet restore failed: %w", err)
	}
	return nil
}
