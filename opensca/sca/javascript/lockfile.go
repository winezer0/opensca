package javascript

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

func readPackageLock(reader io.Reader) (*PackageLock, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	var lock PackageLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if lock.LockfileVersion < 1 || lock.LockfileVersion > 3 {
		return nil, fmt.Errorf("unsupported lockfileVersion %d (supported: 1, 2, 3)", lock.LockfileVersion)
	}
	if lock.LockfileVersion == 1 {
		var top map[string]json.RawMessage
		_ = json.Unmarshal(data, &top)
		if strings.TrimSpace(string(top["dependencies"])) == "null" {
			return nil, fmt.Errorf("dependencies must be an object, not null")
		}
		if lock.Dependencies == nil && lock.Name == "" && lock.Version == "" {
			return nil, fmt.Errorf("missing dependencies or project metadata")
		}
		var validate func(map[string]*PackageLockDep) error
		validate = func(deps map[string]*PackageLockDep) error {
			for name, dep := range deps {
				if dep == nil || dep.Version == "" {
					return fmt.Errorf("invalid dependency %q: missing package or version", name)
				}
				if err := validate(dep.Dependencies); err != nil {
					return err
				}
			}
			return nil
		}
		return &lock, validate(lock.Dependencies)
	}
	if lock.Packages[""] == nil {
		return nil, fmt.Errorf("missing packages[\"\"] root entry")
	}
	for packagePath, pkg := range lock.Packages {
		if pkg == nil {
			return nil, fmt.Errorf("null package entry %q", packagePath)
		}
		if pkg.Link {
			target := lock.Packages[pkg.Resolved]
			if pkg.Resolved == "" || target == nil || target.Link {
				return nil, fmt.Errorf("invalid link %q -> %q", packagePath, pkg.Resolved)
			}
			continue
		}
		if strings.Contains("/"+packagePath+"/", "/node_modules/") && pkg.Version == "" {
			return nil, fmt.Errorf("missing version for %q", packagePath)
		}
		for _, deps := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.PeerDependencies} {
			for name := range deps {
				if _, optional := pkg.OptionalDependencies[name]; optional || pkg.PeerDependenciesMeta[name].Optional {
					continue
				}
				if _, found := findFromNodeModules(name, packagePath, lock.Packages); found == nil {
					return nil, fmt.Errorf("unresolved dependency %q in %q", name, packagePath)
				}
			}
		}
	}
	return &lock, nil
}
