package cache

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/xmirrorsecurity/opensca-cli/v3/cmd/config"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/logs"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
)

var (
	cacheDir       string = ".opensca-cache"
	cacheOnce             = sync.Once{}
	taskCacheDirMu        = sync.RWMutex{}
	taskCacheDir   string
)

// SetTaskCacheDir temporarily sets the cache directory used by OpenSCA.
func SetTaskCacheDir(directory string) func() {
	taskCacheDirMu.Lock()
	previous := taskCacheDir
	taskCacheDir = directory
	taskCacheDirMu.Unlock()
	return func() {
		taskCacheDirMu.Lock()
		taskCacheDir = previous
		taskCacheDirMu.Unlock()
	}
}

func initCache() {
	cacheDir = config.Conf().CacheDir
	if cacheDir == "" {
		cacheDir = os.Getenv("OPENSCA_CACHE_DIR")
	}
	if cacheDir == "" {
		if userCache, err := os.UserCacheDir(); err == nil {
			cacheDir = filepath.Join(userCache, "opensca")
		} else {
			cacheDir = filepath.Join(os.TempDir(), "opensca-cache")
		}
	}
	if err := os.MkdirAll(cacheDir, 0777); err != nil {
		logs.Error(err)
	}
}

func Save(path string, reader io.Reader) bool {
	os.MkdirAll(filepath.Dir(path), 0777)
	if f, err := os.Create(path); err == nil {
		defer f.Close()
		io.Copy(f, reader)
		return true
	}
	return false
}

func Load(path string, do func(reader io.Reader)) bool {
	if f, err := os.Open(path); err == nil {
		defer f.Close()
		do(f)
		return true
	}
	return false
}

func Path(vendor, name, version string, language model.Language) string {
	base := currentCacheDir()
	var path string
	switch language {
	case model.Lan_Java:
		path = filepath.Join(base, "maven", vendor, name, version, fmt.Sprintf("%s-%s.pom", name, version))
	case model.Lan_JavaScript:
		path = filepath.Join(base, "npm", fmt.Sprintf("%s.json", name))
	case model.Lan_Php:
		path = filepath.Join(base, "composer", fmt.Sprintf("%s.json", name))
	default:
		path = filepath.Join(base, "none", fmt.Sprintf("%s-%s-%s", vendor, name, version))
	}
	return path
}

func currentCacheDir() string {
	taskCacheDirMu.RLock()
	base := taskCacheDir
	taskCacheDirMu.RUnlock()
	if base != "" {
		return base
	}
	cacheOnce.Do(initCache)
	return cacheDir
}
