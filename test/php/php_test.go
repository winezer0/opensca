package php

import (
	"encoding/json"
	"github.com/xmirrorsecurity/opensca-cli/v3/cmd/config"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/common"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/sca/php"
	"github.com/xmirrorsecurity/opensca-cli/v3/test/tool"
)

func Test_Php(t *testing.T) {
	// Serve the checked-in locked versions so manifest resolution cannot drift
	// when new packages are published to Packagist.
	before := *config.Conf()
	t.Cleanup(func() { *config.Conf() = before })
	config.Conf().CacheDir = t.TempDir()
	data, err := os.ReadFile("1/composer.lock")
	if err != nil {
		t.Fatal(err)
	}
	var lock php.ComposerLock
	if err := json.Unmarshal(data, &lock); err != nil {
		t.Fatal(err)
	}
	packages := map[string][]*php.ComposerPackage{}
	for _, p := range lock.Packages {
		packages[p.Name] = []*php.ComposerPackage{p}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), ".json")
		if packages[name] == nil {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(php.ComposerRepo{Packages: map[string][]*php.ComposerPackage{name: packages[name]}})
	}))
	defer server.Close()
	php.RegisterComposerRepo(common.RepoConfig{Url: server.URL})
	message := tool.Dep("psr/http-message", "2.0")
	factory := tool.Dep("psr/http-factory", "1.0.2", message)

	std := tool.Dep("", "",
		tool.Dep("opensca/test", "",
			tool.Dep("http-interop/http-factory-guzzle", "1.2.0",
				tool.Dep("guzzlehttp/psr7", "2.6.1",
					tool.Dep("ralouphie/getallheaders", "3.0.3"),
					factory, message,
				),
				factory,
			),
			message,
		),
	)

	tool.RunTaskCase(t, php.Sca{})([]tool.TaskCase{

		// composer.lock
		{Path: "1", Result: std},

		// composer.json
		{Path: "2", Result: std},
	})

}
