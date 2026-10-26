package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	_ "embed"

	"github.com/xmirrorsecurity/opensca-cli/v3/cmd/config"
	"github.com/xmirrorsecurity/opensca-cli/v3/cmd/detail"
	"github.com/xmirrorsecurity/opensca-cli/v3/cmd/format"
	"github.com/xmirrorsecurity/opensca-cli/v3/cmd/ui"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/common"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/logs"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/sca/filter"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/sca/java"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/sca/javascript"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/sca/php"
)

var version = "3.0.11+fixes"
var logo = `
   ___                   ____   ____    _    
  / _ \ _ __   ___ _ __ / ___| / ___|  / \   
 | | | | '_ \ / _ \ '_ \\___ \| |     / _ \  
 | |_| | |_) |  __/ | | |___) | |___ / ___ \ 
  \___/| .__/ \___|_| |_|____/ \____/_/   \_\
       |_|`

func main() {
	os.Exit(run())
}

func run() int {

	fmt.Println(logo)
	fmt.Println("Current version:", version)

	// 处理参数
	args()

	// 初始化HttpClient
	initHttpClient()
	common.SetOffline(config.Conf().Offline)
	defer common.SetOffline(false)
	if config.Conf().Offline {
		config.Conf().Optional.Dynamic = false
		if strings.Contains(config.Conf().Path, "://") && !strings.HasPrefix(config.Conf().Path, "file://") {
			fmt.Fprintln(os.Stderr, "offline mode requires a local project path")
			return 2
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// 检测参数
	arg := &opensca.TaskArg{DataOrigin: config.Conf().Path, InputType: config.Conf().InputType}

	// 是否跳过压缩包检测
	if config.Conf().Optional.DirOnly {
		arg.ExtractFileFilter = func(relpath string) bool { return false }
	}
	arg.IgnoreFileFilter = filter.IgnorePatterns(scanIgnorePatterns())

	// 开启进度条
	var stopProgress func()
	if config.Conf().Optional.ProgressBar {
		stopProgress = startProgressBar(arg)
	}

	// 运行检测任务
	result := opensca.RunTask(ctx, arg)

	// 日志中记录检测结果
	if result.Error != nil {
		logs.Error(result.Error)
	}
	for _, dep := range result.Deps {
		if dep.Name != "" || len(dep.Children) > 0 {
			logs.Debugf("dependency tree:\n%s", dep.Tree(false, false))
		}
	}

	// 生成报告
	report := taskReport(result)

	// 导出报告
	if err := format.Save(report, config.Conf().Output); err != nil {
		logs.Error(err)
		if stopProgress != nil {
			stopProgress()
		}
		return 2
	}

	// 等待进度条完成
	if config.Conf().Optional.ProgressBar {
		<-time.After(time.Millisecond * 200)
		if stopProgress != nil {
			stopProgress()
		}
	}

	// 打印概览信息
	dep, vul := format.Statis(report)
	status := "Complete"
	if result.Error != nil {
		status = "failed"
	} else if len(report.TaskInfo.Diagnostics) > 0 {
		status = "incomplete"
	}
	fmt.Println("\n" + status + "\n" + dep + vul)
	logs.Info("\n" + status + "\n" + dep + vul)

	// 发送检测报告
	if !config.Conf().Offline && !config.Conf().DependenciesOnly {
		if err := format.Saas(report); err != nil {
			logs.Warnf("saas report error: %s", err)
		}
	}

	// 开启ui
	if config.Conf().Optional.UI {
		ui.OpenUI(report)
	}
	if result.Error != nil {
		return 2
	}
	if len(report.TaskInfo.Diagnostics) > 0 {
		return 3
	}
	return 0
}

func args() {

	v := false
	login := false
	cfgf := ""
	proj := "x"
	profiles := ""
	cfg := config.Conf()
	flag.BoolVar(&v, "version", false, "-version")
	flag.BoolVar(&login, "login", false, "login to cloud server. example: -login")
	flag.StringVar(&cfgf, "config", "", "config path. example: -config config.json")
	flag.StringVar(&cfg.Path, "path", cfg.Path, "project path. example: -path project_path")
	flag.StringVar(&cfg.Output, "out", cfg.Output, "report path, support html/json/xml/csv/sarif/sqlite/cdx/spdx/swid/dsdx. example: -out out.json,out.html")
	flag.StringVar(&cfg.LogFile, "log", cfg.LogFile, "-log ./my_opensca_log.txt")
	flag.StringVar(&cfg.Origin.Token, "token", "", "web token, example: -token xxxx")
	flag.StringVar(&proj, "proj", proj, "saas project id, example: -proj xxxx")
	flag.BoolVar(&cfg.Offline, "offline", cfg.Offline, "disable all network access and dynamic builds")
	flag.StringVar(&cfg.InputType, "input-type", cfg.InputType, "auto, project, or sbom; auto excludes SBOMs when scanning directories")
	flag.StringVar(&cfg.CacheDir, "cache-dir", cfg.CacheDir, "dependency metadata cache directory")
	flag.StringVar(&cfg.Java.LocalRepository, "maven-repo", cfg.Java.LocalRepository, "Maven local repository")
	flag.StringVar(&cfg.Java.Settings, "maven-settings", cfg.Java.Settings, "Maven user settings.xml")
	flag.StringVar(&profiles, "profiles", "", "comma-separated Maven profiles; prefix ! to disable")
	flag.StringVar(&cfg.Java.JDK, "java-version", cfg.Java.JDK, "JDK version used for profile activation")
	flag.BoolVar(&cfg.DependenciesOnly, "dependencies-only", cfg.DependenciesOnly, "resolve dependencies and export reports without vulnerability lookup")
	flag.BoolVar(&cfg.IncludeProject, "include-project", cfg.IncludeProject, "include project module PURLs in CycloneDX components")
	// flag.StringVar(&cfg.Optional.Proxy, "proxy", "", "set global proxy for http requests, eg: http://127.0.0.1:7890")
	flag.Parse()

	if v {
		os.Exit(0)
	}

	cfgf = config.LoadConfig(cfgf)
	flag.Parse()

	cfg.Origin.Url = strings.TrimRight(cfg.Origin.Url, "/")
	if profiles != "" {
		cfg.Java.Profiles = strings.Split(profiles, ",")
	}
	if proj != "x" {
		cfg.Origin.Proj = &proj
	}

	logs.CreateLog(config.Conf().LogFile)

	logs.Infof("opensca-cli version: %s", version)
	logs.Infof("use config: %s", cfgf)

	if login {
		if err := detail.Login(); err != nil {
			fmt.Printf("login failure: %s\n", err)
		} else {
			fmt.Println("login success")
		}
	}

	java.RegisterMavenRepo(config.Conf().Repo.Maven...)
	javascript.RegisterNpmRepo(config.Conf().Repo.Npm...)
	php.RegisterComposerRepo(config.Conf().Repo.Composer...)
}

func initHttpClient() {

	// tls
	tlsConfig := func(c *http.Client) {
		c.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = !config.Conf().Optional.TLSVerify
	}
	common.SetHttpDownloadClient(tlsConfig)
	common.SetHttpSaasClient(tlsConfig)

	// proxy
	if config.Conf().Optional.Proxy != "" {
		proxyUrl := config.Conf().Optional.Proxy
		if proxy, err := url.Parse(proxyUrl); err == nil {
			proxyConfig := func(c *http.Client) {
				c.Transport.(*http.Transport).Proxy = http.ProxyURL(proxy)
			}
			common.SetHttpDownloadClient(proxyConfig)
			common.SetHttpSaasClient(proxyConfig)
			logs.Infof("use proxy %s", proxyUrl)
		} else {
			logs.Warnf("parse proxy %s error: %s", proxyUrl, err)
		}
	}
}

func startProgressBar(arg *opensca.TaskArg) (stop func()) {

	var progress atomic.Bool
	progress.Store(true)
	var find, deps atomic.Int64
	var bar int

	go func() {
		logos := []string{`[   ]`, `[=  ]`, `[== ]`, `[===]`, `[ ==]`, `[  =]`, `[   ]`, `[  =]`, `[ ==]`, `[===]`, `[== ]`, `[=  ]`}
		for progress.Load() {
			fmt.Printf("\r%s file:%d dependencies:%d", logos[bar], find.Load(), deps.Load())
			bar = (bar + 1) % len(logos)
			<-time.After(time.Millisecond * 100)
		}
	}()

	// 记录解析过的文件及依赖
	arg.ResCallFunc = func(file *model.File, root ...*model.DepGraph) {
		find.Add(1)
		for _, dep := range root {
			dep.ForEachNode(func(p, n *model.DepGraph) bool {
				if n.Name != "" {
					deps.Add(1)
				}
				return true
			})
		}
	}

	return func() {
		progress.Store(false)
	}
}

func taskReport(r opensca.TaskResult) format.Report {

	path := config.Conf().Path
	optional := config.Conf().Optional

	absPath, _ := filepath.Abs(path)
	appName := filepath.Base(absPath)

	logs.Info("prepare report")

	report := format.Report{}
	report.TaskInfo.ToolVersion = version
	report.TaskInfo.AppName = appName
	report.TaskInfo.Size = r.Size
	report.TaskInfo.Diagnostics = append([]string(nil), r.Diagnostics...)

	if r.Error != nil {
		report.TaskInfo.ErrorString = r.Error.Error()
	}

	// 合并检测结果
	root := &model.DepGraph{}
	if len(r.Deps) > 1 {
		for _, dep := range r.Deps {
			root.AppendChild(dep)
		}
	} else if len(r.Deps) == 1 {
		root = r.Deps[0]
	}
	report.DepDetailGraph = detail.NewDepDetailGraph(root)
	report.ForEach(func(n *detail.DepDetailGraph) bool {
		for _, issue := range n.Issues {
			report.TaskInfo.Diagnostics = append(report.TaskInfo.Diagnostics, issue)
		}
		if n.Name != "" && !n.Project && n.Purl() == "" {
			report.TaskInfo.Diagnostics = append(report.TaskInfo.Diagnostics, "component has no valid PURL: "+n.Name+"@"+n.Version)
		}
		return true
	})
	for _, issue := range report.TaskInfo.Diagnostics {
		logs.Warn(issue)
	}

	// 组件去重
	if optional.Dedup && !config.Conf().DependenciesOnly && !strings.Contains(config.Conf().Output, ".cdx.") {
		logs.Info("remove dup component")
		report.RemoveDedup()
	}

	// 去掉dev组件
	if !optional.SaveDev {
		logs.Info("remove dev component")
		report.RemoveDev()
	}

	// 查询组件详情(漏洞/许可证)
	var err error
	if !config.Conf().DependenciesOnly {
		err = detail.SearchDetail(report.DepDetailGraph)
	}
	if err != nil {
		logs.Warnf("database origin error: %s", err.Error())
		if report.TaskInfo.ErrorString != "" {
			report.TaskInfo.ErrorString += "\n"
		}
		report.TaskInfo.ErrorString += err.Error()
	}

	// 仅保留漏洞组件
	/*if optional.VulnOnly {
		logs.Info("remove no-vuln component")
		var deps []*detail.DepDetailGraph
		report.ForEach(func(n *detail.DepDetailGraph) bool {
			if len(n.Vulnerabilities) > 0 {
				deps = append(deps, n)
			}
			return true
		})
		for _, d := range deps {
			d.Children = nil
		}
		report.DepDetailGraph = &detail.DepDetailGraph{Children: deps}
	}*/

	end := time.Now()
	report.TaskInfo.StartTime = r.Start.Format("2006-01-02 15:04:05")
	report.TaskInfo.EndTime = end.Format("2006-01-02 15:04:05")
	report.TaskInfo.CostTime = end.Sub(r.Start).Seconds()

	return report
}

//go:embed config.json
var defaultConfig []byte

func init() {
	config.RegisterDefaultConfig(defaultConfig)
}
