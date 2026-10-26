package config

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"github.com/titanous/json5"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/common"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/logs"
)

type Config struct {
	BaseConfig
	Offline          bool           `json:"offline"`
	InputType        string         `json:"input_type"`
	CacheDir         string         `json:"cache_dir"`
	Java             JavaConfig     `json:"java"`
	DependenciesOnly bool           `json:"deps_only"`
	IncludeProject   bool           `json:"include_project"`
	Optional         OptionalConfig `json:"optional"`
	Repo             RepoConfig     `json:"repo"`
	Origin           OriginConfig   `json:"origin"`
}

type JavaConfig struct {
	MavenCommand    string            `json:"maven_command"`
	LocalRepository string            `json:"local_repository"`
	Settings        string            `json:"settings"`
	Profiles        []string          `json:"profiles"`
	Properties      map[string]string `json:"properties"`
	JDK             string            `json:"jdk"`
}

type BaseConfig struct {
	Path    string `json:"path"`
	Output  string `json:"out"`
	LogFile string `json:"log"`
}

type OriginConfig struct {
	Url    string    `json:"url"`
	Token  string    `json:"token"`
	Proj   *string   `json:"proj"`
	Json   string    `json:"json"`
	Mysql  SqlOrigin `json:"mysql"`
	Sqlite SqlOrigin `json:"sqlite"`
}

type OptionalConfig struct {
	UI          bool        `json:"ui"`
	Dedup       bool        `json:"dedup"`
	DirOnly     bool        `json:"dir"`
	VulnOnly    bool        `json:"vuln"`
	SaveDev     bool        `json:"dev"`
	ProgressBar bool        `json:"progress"`
	TLSVerify   bool        `json:"tls"`
	Proxy       string      `json:"proxy"`
	Dynamic     DynamicMode `json:"dynamic"`
	Ignore      []string    `json:"ignore"`
}

// DynamicMode controls parsers that invoke external build tools. Auto enables
// Maven and NuGet resolution when their tools are installed; other dynamic
// parsers stay opt-in. The zero value behaves like auto for Maven and NuGet.
type DynamicMode string

const (
	DynamicAuto DynamicMode = "auto"
	DynamicOn   DynamicMode = "on"
	DynamicOff  DynamicMode = "off"
)

func (m DynamicMode) Enabled() bool { return m == DynamicOn }

func (m *DynamicMode) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err == nil {
		switch DynamicMode(value) {
		case DynamicAuto, DynamicOn, DynamicOff:
			*m = DynamicMode(value)
			return nil
		default:
			return fmt.Errorf("invalid dynamic mode %q (expected auto, on, or off)", value)
		}
	}
	var enabled bool
	if err := json.Unmarshal(data, &enabled); err == nil {
		if enabled {
			*m = DynamicOn
		} else {
			*m = DynamicOff
		}
		return nil
	}
	return fmt.Errorf("dynamic must be auto, on, off, or a legacy boolean")
}

type RepoConfig struct {
	Maven    []common.RepoConfig `json:"maven"`
	Npm      []common.RepoConfig `json:"npm"`
	Composer []common.RepoConfig `json:"composer"`
}

type SqlOrigin struct {
	Dsn   string `json:"dsn"`
	Table string `json:"table"`
}

var _config *Config = &Config{}

func Conf() *Config {
	return _config
}

// WriteConfig 写入配置
func WriteConfig(write func(config *Config)) {
	if write != nil {
		write(_config)
	}
}

// loadDefaultConfig 加载默认配置 返回使用的配置文件
func loadDefaultConfig() string {

	var defaultConfigPaths []string

	// 读取工作目录的 config.json
	if p, err := os.Getwd(); err == nil {
		defaultConfigPaths = append(defaultConfigPaths, filepath.Join(p, "config.json"))
	}

	// 读取用户目录下的 opensca_config.json
	if currenUser, err := user.Current(); err == nil {
		defaultConfigPaths = append(defaultConfigPaths, filepath.Join(currenUser.HomeDir, "opensca_config.json"))
	}

	// 读取 opensca-cli 所在目录下的 config.json
	if p, err := os.Executable(); err == nil {
		defaultConfigPaths = append(defaultConfigPaths, filepath.Join(filepath.Dir(p), "config.json"))
	}

	for _, config := range defaultConfigPaths {
		if data, err := os.ReadFile(config); err == nil {
			err := json5.Unmarshal(data, &_config)
			if err == nil {
				logs.Debugf("load config %s", config)
				return config
			}
		}
	}

	return ""
}

// LoadConfig 加载配置文件 返回使用的配置文件
func LoadConfig(filepath string) string {

	if filepath == "" {
		logs.Debug("use default config")
		return loadDefaultConfig()
	}

	if _, err := os.Stat(filepath); err != nil {
		logs.Debugf("%s not exist, create default config file", filepath)
		CreateConfigFile(filepath)
	}

	f, err := os.Open(filepath)
	if err != nil {
		logs.Warnf("read file %s error: %v", filepath, err)
	}

	err = json5.NewDecoder(f).Decode(_config)
	if err != nil {
		logs.Warnf("unmarshal file %s error: %v", filepath, err)
	}

	return filepath
}

var defalutConfigJson []byte

func RegisterDefaultConfig(data []byte) {
	defalutConfigJson = data
	if _config == nil {
		_config = &Config{}
		err := json5.Unmarshal(defalutConfigJson, &_config)
		if err != nil {
			logs.Warnf("unmarshal default config error: %v", err)
		}
	}
}

// CreateConfigFile 生成配置文件
func CreateConfigFile(filepath string) {
	err := os.WriteFile(filepath, defalutConfigJson, 0666)
	if err != nil {
		logs.Warnf("write file %s error: %v", filepath, err)
	}
}
