package java

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/xmirrorsecurity/opensca-cli/v3/cmd/config"
)

type Activation struct {
	ActiveByDefault bool   `xml:"activeByDefault"`
	JDK             string `xml:"jdk"`
	OS              struct {
		Name    string `xml:"name"`
		Family  string `xml:"family"`
		Arch    string `xml:"arch"`
		Version string `xml:"version"`
	} `xml:"os"`
	Property struct {
		Name  string `xml:"name"`
		Value string `xml:"value"`
	} `xml:"property"`
	File struct {
		Exists  string `xml:"exists"`
		Missing string `xml:"missing"`
	} `xml:"file"`
}

func (p *Pom) applyProfiles() {
	cfg := config.Conf().Java
	explicit, disabled := map[string]bool{}, map[string]bool{}
	for _, id := range cfg.Profiles {
		id = strings.TrimSpace(id)
		if strings.HasPrefix(id, "!") || strings.HasPrefix(id, "-") {
			disabled[id[1:]] = true
		} else {
			explicit[id] = true
		}
	}
	active := []Pom{}
	defaults := []Pom{}
	for _, profile := range p.Profiles {
		if disabled[profile.ID] {
			continue
		}
		if explicit[profile.ID] || p.matchesActivation(profile.Activation) {
			active = append(active, profile)
		} else if profile.Activation.ActiveByDefault {
			defaults = append(defaults, profile)
		}
	}
	if len(active) == 0 {
		active = defaults
	}
	if p.Properties == nil {
		p.Properties = PomProperties{}
	}
	for _, profile := range active {
		for k, v := range profile.Properties {
			p.Properties[k] = v
		}
		p.Dependencies = append(p.Dependencies, profile.Dependencies...)
		p.DependencyManagement = append(profile.DependencyManagement, p.DependencyManagement...)
		p.Modules = append(p.Modules, profile.Modules...)
		p.Repositories = append(p.Repositories, profile.Repositories...)
	}
	for k, v := range cfg.Properties {
		p.Properties[k] = &Property{Key: k, Value: v}
	}
}

func (p *Pom) matchesActivation(a Activation) bool {
	conditions := []bool{}
	if a.JDK != "" {
		v := config.Conf().Java.JDK
		if v == "" {
			v = os.Getenv("JAVA_VERSION")
		}
		if v == "" {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			out, _ := exec.CommandContext(ctx, "java", "-version").CombinedOutput()
			cancel()
			match := regexp.MustCompile(`version "([^"]+)"`).FindSubmatch(out)
			if len(match) == 2 {
				v = string(match[1])
			}
		}
		if v == "" {
			p.Issues = append(p.Issues, "profile JDK activation requires java.jdk or a local JDK")
		}
		conditions = append(conditions, matchJDK(a.JDK, v))
	}
	if a.OS.Name != "" || a.OS.Version != "" {
		p.Issues = append(p.Issues, "unsupported profile activation: exact OS name/version; select profile explicitly")
		conditions = append(conditions, false)
	}
	if a.OS.Family != "" {
		family := strings.ToLower(a.OS.Family)
		neg := strings.HasPrefix(family, "!")
		family = strings.TrimPrefix(family, "!")
		match := (family == "windows" && runtime.GOOS == "windows") || (family == "unix" && runtime.GOOS != "windows") || (family == "mac" && runtime.GOOS == "darwin")
		if family != "windows" && family != "unix" && family != "mac" {
			p.Issues = append(p.Issues, "unsupported profile OS family: "+family)
			conditions = append(conditions, false)
		} else {
			conditions = append(conditions, match != neg)
		}
	}
	if a.OS.Arch != "" {
		arch := runtime.GOARCH
		if arch == "386" {
			arch = "x86"
		}
		if arch == "arm64" {
			arch = "aarch64"
		}
		want := strings.ToLower(a.OS.Arch)
		neg := strings.HasPrefix(want, "!")
		conditions = append(conditions, (arch == strings.TrimPrefix(want, "!")) != neg)
	}
	if name := a.Property.Name; name != "" {
		neg := strings.HasPrefix(name, "!")
		name = strings.TrimPrefix(name, "!")
		value, exists := config.Conf().Java.Properties[name]
		if strings.HasPrefix(name, "env.") {
			value, exists = os.LookupEnv(strings.TrimPrefix(name, "env."))
		}
		if neg {
			conditions = append(conditions, !exists)
		} else if a.Property.Value == "" {
			conditions = append(conditions, exists)
		} else {
			want := a.Property.Value
			negValue := strings.HasPrefix(want, "!")
			conditions = append(conditions, (value == strings.TrimPrefix(want, "!")) != negValue && (exists || negValue))
		}
	}
	for _, f := range []struct {
		path    string
		missing bool
	}{{a.File.Exists, false}, {a.File.Missing, true}} {
		if f.path == "" {
			continue
		}
		base := filepath.Dir(p.File.Abspath())
		if p.File.Abspath() == "" {
			p.Issues = append(p.Issues, "profile file activation requires a POM path")
			conditions = append(conditions, false)
			continue
		}
		path := strings.ReplaceAll(f.path, "${basedir}", base)
		unresolved := false
		path = os.Expand(path, func(k string) string {
			if k == "user.home" {
				h, _ := os.UserHomeDir()
				return h
			}
			if strings.HasPrefix(k, "env.") {
				if v, ok := os.LookupEnv(strings.TrimPrefix(k, "env.")); ok {
					return v
				}
			}
			unresolved = true
			return ""
		})
		if unresolved {
			p.Issues = append(p.Issues, "unsupported or unresolved profile file activation: "+f.path)
			conditions = append(conditions, false)
			continue
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(base, path)
		}
		_, err := os.Stat(path)
		conditions = append(conditions, (err == nil && !f.missing) || (os.IsNotExist(err) && f.missing))
	}
	if len(conditions) == 0 {
		return false
	}
	for _, c := range conditions {
		if !c {
			return false
		}
	}
	return true
}

func matchJDK(spec, version string) bool {
	if version == "" {
		return false
	}
	if strings.HasPrefix(spec, "!") {
		return !matchJDK(spec[1:], version)
	}
	if !strings.ContainsAny(spec, "[(") {
		return strings.HasPrefix(version, spec)
	}
	if len(spec) < 2 {
		return false
	}
	limits := strings.Split(spec[1:len(spec)-1], ",")
	if len(limits) == 1 {
		return compareJava(version, limits[0]) == 0
	}
	if len(limits) != 2 {
		return false
	}
	lower, upper := strings.TrimSpace(limits[0]), strings.TrimSpace(limits[1])
	if lower != "" {
		c := compareJava(version, lower)
		if c < 0 || (c == 0 && spec[0] == '(') {
			return false
		}
	}
	if upper != "" {
		c := compareJava(version, upper)
		if c > 0 || (c == 0 && spec[len(spec)-1] == ')') {
			return false
		}
	}
	return true
}
func compareJava(a, b string) int {
	parse := func(s string) []int {
		out := []int{}
		for _, p := range regexp.MustCompile(`[._+\-]`).Split(s, -1) {
			n, err := strconv.Atoi(p)
			if err != nil {
				break
			}
			out = append(out, n)
		}
		return out
	}
	x, y := parse(a), parse(b)
	for i := 0; i < len(x) || i < len(y); i++ {
		u, v := 0, 0
		if i < len(x) {
			u = x[i]
		}
		if i < len(y) {
			v = y[i]
		}
		if u < v {
			return -1
		}
		if u > v {
			return 1
		}
	}
	return 0
}
