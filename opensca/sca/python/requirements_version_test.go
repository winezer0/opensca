package python

import (
	"reflect"
	"strings"
	"testing"
)

// TestRequirementScanVersionPolicy locks the same contract in both analyzer repositories.
func TestRequirementScanVersionPolicy(t *testing.T) {
	tests := []struct{ input, want string }{
		{"==1.5", "1.5"}, {"===1.5", "1.5"},
		{">=1.0,>=1.5", "1.5"}, {"<=2.0,<=1.8", "1.8"},
		{">=1.0,<=2.0", "1.0"}, {">=1.0,!=1.0", "1.0"},
		{">1.0", ""}, {"<2.0", ""}, {"!=1.0", ""},
		{">=1.0,>2.0,<0.5", "1.0"},
		{">=1.0,!=1.*", "1.0"},
		{">=1.9,>=1.10", "1.10"}, {"<=1.9,<=1.10", "1.9"},
		{">=1!1.0,>=9.0", "1!1.0"},
		{">=1.0rc1,>=1.0", "1.0"},
		{">=1.0.dev1,>=1.0a1", "1.0a1"},
		{">=1.0,>=1.0.post1", "1.0.post1"},
		{"==1.5,>=1.0,<=2.0", "1.5"},
		{"==1.0,===1.0.0", "1.0"},
		{">=1.0,>=1.0.0", "1.0"},
		{"<=1.0,<=1.0.0", "1.0"},
		{"==1.0,==2.0", ""}, {">=2.0,<=1.0", ""},
		{"==1.0,>=2.0", ""}, {"==3.0,<=2.0", ""},
		{">=v1.0RC1", "1.0rc1"}, {"==1.0+LOCAL", "1.0+local"},
		{"", ""}, {"*", ""}, {"==1.*", ""}, {"~=1.0", ""},
		{">=broken", ""}, {"=>1.0", ""}, {">=1.0,", ""},
		{">=1.0,!=bad", ""}, {">=1.0 garbage", ""},
		{"(>=1.0,<=2.0)", "1.0"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := selectRequirementVersion(tt.input); got != tt.want {
				t.Fatalf("version(%q) = %q, want %q", tt.input, got, tt.want)
			}
			parts := strings.Split(tt.input, ",")
			for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
				parts[i], parts[j] = parts[j], parts[i]
			}
			if !strings.HasPrefix(tt.input, "(") {
				if got := selectRequirementVersion(strings.Join(parts, ",")); got != tt.want {
					t.Fatalf("reordered version = %q, want %q", got, tt.want)
				}
			}
		})
	}
}

// TestRequirementDeclarationsPreserveManifestSyntax checks markers, extras, hashes and continuations.
func TestRequirementDeclarationsPreserveManifestSyntax(t *testing.T) {
	data := "# comment\r\nrequests[security] >=1.9, >=1.10 ; python_version < '3.8' # note\n" +
		"aiofiles==24.1.0 \\\n    --hash=sha256:abc \\\n    --hash=sha256:def\n" +
		"unresolved>1.0\nplain\n-r other.txt\n--index-url https://example.invalid\n" +
		"remote @ https://example.invalid/archive.whl\ninvalid>=oops\n"
	want := []requirementDeclaration{
		{name: "requests", version: "1.10", constraint: ">=1.9, >=1.10"}, {name: "aiofiles", version: "24.1.0", constraint: "==24.1.0"},
		{name: "unresolved", constraint: ">1.0"}, {name: "plain"}, {name: "invalid", constraint: ">=oops"},
	}
	if got := parseRequirementDeclarations(data); !reflect.DeepEqual(got, want) {
		t.Fatalf("declarations = %#v, want %#v", got, want)
	}
}
