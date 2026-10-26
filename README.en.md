# OpenSCA

**Original project README:** [Chinese README](https://github.com/XmirrorSecurity/OpenSCA-cli/blob/master/README.md) · [English README](https://github.com/XmirrorSecurity/OpenSCA-cli/blob/master/.github/README.md)

**Current documentation:** [中文](README.md) · English

This is a modified version of [XmirrorSecurity/OpenSCA-cli](https://github.com/XmirrorSecurity/OpenSCA-cli), maintained at [winezer0/opensca](https://github.com/winezer0/opensca). It extends the original dependency analysis, vulnerability lookup, and reporting capabilities with local and offline resolution, dependency graph and SBOM fixes, and pnpm and NuGet support.

This README describes the current implementation in this repository. **[Added], [Changed], and [Fixed] refer to differences from the imported upstream snapshot.** The original READMEs and [English](docs/README.md) / [Chinese](docs/README-zh-CN.md) manuals remain historical references; use this document for current installation sources, options, and behavior.

## Contents

- [Changes from upstream](#changes-from-upstream)
- [Installation and quick start](#installation-and-quick-start)
- [Supported inputs](#supported-inputs)
- [Usage](#usage)
- [Options and configuration](#options-and-configuration)
- [Output and diagnostics](#output-and-diagnostics)
- [Migration and limitations](#migration-and-limitations)
- [Validation and feedback](#validation-and-feedback)

## Changes from upstream

| Status | Feature | Upstream behavior | Current behavior and usage |
| --- | --- | --- | --- |
| [Added] | Offline mode | No unified offline control | `-offline` disables network access and dynamic builds; accepts local input and uses local repositories and existing caches |
| [Changed] | Dependency-only mode | Resolution tied to vulnerability lookup | `-deps-only` skips vulnerability lookup and SaaS report upload; exports dependencies without a token. Add `-offline` to disable networking as well |
| [Added] | pnpm | No lockfile parser | Reads `pnpm-lock.yaml` layouts 5, 6, and 9, including workspaces, optional dependencies, and peer contexts, without running pnpm |
| [Added] | NuGet / .NET | No parser for this ecosystem | Reads `packages.config`, C#/F#/VB projects, solutions, and `project.assets.json`; prefers usable assets and can run `dotnet restore` when needed |
| [Changed] | Dynamic resolution | Boolean switch | `optional.dynamic` now accepts `auto` / `on` / `off`, with legacy `true` / `false` support. Default `auto` can attempt Maven and NuGet; other dynamic parsers require `on` |
| [Added] | Local Maven configuration | No local repository selection | Adds `-maven-repo`, `-maven-settings`, `-maven-command`, `-profiles`, and `-java-version`; caches can use `-cache-dir` |
| [Fixed] | Static Maven parsing | Gaps in parent POM, local resolution, and profile activation | Improves local repository resolution, parent paths and versions, and profile conditions; reports incomplete resolution. See limitations below |
| [Fixed] | npm lockfiles | Standalone lockfiles could produce no dependencies; nested graphs could lose edges | Supports standalone `package-lock.json` v1/v2/v3, nested versions, workspaces, and development/runtime relationships |
| [Fixed] | Go module selection | Historical `go.sum` versions mixed into current dependencies; vendor manifests scanned again | Static resolution prefers `vendor/modules.txt`, then `go.mod`, with `go.sum` only as fallback; fixes `replace`, single-line statements, and `+incompatible` versions |
| [Fixed] | CycloneDX | Duplicate components and inconsistent references or edges | Stable references, deduplicated components and edges, preserved root dependencies; project nodes excluded from `components` unless `-include-project` is set |
| [Fixed] | SPDX / PURL | Invalid document fields, references, or package identities | Repairs SPDX JSON and tag-value documents and centralizes PURL generation; diagnoses unknown ecosystems and unresolved versions |
| [Changed] | SBOM input | Directory scans could count existing SBOMs again | Directory scans exclude SBOMs by default; individual files can be detected automatically or imported explicitly with `-input-type sbom` |
| [Added] | Completeness diagnostics | Fallbacks, skips, and unresolved dependencies were less visible | Reports diagnostics and distinguishes success, failure, and incomplete results; an exported SBOM does not establish completeness or absence of vulnerabilities |

See [SBOM / OSV compatibility notes and tests (Chinese)](OSV兼容输出与测试说明.md). For OSV integration, OpenSCA resolves dependencies and exports SBOMs; users run `osv-scanner` separately. OpenSCA does not manage OSV databases or merge OSV findings.

## Installation and quick start

Check [this repository's Releases](https://github.com/winezer0/opensca/releases) for a suitable platform build, or build from source. Building requires **Go 1.25 or newer**, as specified in [go.mod](go.mod).

```sh
git clone https://github.com/winezer0/opensca.git
cd opensca
go build -o opensca .
./opensca -version
./opensca -path ./example -offline -deps-only -out bom.cdx.json,report.json
```

Windows PowerShell:

```powershell
git clone https://github.com/winezer0/opensca.git
cd opensca
go build -o opensca.exe .
.\opensca.exe -version
.\opensca.exe -path .\example -offline -deps-only -out bom.cdx.json,report.json
```

Examples below use `./opensca`; use `.\opensca.exe` on Windows. Dependency-only exports need no cloud token. Go module downloads during builds, online dependency resolution, and external vulnerability scanning have separate network requirements.

## Supported inputs

`-path` accepts a directory, a single manifest, or an SBOM. Existing archive scanning remains available.

| Ecosystem / type | Main inputs | Notes for this version |
| --- | --- | --- |
| Java / Maven | `pom.xml` | [Changed] Local repositories, profiles, and dynamic Maven controls |
| Groovy / Gradle | Gradle projects | Inherited support; dynamic resolution requires `optional.dynamic: "on"` |
| JavaScript / npm, Yarn | `package.json`, `package-lock.json`, `yarn.lock` | [Fixed] Standalone npm lockfiles and dependency graphs |
| JavaScript / pnpm | `pnpm-lock.yaml` | [Added] Layouts 5 / 6 / 9; directories handled by pnpm do not produce duplicate npm / Yarn graphs |
| .NET / NuGet | `packages.config`, `*.csproj`, `*.fsproj`, `*.vbproj`, `*.sln`, `project.assets.json` | [Added] PackageReference, version properties, central package management, and multi-target assets |
| Go | `vendor/modules.txt`, `go.mod`, `go.sum`, `Gopkg.lock` / `Gopkg.toml` | [Fixed] Module set selection and version parsing |
| Python, PHP, Ruby, Rust, Erlang | Their supported manifests / lockfiles | Inherited capabilities; see [upstream detection coverage](https://github.com/XmirrorSecurity/OpenSCA-cli/blob/master/.github/README.md#detection-ability) |
| SBOM | CycloneDX, SPDX, and other inherited formats | [Changed] Excluded from directory scans by default; explicit input is detected by format |

## Usage

### 1. Export dependencies and SBOMs [Added]

```sh
./opensca -path ./project -offline -deps-only -out bom.cdx.json,report.json
```

`bom.cdx.json` is CycloneDX; `report.json` is an OpenSCA native report containing task details and diagnostics. **The filename suffix selects the format: a plain `.json` file is not CycloneDX.** Omit `-offline` to allow network access during resolution while still skipping vulnerability lookup.

### 2. Local Maven resolution and profiles [Added / Changed]

```sh
./opensca -path ./java-project -offline -deps-only -maven-repo /data/m2/repository -maven-settings /data/m2/settings.xml -profiles 'prod,!test' -java-version 17 -out java.cdx.json,java-report.json
```

Local repository precedence: `-maven-repo` / `java.local_repository` → `MAVEN_REPO_LOCAL` → `localRepository` in the selected or default user `settings.xml` → `~/.m2/repository`. Prepare parent POMs, BOMs, and dependency metadata before an offline scan; inspect diagnostics when anything is missing.

To attempt dynamic Maven resolution, omit `-offline` and keep `optional.dynamic: "auto"` or set it to `"on"`. Select a custom executable with `-maven-command /path/to/mvn`. See [limitations](#migration-and-limitations) for dynamic profile behavior.

### 3. npm and pnpm lockfiles [Added / Fixed]

```sh
./opensca -path ./web/package-lock.json -offline -deps-only -out npm.cdx.json
./opensca -path ./web/pnpm-lock.yaml -offline -deps-only -out pnpm.cdx.json
```

Lockfiles work as standalone input. Directory scans can also use `package.json` for project metadata. pnpm links resolve to workspace project nodes, and peer contexts determine the corresponding dependency relationships.

### 4. NuGet / .NET [Added]

```sh
# Generate assets with the .NET SDK; this may access the network and update obj
dotnet restore ./dotnet-project/App.csproj
./opensca -path ./dotnet-project -offline -deps-only -out nuget.cdx.json,nuget-report.json

# A traditional packages.config can be read independently without dotnet
./opensca -path ./dotnet-project/packages.config -offline -deps-only -out packages.cdx.json
```

Project scans prefer usable `project.assets.json`. When assets are missing, stale, or invalid, non-offline `auto` / `on` modes attempt `dotnet restore`. Failure or disabled restore falls back to a static PackageReference inventory with an incomplete-resolution diagnostic. A static inventory does not replace a restored transitive graph; `packages.config` itself is a flat package inventory.

### 5. OSV integration [Changed]

```sh
./opensca -path ./project -offline -deps-only -out bom.cdx.json,report.json
# Inspect OpenSCA's exit code and diagnostics, then use an installed OSV-Scanner 2.x
osv-scanner scan source --lockfile bom.cdx.json --format json --output-file osv-result.json
```

No bridge or format conversion is required. The OSV command above can access the network. For a fully offline workflow, prepare OSV-Scanner's local databases and configure its offline options separately. OpenSCA's `-offline` controls OpenSCA only; vulnerability counts in a `-deps-only` report are not OSV findings.

### 6. Import an existing SBOM [Changed]

```sh
./opensca -path ./existing.cdx.json -input-type sbom -offline -deps-only -out imported.cdx.json,imported-report.json
```

In `auto` mode, an individual SBOM file can be detected automatically. Use `-input-type sbom` to scan SBOMs within a directory, or `-input-type project` to restrict input to project manifests.

### 7. Use inherited vulnerability lookup

```sh
# Configure a local vulnerability source under origin in config.local.json first
./opensca -path ./project -config config.local.json -out report.json,report.html

# Existing cloud service; obtain a token for a usable service separately
./opensca -path ./project -token YOUR_TOKEN -out report.json,report.html
```

For a local JSON vulnerability source, save this as `config.local.json`:

```json
{
  "origin": {"json": "./db-demo.json"}
}
```

JSON / MySQL / SQLite vulnerability sources and cloud configuration remain available; see [config.json](config.json) and [db-demo.json](db-demo.json). Omit `-deps-only` when querying vulnerabilities. `-offline` can be combined with a local vulnerability source and disables cloud access.

## Options and configuration

| Option | Status | Purpose |
| --- | --- | --- |
| `-path PATH` | Inherited | Input directory, manifest, or SBOM |
| `-out FILE[,FILE...]` | Inherited | One or more reports, selected by suffix |
| `-config FILE` | Inherited | Load configuration; explicitly supplied CLI values take precedence |
| `-offline` | [Added] | Disable networking and dynamic builds; local input only |
| `-deps-only` | [Changed] | Skip vulnerability lookup and SaaS upload |
| `-input-type auto\|project\|sbom` | [Added] | Automatic detection by default; directory scans exclude SBOMs |
| `-include-project` | [Added] | Add project modules to CycloneDX `components` |
| `-maven-repo PATH` | [Added] | Maven local repository |
| `-maven-settings FILE` | [Added] | Maven settings read by static resolution |
| `-maven-command PATH` | [Added] | Maven executable for dynamic resolution |
| `-profiles IDS` | [Added] | Comma-separated Maven profiles; `!id` disables a profile; quote the value |
| `-java-version VERSION` | [Added] | JDK version for static profile activation |
| `-cache-dir PATH` | [Added] | Metadata cache; overrides `OPENSCA_CACHE_DIR`, otherwise uses a user cache directory |
| `-token TOKEN` / `-proj ID` | Inherited | Cloud token and project ID |
| `-log FILE` / `-version` / `-help` | Inherited | Log path, version, and full option list |

Set `origin` and `optional` settings in a **configuration file**. The current CLI does not provide `-origin.*`, `-optional.*`, or `-dynamic` options. Dependency-only mode uses `-deps-only` or the `deps_only` config key. The former `-dependencies-only` and `dependencies_only` names are no longer accepted. Save this example as `config.offline.json` and use `-config config.offline.json`:

```json
{
  "offline": true,
  "deps_only": true,
  "input_type": "project",
  "cache_dir": "./.opensca-cache",
  "out": "bom.cdx.json,report.json",
  "optional": {
    "dynamic": "off",
    "progress": false,
    "dev": true,
    "ignore": ["build/", "dist/"]
  },
  "java": {
    "local_repository": "/data/m2/repository",
    "settings": "/data/m2/settings.xml",
    "profiles": ["prod", "!test"],
    "jdk": "17",
    "properties": {"env": "prod"}
  }
}
```

`auto` is the default: try Maven when available, and NuGet restore when usable assets are missing. `on` enables dynamic parsers; `off` uses static parsing only. `-offline` always disables dynamic builds. `java.properties` supplies user properties for static Maven resolution and profile activation. Use `/` or JSON-escaped `\\` in Windows paths.

## Output and diagnostics

| Suffix | Format / purpose | Notes |
| --- | --- | --- |
| `.cdx.json` / `.cdx.xml` | CycloneDX SBOM | [Fixed] Standard components and dependency graph; `.cdx.json` is recommended for OSV |
| `.spdx.json` / `.spdx` | SPDX JSON / tag-value | [Fixed] Document metadata, package references, PURLs, and relationships |
| `.json` / `.xml` | OpenSCA native report | In JSON, inspect `task_info.error` and `task_info.diagnostics` |
| `.html` / `.csv` / `.sqlite` / `.db` / `.sarif` | Existing presentation, database, and integration reports | Inherited support |
| `.swid.json` / `.swid.xml` / `.dsdx`, etc. | Other inherited outputs | See [save.go](cmd/format/save.go); `.spdx.xml` is not a standard SPDX output suitable for OSV |

[Added] CycloneDX exports diagnostics as `opensca:diagnostic` properties and task errors as `opensca:error`. Also retain a native JSON report to inspect damaged input, unresolved versions, dynamic fallbacks, and missing metadata.

| Exit code | Meaning | Recommended action |
| --- | --- | --- |
| `0` | Completed without completeness diagnostics | Check the selected mode to determine whether vulnerability lookup ran |
| `2` | Task failure, invalid offline input, or a detected report-write failure | Inspect errors and logs; partial reports may exist |
| `3` | Resolution diagnostics; results may be incomplete | Inspect diagnostics and supply missing metadata; do not interpret this as no dependencies or no vulnerabilities |

Exit codes are not based on vulnerability counts. Diagnostic and write-error coverage follows the current implementation; inherited output formats do not all have equivalent completeness validation.

## Migration and limitations

- **Update installation sources.** Upstream install scripts, Homebrew, Docker images, and IDE plugins do not establish that this fork's changes are included. Use this repository or its builds for this version.
- **Update automation.** Check exit codes and diagnostics even when an SBOM was written; handle `3` separately. Directory scans now exclude existing SBOMs, and Go no longer merges every historical `go.sum` entry, so component counts can decrease.
- **Prepare offline metadata.** Offline mode cannot populate repositories or caches. Missing Maven parent POMs / BOMs or unusable NuGet assets may yield incomplete results. Scanning a submodule without its parent in the scanned set or an available repository remains limited.
- **Distinguish static and dynamic Maven settings.** Static profiles support explicit selection, activeByDefault, and common JDK / OS / property / file conditions, without fully emulating Maven. The current dynamic path passes all declared profiles when `-profiles` is omitted; account for this when expecting native conditional activation. `-maven-repo`, `-maven-settings`, `-java-version`, and `java.properties` primarily serve static parsing and are not all forwarded to `mvn`.
- **Static NuGet parsing is not full MSBuild evaluation.** Use valid assets for complex conditions, imports, version ranges, and transitive dependencies. Automatic restore can access the network and update build artifacts.
- **Use validated interchange formats.** Prefer `.cdx.json` for OSV; SPDX JSON / tag-value scenarios are also covered in the compatibility tests. Components without valid PURLs carry a warning that matching may be incomplete.

## Validation and feedback

Focused dependency and format tests:

```sh
go test ./cmd/config ./cmd/format ./opensca/model ./opensca/sca/java ./opensca/sca/javascript ./opensca/sca/golang ./opensca/sca/nuget
go test . -run '^(TestOSVCompatibility|TestPackageLockSBOMOSV)$' -count=1
```

Without `OSV_SCANNER`, the second command skips external consumer checks while still testing local dependency and output assertions. See the [compatibility notes (Chinese)](OSV兼容输出与测试说明.md) and [NuGet restore test](nuget_restore_test.go) for external OSV checks and live NuGet restore validation.

Report issues in [this repository](https://github.com/winezer0/opensca/issues), including the version, command, input manifest, and diagnostics, after removing credentials. We acknowledge the upstream project and its contributors. This project retains the [Apache-2.0](LICENSE) license.
