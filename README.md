# OpenSCA

**原项目 README：** [中文 README](https://github.com/XmirrorSecurity/OpenSCA-cli/blob/master/README.md) · [English README](https://github.com/XmirrorSecurity/OpenSCA-cli/blob/master/.github/README.md)

**新版文档：** 中文 · [English](README.en.md)

本项目是 [XmirrorSecurity/OpenSCA-cli](https://github.com/XmirrorSecurity/OpenSCA-cli) 的修改版，维护于 [winezer0/opensca](https://github.com/winezer0/opensca)。在原有依赖分析、漏洞查询和报告能力上，重点增加本地与离线解析，修复依赖图和标准 SBOM 输出，并增加 pnpm、NuGet 支持。

本文对应本仓库当前实现。**【新增】、【修改】、【修复】均相对于仓库导入的原版快照**；旧版 README、[中文手册](docs/README-zh-CN.md)和[英文手册](docs/README.md)保留作历史参考，安装地址、参数和行为以本文为准。

## 导航

- [与原项目的差异](#与原项目的差异)
- [安装与快速开始](#安装与快速开始)
- [支持的输入](#支持的输入)
- [新版用法](#新版用法)
- [参数与配置](#参数与配置)
- [输出与诊断](#输出与诊断)
- [迁移说明与限制](#迁移说明与限制)
- [验证与反馈](#验证与反馈)

## 与原项目的差异

| 标记 | 功能 | 原版行为 | 本版变化与使用方式 |
| --- | --- | --- | --- |
| 【新增】 | 离线模式 | 缺少统一的离线控制 | `-offline` 禁用网络访问和动态构建；只接受本地输入，使用本地仓库与已有缓存 |
| 【变更】 | 仅依赖分析 | 原参数较长 | 使用 `-deps-only` 跳过漏洞查询和 SaaS 报告上传，可免 token 导出依赖报告；配置键为 `deps_only`；需要完全离线时再加 `-offline` |
| 【新增】 | pnpm | 无锁文件解析器 | 直接解析 `pnpm-lock.yaml` 的 5、6、9 版布局，处理 workspace、optional dependencies 和 peer 上下文，无需运行 pnpm |
| 【新增】 | NuGet / .NET | 无对应生态解析器 | 支持 `packages.config`、C#/F#/VB 项目、解决方案及 `project.assets.json`；优先使用有效 assets，必要时可调用 `dotnet restore` |
| 【修改】 | 动态解析 | 布尔开关 | `optional.dynamic` 改为 `auto` / `on` / `off`，兼容旧 `true` / `false`；默认 `auto` 可尝试 Maven、NuGet，其他动态解析器仍需 `on` |
| 【新增】 | Maven 本地配置 | 缺少本地仓库选择 | 增加 `-maven-repo`、`-maven-settings`、`-maven-command`、`-profiles`、`-java-version`；缓存目录支持 `-cache-dir` |
| 【修复】 | Maven 静态解析 | 父 POM、本地解析及 profile 激活存在缺漏 | 补充本地仓库解析、父 POM 路径和版本处理、profile 条件判断；无法完整解析时保留诊断，见下方限制 |
| 【修复】 | npm 锁文件 | 单独输入锁文件可能无结果，嵌套依赖图可能丢失 | 支持无 `package.json` 的 `package-lock.json` v1/v2/v3，保留嵌套多版本、workspace 及开发/运行时依赖关系 |
| 【修复】 | Go 依赖选择 | 将 `go.sum` 的历史版本混入当前依赖，重复扫描 vendor 内清单 | 静态解析优先 `vendor/modules.txt`，其次 `go.mod`，`go.sum` 仅兜底；修复 `replace`、单行语句及 `+incompatible` 版本处理 |
| 【修复】 | CycloneDX | 组件重复、引用与依赖边不一致 | 稳定引用、组件和边去重，保留根依赖；工程节点默认不列入 `components`，可用 `-include-project` 加入 |
| 【修复】 | SPDX / PURL | 文档字段、包引用或包身份可能不被消费者接受 | 修复 SPDX JSON 与 tag-value 文档，统一 PURL 生成；无法确定生态或具体版本时报告诊断 |
| 【修改】 | SBOM 输入 | 扫描目录可能把已有 SBOM 再算一次 | 默认目录扫描排除 SBOM；单文件输入可自动识别，也可用 `-input-type sbom` 显式导入 |
| 【新增】 | 完整性诊断 | 降级、跳过和未解析依赖不够直观 | 报告记录诊断，CLI 区分成功、失败和不完整；不能把“输出了 SBOM”视为“完整解析或无漏洞” |

实现与兼容性测试说明见 [OSV 兼容输出与测试说明](OSV兼容输出与测试说明.md)。OpenSCA 负责依赖解析及 SBOM 输出；对接 OSV 时由用户独立运行 `osv-scanner`，本项目不会代为管理 OSV 数据库或合并其漏洞结果。

## 安装与快速开始

从[本仓库 Releases](https://github.com/winezer0/opensca/releases)选择所需平台的构建；若没有适用构建，从源码编译。构建要求 **Go 1.25 或更高版本**，以 [go.mod](go.mod) 为准。

```sh
git clone https://github.com/winezer0/opensca.git
cd opensca
go build -o opensca .
./opensca -version
./opensca -path ./example -offline -deps-only -out bom.cdx.json,report.json
```

Windows PowerShell：

```powershell
git clone https://github.com/winezer0/opensca.git
cd opensca
go build -o opensca.exe .
.\opensca.exe -version
.\opensca.exe -path .\example -offline -deps-only -out bom.cdx.json,report.json
```

下文以 `./opensca` 为例，Windows 改为 `.\opensca.exe`。仅解析依赖不需要云平台 token；构建下载 Go 模块、在线依赖解析及外部漏洞扫描的网络需求分别配置。

## 支持的输入

除目录外，可通过 `-path` 指定单个清单或 SBOM。原有压缩包扫描能力保留。

| 生态 / 类型 | 主要输入 | 本版备注 |
| --- | --- | --- |
| Java / Maven | `pom.xml` | 【修改】本地仓库、profile 和动态 Maven 解析控制 |
| Groovy / Gradle | Gradle 工程 | 沿用原有解析能力；动态解析需 `optional.dynamic: "on"` |
| JavaScript / npm、Yarn | `package.json`、`package-lock.json`、`yarn.lock` | 【修复】npm 锁文件单独输入及依赖图 |
| JavaScript / pnpm | `pnpm-lock.yaml` | 【新增】锁文件布局 5 / 6 / 9；同目录由 pnpm 解析后不再重复生成 npm / Yarn 图 |
| .NET / NuGet | `packages.config`、`*.csproj`、`*.fsproj`、`*.vbproj`、`*.sln`、`project.assets.json` | 【新增】PackageReference、版本属性、中央包管理及多目标框架 assets |
| Go | `vendor/modules.txt`、`go.mod`、`go.sum`、`Gopkg.lock` / `Gopkg.toml` | 【修复】依赖集合选择及版本解析 |
| Python、PHP、Ruby、Rust、Erlang | 对应清单 / 锁文件 | 保留原有能力，范围见[原项目检测能力](https://github.com/XmirrorSecurity/OpenSCA-cli/blob/master/README.md#检测能力) |
| SBOM | CycloneDX、SPDX 等原有支持格式 | 【修改】目录默认排除；显式输入按格式识别 |

## 新版用法

### 1. 仅导出依赖与 SBOM【新增】

```sh
./opensca -path ./project -offline -deps-only -out bom.cdx.json,report.json
```

`bom.cdx.json` 是 CycloneDX，`report.json` 是 OpenSCA 原生报告，含任务信息与诊断。**文件名后缀决定格式：普通 `.json` 不是 CycloneDX。** 去掉 `-offline` 可允许依赖解析联网，仍不查询漏洞。

### 2. Maven 本地解析与 profile【新增 / 修改】

```sh
./opensca -path ./java-project -offline -deps-only -maven-repo /data/m2/repository -maven-settings /data/m2/settings.xml -profiles 'prod,!test' -java-version 17 -out java.cdx.json,java-report.json
```

本地仓库选择顺序：`-maven-repo` / `java.local_repository` → `MAVEN_REPO_LOCAL` → 指定或用户默认 `settings.xml` 中的 `localRepository` → `~/.m2/repository`。离线扫描前需准备父 POM、BOM 和依赖元数据；缺失时应检查诊断。

若希望尝试动态 Maven 解析，去掉 `-offline`，保持 `optional.dynamic: "auto"` 或设为 `"on"`；自定义命令可用 `-maven-command /path/to/mvn`。动态路径的 profile 行为见[限制](#迁移说明与限制)。

### 3. npm 与 pnpm 锁文件【新增 / 修复】

```sh
./opensca -path ./web/package-lock.json -offline -deps-only -out npm.cdx.json
./opensca -path ./web/pnpm-lock.yaml -offline -deps-only -out pnpm.cdx.json
```

锁文件可单独输入；扫描整个目录时可结合 `package.json` 补充工程信息。pnpm 的链接会映射到 workspace 工程节点，peer 上下文用于解析对应依赖关系。

### 4. NuGet / .NET【新增】

```sh
# 先由 .NET SDK 生成 assets；此步骤可能联网并更新项目的 obj 目录
dotnet restore ./dotnet-project/App.csproj
./opensca -path ./dotnet-project -offline -deps-only -out nuget.cdx.json,nuget-report.json

# 传统 packages.config 也可独立读取，无需 dotnet
./opensca -path ./dotnet-project/packages.config -offline -deps-only -out packages.cdx.json
```

扫描项目时优先读取有效的 `project.assets.json`。缺失、过期或不可用时，非离线的 `auto` / `on` 模式会尝试 `dotnet restore`；失败或被禁用则回退到静态 PackageReference 清单并标记不完整。静态清单不能代替恢复后的完整传递依赖图；`packages.config` 本身仅提供扁平包清单。

### 5. 对接 OSV【修改】

```sh
./opensca -path ./project -offline -deps-only -out bom.cdx.json,report.json
# 检查 OpenSCA 的退出码和诊断后，再由已安装的 OSV-Scanner 2.x 扫描
osv-scanner scan source --lockfile bom.cdx.json --format json --output-file osv-result.json
```

无需 bridge 或格式转换。以上 OSV 命令可联网；若需全流程离线，须另行准备 OSV-Scanner 的本地数据库并配置其离线参数。OpenSCA 的 `-offline` 只控制 OpenSCA；`-deps-only` 输出中的漏洞数量不代表 OSV 扫描结果。

### 6. 显式读取已有 SBOM【修改】

```sh
./opensca -path ./existing.cdx.json -input-type sbom -offline -deps-only -out imported.cdx.json,imported-report.json
```

`auto` 模式下单个 SBOM 文件可自动识别；目录中需要扫描 SBOM 时显式使用 `-input-type sbom`。使用 `-input-type project` 可限定为工程清单。

### 7. 沿用原有漏洞查询

```sh
# 原有本地漏洞库：先在 config.local.json 的 origin 中配置来源
./opensca -path ./project -config config.local.json -out report.json,report.html

# 原有云平台查询，需要自行取得可用服务的 token
./opensca -path ./project -token YOUR_TOKEN -out report.json,report.html
```

本地 JSON 漏洞库示例，保存为 `config.local.json`：

```json
{
  "origin": {"json": "./db-demo.json"}
}
```

原有 JSON / MySQL / SQLite 漏洞源和云平台配置保留，字段见 [config.json](config.json) 与 [db-demo.json](db-demo.json)。执行漏洞查询时不要添加 `-deps-only`；`-offline` 可配合本地漏洞库使用，会禁用云端访问。

## 参数与配置

| 参数 | 标记 | 说明 |
| --- | --- | --- |
| `-path PATH` | 原有 | 输入目录、清单或 SBOM 路径 |
| `-out FILE[,FILE...]` | 原有 | 按文件后缀输出一个或多个报告 |
| `-config FILE` | 原有 | 加载配置；命令行指定的同名项优先 |
| `-offline` | 【新增】 | 禁用网络和动态构建，仅接受本地输入 |
| `-deps-only` | 【变更】 | 跳过漏洞查询与 SaaS 上传 |
| `-input-type auto\|project\|sbom` | 【新增】 | 默认自动识别，目录默认排除 SBOM |
| `-include-project` | 【新增】 | 将工程模块也加入 CycloneDX `components` |
| `-maven-repo PATH` | 【新增】 | Maven 本地仓库 |
| `-maven-settings FILE` | 【新增】 | 静态解析读取的 Maven settings 文件 |
| `-maven-command PATH` | 【新增】 | 动态解析使用的 Maven 可执行文件 |
| `-profiles IDS` | 【新增】 | 逗号分隔的 Maven profile；`!id` 表示禁用，建议加引号 |
| `-java-version VERSION` | 【新增】 | 静态 profile JDK 激活条件使用的版本 |
| `-cache-dir PATH` | 【新增】 | 依赖元数据缓存，优先于 `OPENSCA_CACHE_DIR`，默认位于用户缓存目录 |
| `-token TOKEN` / `-proj ID` | 原有 | 云平台 token 与项目 ID |
| `-log FILE` / `-version` / `-help` | 原有 | 日志、版本、完整参数列表 |

`origin` 和 `optional` 下的选项通过**配置文件**设置，当前 CLI 不提供 `-origin.*`、`-optional.*` 或 `-dynamic` 参数。仅依赖模式使用 `-deps-only` 或配置键 `deps_only`；旧名称 `-dependencies-only` / `dependencies_only` 已停用。示例保存为 `config.offline.json` 后使用 `-config config.offline.json`：

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

`auto` 是默认模式，Maven 可用时尝试动态解析，NuGet 缺少可用 assets 时尝试 restore；`on` 启用动态解析器；`off` 仅静态解析。`-offline` 始终禁用动态构建。`java.properties` 为静态 Maven 属性与 profile 判断提供用户属性。Windows 配置路径请用 `/` 或 JSON 转义的 `\\`。

## 输出与诊断

| 后缀 | 格式 / 用途 | 备注 |
| --- | --- | --- |
| `.cdx.json` / `.cdx.xml` | CycloneDX SBOM | 【修复】标准组件与依赖图；推荐 `.cdx.json` 对接 OSV |
| `.spdx.json` / `.spdx` | SPDX JSON / tag-value | 【修复】文档头、包引用、PURL 与关系 |
| `.json` / `.xml` | OpenSCA 原生报告 | JSON 中查看 `task_info.error` 和 `task_info.diagnostics` |
| `.html` / `.csv` / `.sqlite` / `.db` / `.sarif` | 原有展示、数据库与集成报告 | 沿用原有能力 |
| `.swid.json` / `.swid.xml` / `.dsdx` 等 | 其他原有输出 | 具体分派见 [save.go](cmd/format/save.go)；`.spdx.xml` 不属于可供 OSV 使用的标准 SPDX 输出 |

【新增】CycloneDX 的诊断通过 `opensca:diagnostic` 属性输出，任务错误通过 `opensca:error` 输出。建议同时保存原生 JSON，检查输入损坏、版本不确定、动态解析回退、元数据缺失等问题。

| 退出码 | 含义 | 使用建议 |
| --- | --- | --- |
| `0` | 流程完成，未产生完整性诊断 | 仍需按所选模式判断是否执行了漏洞查询 |
| `2` | 任务失败、离线输入不合法或已检测到的报告写入失败 | 检查错误和日志；可能仍有部分报告 |
| `3` | 有解析诊断，结果可能不完整 | 检查诊断并补齐依赖元数据；不要当作“无依赖”或“无漏洞” |

退出码不以漏洞数量为依据。诊断和写入错误的覆盖范围以当前实现为准，不应假定所有旧输出格式都具备同等完整性校验。

## 迁移说明与限制

- **更新安装来源。** 旧版的一键安装、Homebrew、Docker 和 IDE 插件入口属于原项目，不能据此认定已包含本仓库修改；本版使用上文仓库或构建。
- **更新自动化判断。** SBOM 文件生成后仍要检查退出码和诊断；`3` 需要单独处理。目录默认忽略已有 SBOM，Go 不再把 `go.sum` 全量历史条目并入依赖，组件数量可能减少。
- **准备离线数据。** 离线不会自动补齐本地仓库或缓存；Maven 父 POM / BOM 缺失、NuGet assets 不可用时，结果可能不完整。仅扫描子模块且父 POM 不在扫描集合或可用仓库中，仍存在解析限制。
- **区分 Maven 静态与动态配置。** 静态 profile 支持显式启停、activeByDefault、常用 JDK / OS / 属性 / 文件条件，不能完整模拟 Maven。当前动态 Maven 路径未指定 `-profiles` 时会将所有已声明 profile 传给 Maven；需要原生条件激活时应注意该差异。`-maven-repo`、`-maven-settings`、`-java-version`、`java.properties` 主要用于静态解析，不能假定全部透传给 `mvn`。
- **NuGet 静态解析不等于完整 MSBuild 求值。** 复杂条件、导入、版本范围及传递依赖以有效 assets 为准；允许自动 restore 时可能联网并更新项目构建产物。
- **优先选用已验证的交换格式。** 对接 OSV 使用 `.cdx.json`，也可参考测试中的 SPDX JSON / tag-value 场景；缺少有效 PURL 的组件会提示匹配可能不完整。

## 验证与反馈

依赖解析和格式相关的针对性测试：

```sh
go test ./cmd/config ./cmd/format ./opensca/model ./opensca/sca/java ./opensca/sca/javascript ./opensca/sca/golang ./opensca/sca/nuget
go test . -run '^(TestOSVCompatibility|TestPackageLockSBOMOSV)$' -count=1
```

第二条命令未设置 `OSV_SCANNER` 时会跳过外部消费者检查，仍验证本地依赖与输出断言；外部 OSV 检查和实际 NuGet restore 验证方式见[兼容性测试说明](OSV兼容输出与测试说明.md)及 [NuGet restore 测试](nuget_restore_test.go)。

问题反馈请到[本仓库 Issues](https://github.com/winezer0/opensca/issues)，附版本、命令、输入清单和诊断信息，提交前移除凭据。原项目及贡献者的工作在此致谢；本项目沿用 [Apache-2.0](LICENSE) 许可证。
