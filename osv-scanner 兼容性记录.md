# OSV 兼容输出与测试说明

## 使用范围

OpenSCA 负责依赖解析和标准 CycloneDX 输出；OSV 扫描由用户独立执行。无需 bridge、格式转换程序或 OpenSCA 的漏洞库配置。

```powershell
go build -o opensca.exe .
.\opensca.exe -path C:\project -offline -deps-only -maven-repo C:\Users\windows\.m2\repository -out C:\reports\bom.cdx.json
osv-scanner scan source --lockfile C:\reports\bom.cdx.json
```

外部 scanner 的联网、离线数据库和漏洞结果由用户自行配置。以上 scanner 命令以 2.x CLI 为例。

## 本次修复

| 项目 | 行为 |
|---|---|
| CycloneDX 图 | 统一稳定 bom-ref，组件和边去重，保留根依赖与匿名容器下的依赖；组件排序稳定 |
| PURL | 使用 packageurl 库构造和解析；不把未知生态猜成 Maven，不把版本范围当成确定版本。CycloneDX 中无法生成有效 PURL 的依赖会附带 `opensca:diagnostic`，提示 OSV 匹配可能不完整 |
| SBOM 输入 | 目录扫描默认排除 SBOM；单文件或 `-input-type sbom` 显式导入；按格式识别，避免一个 JSON 被多个 SBOM parser 重复读取 |
| Maven 仓库 | `-maven-repo` / `java.local_repository` > `MAVEN_REPO_LOCAL` > 用户 settings.xml > `~/.m2/repository`；设置文件可通过 `-maven-settings` 指定 |
| 父 POM | 支持默认 `../pom.xml`、目录路径、显式空 relativePath 和属性版本；校验 group/artifact 及确定版本 |
| Profile | `-profiles a,!b`，支持 activeByDefault、常用 JDK 范围、OS family/arch、用户属性和文件条件；不支持的条件输出诊断。`java.properties` 提供用户属性，`-java-version` 指定 JDK |
| 工程模块 | Maven 工程节点显式标记；默认保留 application 节点与关系，工程子模块不带 PURL；`-include-project` 可包含。metadata 根节点保留项目身份 |
| 缓存 | `-cache-dir` / `cache_dir` > `OPENSCA_CACHE_DIR` > 系统用户缓存目录，不再写到安装目录 |
| 纯依赖输出 | `-deps-only` 跳过漏洞查询和 SaaS 报告上传，不需要 token |
| 离线与诊断 | `-offline` 禁止共享 HTTP client 联网并关闭动态构建；元数据缺失、未解析坐标、损坏或不支持版本的清单记录到诊断中。JSON 使用 `task_info.diagnostics`，CycloneDX 使用 `opensca:diagnostic` 属性 |
| 退出码 | 0：解析完成；2：任务或 CycloneDX 写入失败；3：存在解析诊断。退出码不代表漏洞扫描结果 |

静态解析不替代 Maven 的完整 effective model。精确 OS 名称/版本等尚未支持的激活条件会报告诊断，可显式选择 profile。没有锁文件或解析器时，不会凭空补出传递依赖或确定版本。

## 原有测试失败原因与处理

| 测试 | 原因 | 修复 |
|---|---|---|
| Python | Pipfile 实为 TOML，却用 JSON decoder；未锁定版本的 requirements/Pipfile 被期望解析出历史固定版本及传递树；动态路径还会在禁用时创建临时环境文件 | 改为 TOML，支持字符串与 table 格式、开发依赖；静态测试按文件实际信息断言，锁文件单独覆盖固定版本；动态禁用或离线时立即返回 |
| PHP | manifest 使用范围版本并查询实时 Packagist，发布新版本后预期漂移；旧预期遗漏共享依赖边 | 用 checked-in composer.lock 中的包构建本地 HTTP 仓库，仍执行真实版本选择流程；按锁文件补齐全部边 |
| Ruby / Rust | 测试遗漏共享依赖边，并受匿名 parser 根节点和树遍历顺序影响 | 根据 Gemfile.lock / Cargo.lock 补齐边；图断言比较节点与边集合，忽略无身份容器 |
| JavaScript | 旧树打印对已访问节点去重，隐藏 wrap-ansi 的两条共享边，原断言无法发现差异 | 补齐锁文件中的两条边；使用完整图断言，并新增断言自身的回归测试 |
| Java 静态 | 本次父 POM 校验直接比较未展开的 GAV，拒绝 `${revision}` 等有效身份 | 使用属性解析后的副本校验，保留未解析父属性的继承路径，仍拒绝不一致的确定坐标 |
| Java 动态 | 未安装 Maven 时扫描返回空图，测试仍套用静态 fixture 直接断言；真实下载还依赖外部仓库和本机环境 | 真实 Maven 集成测试需 `OPENSCA_TEST_LIVE_MAVEN=1`，显式启用但缺少 mvn 时失败；默认测试使用固定 Maven 输出覆盖 ANSI、EOF、模块边界、classifier、scope 和语言 |
| 日志包 | 非格式化日志 wrapper 的调用方式触发 go vet printf 检查 | 使用固定 `%s` 与 fmt.Sprint |

## 验证命令

```powershell
go test ./... -count=1 -timeout 120s
go test -race ./... -count=1 -timeout 120s
go vet ./...

# 默认运行：解析、PURL 和无效清单的诊断断言，不需要安装 osv-scanner
go test . -run TestOSVCompatibility -count=1 -v -timeout 100s

# 设置后还会运行外部消费者和固定 OSV 数据库命中/未命中检查
$env:OSV_SCANNER = 'C:\tools\osv-scanner.exe'
go test . -run TestOSVCompatibility -count=1 -v -timeout 100s

# 可选：本机需安装 Maven，并允许访问 fixture 所需仓库
$env:OPENSCA_TEST_LIVE_MAVEN = '1'
go test ./test/java -run Test_JavaWithMvn -count=1 -v -timeout 300s
```

兼容性测试即使未设置 `OSV_SCANNER`，也会构建 OpenSCA 并验证依赖解析与 PURL；设置变量后再调用真实 scanner，验证 SBOM 消费和固定 OSV 数据命中。固定测试库只用于格式和流程验收，不能作为真实漏洞覆盖率证明。

## 本机验证记录（2026-10-26）

### OpenSCA → CycloneDX → osv-scanner 场景矩阵

`osv_compatibility_test.go` 会构建 OpenSCA CLI、扫描临时项目并检查输出 PURL；设置 `OSV_SCANNER` 后会把 CycloneDX 交给外部 scanner 离线扫描。测试公告来自临时生成的本地 OSV 数据库，不依赖公开漏洞库，也不代表真实库的覆盖程度。

| 开发场景 | 输入 | 输出/OSV 验证 | 结果 |
|---|---|---|---|
| Maven 直接依赖 | POM + 本地 Maven 仓库 | log4j-core 2.14.1 命中，2.17.1 不命中 | 通过 |
| Maven 传递依赖 | app → wrapper → log4j-core | 两层组件与依赖边保留，OSV 命中传递组件 | 通过 |
| npm scoped 依赖 | package.json + lock v3 | `pkg:npm/%40acme/demo@1.2.3` 命中 | 通过 |
| npm workspace | 根 lockfile + `packages/app` 清单 | workspace 的 lodash PURL 与依赖边保留并命中 | 通过 |
| Yarn v1 | package.json + yarn.lock | lodash PURL 保留并命中 | 通过 |
| Gradle Groovy | build.gradle + 本地 Maven POM | Guava Maven PURL 保留并命中 | 通过 |
| Go module | go.mod | Go PURL 和 OSV 漏洞关联 | 通过 |
| Python 固定版本 | requirements.txt | PyPI PURL 和 OSV 漏洞关联 | 通过 |
| Composer | composer.json + composer.lock | Packagist PURL 和 OSV 漏洞关联 | 通过 |
| RubyGems | Gemfile.lock | gem PURL 和 OSV 漏洞关联 | 通过 |
| Cargo | Cargo.lock | crates.io PURL 和 OSV 漏洞关联 | 通过 |
| Cargo 多版本 | 同一个 lockfile 含 serde 1.0.188/1.0.200 | 两个独立 PURL 均输出，仅公告影响版本命中 | 通过 |
| pnpm v5/v6/v9 | pnpm-lock.yaml，可单独输入 | lodash PURL 保留并命中；固定库中不受影响版本不命中 | 通过 |
| pnpm workspace | 根/成员清单与 v9 锁文件 | 本地成员标记工程，传递/共享边与 lodash 多版本保留，OSV 命中传递依赖 | 通过 |
| NuGet packages.config | packages.config，可单独输入 | Newtonsoft.Json PURL 保留；固定库中受影响版本命中、不受影响版本不命中 | 通过 |
| NuGet assets | project.assets.json，可单独输入 | 使用已解析版本生成 PURL，固定 OSV 数据库命中 | 通过 |
| 无效 pnpm / NuGet 清单 | 缺失包引用、未锁定版本等 | CLI 返回 3，SBOM 明确提示依赖数据可能不完整 | 通过 |
| 无有效 PURL 的依赖 | 未映射语言的组件 | `opensca:diagnostic` 指明包身份且提示 OSV 匹配可能不完整 | 通过（格式单测） |

### 本轮联测发现并修复

- Go module 和 Composer 项目根最初未标记为工程节点，被误输出成无版本依赖并让任务错误返回 3。现已标记项目根并保留在 CycloneDX metadata。
- Cargo 解析曾用 crate 名作为唯一 key，同名多版本会互相覆盖；依赖引用携带 registry source 时也会污染版本字符串。现改用 name + version 区分组件，并从依赖引用提取具体版本。两个版本的外部扫描回归通过。
- 不同生态的组件身份都由 PURL 供 scanner 匹配。测试确认 `%40` scoped npm 名称和 Maven group/artifact 结构可命中对应公告。

- 外部 scanner 未设置时，依赖解析/PURL 场景仍执行；仅 scanner 命中断言跳过。pnpm 和 NuGet 已从“不支持诊断”升级为实际解析与 PURL 检查；无效清单另有诊断回归。
- 独立生态场景以直接依赖为主，另测 Maven 和 pnpm workspace 的传递依赖。没有验证各生态所有 lockfile 版本、平台条件或私有 registry 行为。

- 全量默认测试（`go test ./... -count=1`）：通过，同时显式启用并通过外部 OSV 兼容性测试。
- 全量竞态检查（`go test -race ./... -count=1`）：通过。
- `go vet ./...`、`git diff --check`：通过。
- 外部消费者：本机 osv-scanner 2.7.0，测试完全使用临时离线数据库。
- 真实 Maven 进程集成：本机没有 mvn，未启用；固定 Maven 输出解析回归和静态 POM 回归已通过。默认跳过该外部环境测试不代表真实 Maven 集成已验证。
- 原有 Java 静态和部分 JavaScript 用例仍会使用下载源/缓存，全量套件尚不是完全隔离的离线测试集。

## package-lock 独立输入修复与在线验证（2026-10-26）

沿用现有扫描入口，无需新增命令行参数。没有 package.json 时，从 package-lock.json 读取项目身份和锁定依赖；支持 lockfileVersion 1、2、3。v2/v3 使用 packages 条目解析实际安装位置，并纳入 workspace importer 及其依赖；workspace 成员也不要求保留 package.json。

本轮修复：
- 保留每个安装位置的节点身份，避免同名同版本包因来源文件相同而合并，确保不同分支的传递依赖版本都输出。
- workspace 从成员目录逐级查找依赖至根 node_modules，支持提升依赖和 workspace link。
- 共用运行时/开发依赖按锁文件的 dev 标记处理，避免被误判为仅开发依赖。
- 校验版本、根条目、空包记录、包版本、link 目标及必需依赖引用。无效锁文件报告解析失败或扫描不完整；有效空项目仍正常返回。

测试见 package_lock_osv_test.go 及 npm/JavaScript 解析器回归测试。在线测试命令（在各自仓库根目录运行）：

~~~powershell
$env:OSV_SCANNER = 'C:\Users\windows\Desktop\localsca\osv-scanner\osv-scanner.exe'
go test . -run '^TestPackageLockSBOMOSV$' -count=1 -v
~~~

| 场景 | 验证 | 本机结果 |
|---|---|---|
| v1 锁文件单独输入 | SBOM 输出 lodash 4.17.21，OSV 保留对应 PURL | 通过 |
| v2/v3 嵌套依赖，无 package.json | 同名同版本 common 位于不同位置，分别保留 lodash 4.17.20、4.17.21 | 通过 |
| v3 成对输入 | 保留上述两个版本，验证原有输入流程 | 通过 |
| v2/v3 workspace，仅一个锁文件 | 无根/成员清单仍输出成员的 lodash 依赖 | 通过 |
| 开发/运行时共享依赖 | shared 保持运行时属性，dev-tool 保持开发属性 | 解析回归通过 |
| 未知版本、缺失根、null 包、未解析必需依赖、损坏 JSON | CLI 非零退出，SBOM 明确标记依赖数据可能不完整 | 通过 |
| 有效空项目 | 无依赖时正常返回，不误报损坏 | 解析回归通过 |

本轮外部扫描使用在线 OSV 服务，不依赖本机数据库缓存。断言 OSV 保留所有预期 PURL，并确认 lodash 4.17.20 有漏洞记录；不将 4.17.21 的线上漏洞数量写死。原有固定数据库测试仍用于可重复的格式验证。

v1 没有现代 packages 根清单信息，独立输入时会以锁内顶层条目作为扫描起点；包名、版本可以输出，但直接/传递关系不能保证与丢失的原始清单完全一致。

workspace 成员标记为本地工程，默认不输出其公共 npm PURL；其外部依赖和依赖边仍保留，避免将本地成员误当作 registry 包扫描。

本轮全量默认测试通过：127 项 / 31 个包。最后调整 workspace 工程标记后，相关解析器、JavaScript 场景和根包测试再次通过（70 项），v2/v3 workspace 在线 OSV 用例再次通过。

## pnpm 与 NuGet 解析接入（2026-10-26）

参考 MurphySec 的 pnpm v5/v6/v9 清单布局与 NuGet `packages.config` 读取方式，直接适配 OpenSCA 的扫描注册、语言/PURL 映射及依赖图；无需安装 pnpm、npm、NuGet 或 dotnet，也不增加命令行参数。

- pnpm：支持单独锁文件与配对清单；读取 dependencies、devDependencies、optionalDependencies；v9 用 snapshots 建关系、packages 校验身份；保留 peer 上下文、scoped 包、别名、workspace link、共享依赖、循环边和同名多版本。workspace 成员标记为本地工程，默认不带公共 npm PURL。有效空项目正常结束。workspace 范围外的嵌套独立 npm 项目仍正常解析。
- NuGet：读取已安装包的确定版本，按包名不区分大小写去重，保留不同版本；developmentDependency 接入 OpenSCA 的开发依赖开关。`packages.config` 只提供平面包清单，因此输出项目到包的关系，不推断包之间的传递关系。
- 诊断：损坏 YAML/XML、缺失包/快照元数据、无效版本、无法解析的 workspace 链接、未知锁格式和不支持的包来源明确报告扫描不完整。无效 pnpm 锁文件会阻止其项目回退到 npm registry，避免产生看似完整的结果。
- 初次接入只支持 `packages.config`；后续已补上 `.csproj` / solution、`dotnet restore` 和 `project.assets.json`，见下一节。`packages.lock.json`、pnpm 本地 file/tarball 与 Git 包来源仍未完整接入。固定 OSV 测试公告不代表公开漏洞库的实际覆盖。

测试入口：`opensca/sca/javascript/pnpm_test.go`、`opensca/sca/nuget/sca_test.go`、`opensca/model/language_test.go` 和 `osv_compatibility_test.go`。后者实际构建 CLI，并把输出 CycloneDX 交给真实 osv-scanner；固定离线数据库覆盖命中和未命中，workspace 场景同时检查传递边、开发依赖共享边与多版本 PURL。

本轮验收结果：

| 检查 | 结果 |
|---|---|
| `go test ./... -count=1 -timeout 180s`，设置 `OSV_SCANNER` 为本机真实可执行文件 | 通过，包含 CLI / CycloneDX / OSV 联测 |
| 清除 `OSV_SCANNER` 后运行 `go test . -run '^TestOSVCompatibility$' -count=1 -timeout 120s` | 通过，依赖解析、PURL、workspace 与无效清单诊断仍执行 |
| `go test -race ./opensca/sca/javascript ./opensca/sca/nuget ./opensca/model -count=1 -timeout 120s` | 通过，69 项测试 |
| `go vet ./...` | 通过 |
| `gofmt -l` 检查本轮 Go 文件、`git diff --check` | 通过 |

固定库中的 lodash 4.17.21 / Newtonsoft.Json 13.0.1 为人为指定的受影响版本，4.17.20 / 13.0.2 为未命中对照；该设定仅检验匹配流程，与真实公开漏洞状态无关。

## NuGet 项目与自动 restore（2026-10-26）

已参考 MurphySec 的 restore 流程接入 `.csproj`、`.fsproj`、`.vbproj` 和 `.sln`。solution 输入会列出受支持的成员项目，按项目解析并复用已生成的资产文件。扫描 `project.assets.json` 单文件也可直接输出依赖。

默认 `optional.dynamic: "auto"`，无需增加参数：

1. 优先读取已有 `obj/project.assets.json`，也支持项目中能静态确定的 `MSBuildProjectExtensionsPath` / `BaseIntermediateOutputPath`。资产文件早于项目或最近的 `Directory.Build.props` / `Directory.Packages.props` 时，尝试重新 restore。
2. 缺失、过期或无效且允许动态解析时，查找 PATH 中的 dotnet，执行 `dotnet restore <项目> --verbosity minimal --disable-parallel -p:NuGetAudit=false`。受扫描 context 和单项目两分钟超时限制；关闭 NuGet Audit 是为了让此流程只恢复依赖。
3. restore 成功后读取 SDK 实际解析产物。若 SDK 的增量 restore 判断依赖未变，没有重写 assets 的时间戳，也接受已验证的产物。
4. `-offline` 或 `dynamic:off` 禁止执行 restore，但可正常读取有效的已有 assets。SDK 缺失、restore 失败或产物无效时，输出静态 PackageReference / ProjectReference 清单并明确诊断扫描不完整（退出码 3）。

解析结果：

- 支持 assets 格式版本 3 和 4。真实 SDK 8 使用长目标框架名称（如 `.NETStandard,Version=v2.1`），SDK 10 使用短 TFM；已统一匹配项目框架及 RID 上下文。
- 从 targets / libraries 读取确定版本，保留直接与传递依赖、共享依赖边、多框架/RID 下的多版本；不会把 RequestedVersion 当成 ResolvedVersion。集中版本管理、条件包引用和项目引用的准确结果由 SDK/MSBuild 计算。
- ProjectReference 节点标为本地工程，默认不附公共 NuGet PURL；其外部包和关系仍保留。`PrivateAssets="all"` 的包仍属于本项目依赖，不据此直接剔除。
- 静态回退只解析可识别的属性和无条件引用，不模拟完整 MSBuild。NuGet 的裸版本 `1.0.0` 是最低版本约束，只有 `[1.0.0]` 这种单点范围才可静态认定为精确版本；其他请求保持版本未知，避免生成错误 PURL。

真实集成测试：

```powershell
$env:OPENSCA_TEST_LIVE_DOTNET = '1'
$env:OSV_SCANNER = 'C:\Users\windows\Desktop\localsca\osv-scanner\osv-scanner.exe'
go test . -run '^TestNuGetLiveRestore$' -count=1 -v -timeout 300s
```

`nuget_restore_test.go` 为每个已安装的 SDK 主版本创建临时本地 nupkg 源，清除远端源并隔离包缓存，实际运行 OpenSCA CLI → dotnet restore → assets → CycloneDX → 真实 osv-scanner。本机 SDK 8.0.422、10.0.301 均已通过。验证包括：

- 首次自动 restore，含空格路径、`Directory.Packages.props`、项目引用、多目标框架和 `PrivateAssets`。
- 请求 Wrapper `[1.0.0,2.0.0)`，实际输出 Wrapper 1.1.0；同一 Local.Extra 包在不同框架分别输出 1.0.0、2.0.0。
- Wrapper → Leaf 与 Child → Leaf 两条共享边保留，本地 Child 不被误当成公共 NuGet 包。
- 已有 assets 的离线复用、solution 输入、集中版本修改后的重新恢复，以及缺失包导致真实 restore 失败时的 SBOM 诊断。
- 固定 OSV 数据库命中 Local.Leaf 传递依赖，并保留全部预期 PURL。

默认测试不要求安装 SDK：`project_test.go` 覆盖已有产物、自动调用/禁用/失败、版本不确定性、框架/RID、项目引用和损坏产物；原 `TestOSVCompatibility` 也新增 assets 单文件真实 CLI / OSV 场景。真实 SDK 测试只有显式设置上述变量才执行，显式启用但 SDK 缺失时会失败。

边界：现有 assets 表示最近一次 restore 的快照；上述时间戳检查不等价于完整 MSBuild 输入追踪。复杂自定义导入或输出目录无法静态确定时，可能需要先自行 restore。`packages.lock.json` 与 `.slnx` 尚未作为扫描入口；未验证所有历史 SDK、私有源认证或工作负载。固定本地包和 OSV 公告用于可重复验收，不代表公开漏洞库覆盖率。

本轮最终验收：

| 检查 | 结果 |
|---|---|
| 同时设置 `OPENSCA_TEST_LIVE_DOTNET=1`、`OSV_SCANNER` 后执行 `go test ./... -count=1 -timeout 300s` | 全量通过，含 SDK 8/10、本地真实 restore、solution、配置更新、失败诊断及真实 OSV 联测 |
| `go test -race ./opensca/sca/nuget ./opensca/model -count=1 -timeout 120s` | 38 项测试通过 |
| 未设置两个外部测试变量时运行 `TestOSVCompatibility` | 通过，依赖解析、assets 和无效清单诊断仍执行 |
| `go vet ./...`、`gofmt -l`、`git diff --check` | 通过 |
