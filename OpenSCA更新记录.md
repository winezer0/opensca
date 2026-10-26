# OpenSCA 更新记录（相对原版）

> **基线**：`master` / `15e5191`（import-snapshot，两者代码完全一致，取自上游 `XmirrorSecurity/opensca-cli`）
> **当前**：`main` 分支
> **规模**：相对导入快照，14 个后续 commit、83 个文件，+5945 / −1048（截至 `43cca99`）。
> **目的**：让 OpenSCA 解析出的依赖清单可直接交给 `osv-scanner --offline` 做离线漏洞扫描，
> 且漏洞库、漏洞匹配逻辑完全留在本地。
> **记录时间**：2026-10-26

---

## 一、总览

| 类别 | 条数 | 涉及模块 |
|---|---|---|
| Bug 修复 | 13 | Maven（6）、Go（5）、SPDX（1）、npm（1） |
| 新增功能 | 8 | 原有六项，加 pnpm 锁文件解析、NuGet 依赖解析 |
| 测试 / 文档 / 工具链 | — | OSV 兼容性、pnpm / NuGet 测试、文档迁移、`.gitignore` 与发布 CI |

> 计数按**问题条数**统计，不是 commit 数：几个问题合在同一个 commit 里（如 `962194c` 一次修了 O1–O6）。
> commit 与问题的对应见 §六。
>
> pnpm 与 NuGet 支持已由 `9dcd9fd` 提交；发布工作流修复见 `43cca99`。

修复效果：

| 项 | 原版 | 现在 |
|---|---|---|
| 同一工程的 CycloneDX 组件数（8 个唯一包） | 45 个 component | 8 个 |
| Go 工程（inott-epg-go，`go.mod` 67 require） | **498 组件 / 187 漏洞** | **67 / 35** |
| SPDX tag-value 输出 | osv-scanner 解析失败 | 67 包 / 35 漏洞 |
| 扫描目录里有 SBOM 文件 | 被当依赖重读，组件数从 9 膨胀到 111 | 忽略，不影响结果 |

---

## 二、Bug 修复

### 2.1 Maven 解析

#### O1 · CycloneDX 输出组件重复

**原版行为**：8 个唯一包被写成 45 个 `component`。原因是按「遍历到的节点」逐个追加，
没有按 `bom-ref` 去重；同时 `bom-ref` 与 `dependencies.ref` 的命名空间不一致，
消费者按 ref 对不上关系。另外 purl 由手写字符串拼接，部分生态缺 namespace。

**修复**：按 `bom-ref` 去重、排序输出；purl 统一走 packageurl 库构造；
工程自身不进 `components`（放在 `metadata.component`）。

**commit**：`962194c`

#### O2 · 扫描目录内的 SBOM 文件被当依赖重读

**原版行为**：扫描器会匹配目录里所有 `.json`/`.xml` SBOM 文件并当依赖清单解析。
如果输出目录在工程内，第二次扫描会把上一次的结果读进来，组件数翻倍。
降级分支不设置 `Language`，拼出的 purl 是 `pkg:/name@ver`（缺 type），属于非法 purl，
osv-scanner 会静默丢弃。

**修复**：新增 `-input-type`（`auto`/`project`/`sbom`），目录扫描时默认不加载 SBOM；
`sca/sbom/cdx.go` 补上 `dep.Language`，按 purl 表反查生态。

**commit**：`962194c`

#### O3 · 完全没有 `localRepository` 支持

**原版行为**：全库搜 `localRepository` / `.m2` / `M2_HOME` **零匹配**。取 pom 只有两条路：
自建的 `.opensca-cache/maven/` 和 HTTP。隔离网环境里父 pom、私有依赖全部解析不到。

**修复**：新增 `opensca/sca/java/local.go`，读 `settings.xml` 的 `<localRepository>`、
环境变量、`~/.m2/repository`，按 groupId/artifactId/version 从本地仓库直接取 pom；
新增 `-maven-repo` / `-maven-settings` 参数可显式指定。

**commit**：`962194c`

#### O4 · `relativePath` 只在「已被扫描的 pom 集合」内生效

**原版行为**：`relativePath` 的去向只在 `PathMap`（本次扫描到的那批 pom）里查。
只扫子模块时父 pom 不在集合内，8 个包会掉到 2 个。

**修复**：本地仓库兜底（O3）之后，父 pom 可以从 `~/.m2` 取到，夹具实测已对齐。

**状态**：⚠️ **部分修复**。relpath 夹具通过（1/1），但该夹具的父 pom 同时存在于 `~/.m2`，
无法区分究竟是 `relativePath` 还是本地仓库兜底生效。**根因未消除**：
只扫子模块、且父 pom 既不在 `PathMap` 也不在任何仓库时，依然会丢。

**commit**：`962194c`

#### O5 · profile 只取 `profiles[0]`，忽略 `<activation>`

**原版行为**：`pom.go` 里写死只取第一个 profile，完全不看 `<activation>`。
JDK / OS / property / activeByDefault 一律忽略。JDK 21 上把 `<jdk>1.8</jdk>` 的 profile
当成激活，报出错误依赖。

**修复**：新增 `opensca/sca/java/profiles.go`（259 行），完整实现 activation 判定：
`activeByDefault`、`<jdk>`（含版本区间如 `[17,)`）、`<os>`（name/family/arch/version）、
`<property>`、`<file>`（exists/missing）。显式激活用 `-profiles a,b`、禁用用 `-profiles '!c'`；
无法判定的条件（如需要用户环境变量的 property）会写进诊断。

**commit**：`962194c`

#### O6 · 缓存目录绑定可执行文件位置

**原版行为**：缓存目录取自 `filepath.Dir(os.Executable())`，即 `.opensca-cache` 落在可执行文件旁边。
多用户、容器、只读安装目录场景下不可用，也无法共享。

**修复**：改用 `os.UserCacheDir()/opensca`，可用 `-cache-dir` 或 `OPENSCA_CACHE_DIR` 覆盖。

**commit**：`962194c`

### 2.2 Go 解析

原版 Go 解析对 `inott-epg-go` 报出 498 组件 / 187 漏洞（真值 67 / 35）。五个独立缺陷：

#### O7 · `go.sum` 当组件清单，且优先于 `go.mod`

**原版行为**：`sca.go` 里先解析 `go.sum`，解析完还把 `go.mod` 从待处理表里删掉。
`go.sum` 记录的是**历史上解析过的所有** `module@version`（本工程 1177 条），
不是最终选中的集合（67 条）。

**修复**：解析顺序改为 `vendor/modules.txt` → `go.mod` → `go.sum`；
`go.sum` 只在前两者都不存在时兜底。

**commit**：`a02cceb`

#### O8 · `vendor/` 内第三方库自带的清单被当项目解析

**原版行为**：`Filter` 只按文件名匹配（`go.mod` / `go.sum` / `Gopkg.lock`），
遍历会走进 `vendor/`。vendor 里是依赖的完整源码，其中还带着它们自己的 `Gopkg.lock`，
于是 `modern-go/concurrent` 多出一条 `1.0.0`（dep 时代版本号，无 `v` 前缀）。

**修复**：新增 `inVendorDir()`，`vendor/` 下任何文件都不进扫描。

**commit**：`a02cceb`

#### O9 · 剥离 `+incompatible` 后缀

**原版行为**：`TrimSuffix(version, "+incompatible")`。这个后缀是版本号的一部分
（表示该主版本还没有 go.mod），剥掉之后版本与 `vendor/modules.txt` 对不上，
OSV 也匹配不到对应公告。

**修复**：保留后缀，`ParseGomod` 与 `ParseGosum` 都改。

**commit**：`a02cceb`

#### O10 · `replace` 三种写法全错

**原版行为**：

| 写法 | 原版结果 |
|---|---|
| `replace A => B v2` | 先删 A 再加 B，**A 从清单里消失**（A 才是 import 路径） |
| `replace A => ./local` | 右侧只有一个字段，解析出空名，A 被删又不补回 → **组件消失** |
| `replace A v1.0.0 => B v2` | `delete(deps, "A v1.0.0")` 匹配不到键 `A` → A 和 B **同时存在** |

**修复**：与 go 命令语义一致——本地目录替换保持原路径与原版本；精确版本只替换该版本；
未被 require 的模块不因 replace 凭空出现。

**commit**：`a02cceb`

#### O11 · 单行 `require A v1` 不重置块状态

**原版行为**：`require` / `replace` 标志只在遇到 `)` 时才清除。一行单行 `require A v1`
就会让标志永久为真，后面的 `replace A => B v1` 被当成 require 解析，
产生版本号为 `=>` 的假组件。本工程 `go.mod` 全用块写法所以没暴露，但任何单行写法的工程都会中。

**修复**：块状态只由 `require (` / `replace (` 进入、`)` 清出；单行写法就地处理。

**commit**：`7790e77`

### 2.3 SPDX 输出

#### O12 · SPDX 文档不合法，tag-value 直接被消费者拒绝

**原版行为**：三处结构问题。

- 项目自身没有版本，`Purl()` 返回空串，却仍写出 `referenceLocator: ""` 的 externalRef。
  空的 locator 不是合法 ExternalRef，严格解析器会拒绝整份文档。
- `documentNamespace` 固定为 `ftp://spdx`。SPDX 要求每份文档的命名空间全局唯一，两份报告会撞。
- `spdxVersion: 2.2`，没有 `documentDescribes`，消费者看不出哪个包是主体。

tag-value 序列化更严重：模板里写了 `DocumentDescribes:` 标签，而 SPDX tag-value **没有这个 tag**，
osv-scanner 报 `received unknown tag DocumentDescribes in CreationInfo section` 后直接失败。
此外模板末尾缺换行、空的 `PackageSupplier: ` 行也会让 tag-value 解析中断。

**修复**：空 purl 不写 externalRef（`ExternalRefs` 加 `omitempty`），空 vendor 不写 supplier；
namespace 改为 `https://opensca.dev/spdx/<name>-<随机串>`（时间戳在 Windows 上会重复，改随机）；
2.2 → 2.3 并补 `documentDescribes`；tag-value 用 `Relationship: SPDXRef-DOCUMENT DESCRIBES …`
表达同一含义，模板补齐换行。

**验证**：CycloneDX JSON / SPDX JSON / SPDX tag-value 三种序列化喂 osv-scanner，
都是 67 包、35 条漏洞，且逐包逐漏洞集合完全相同。

**commit**：`5653670`

### 2.4 npm

#### N-1 · 只有锁文件、没有 `package.json` 时扫不出依赖

**原版行为**：npm 解析依赖 `package.json` 判断项目与包信息，只有 `package-lock.json`
（容器镜像、只提交锁文件的仓库）时得到空结果。

**修复**：新增独立锁文件支持路径，从 lockfile 自身推导项目信息与依赖图，保留嵌套依赖关系；
补了回归测试与在线 OSV 兼容性用例。

**commit**：`82c9ab9`

---

## 三、新增功能

### 3.1 离线与输出控制

| 参数 | 作用 |
|---|---|
| `-offline` | 不做任何网络请求（配合预置缓存或本地仓库） |
| `-deps-only` | 只解析依赖、导出 SBOM，跳过漏洞查询；配置键为 `deps_only` |
| `-include-project` | 把工程自身也放进 `components`（默认只放 `metadata.component`） |
| `-input-type auto\|project\|sbom` | 指定输入类型；`auto` 时目录扫描不加载 SBOM |

**commit**：`962194c`

### 3.2 Maven 本地化

| 参数 | 作用 |
|---|---|
| `-maven-repo` | 指定本地 Maven 仓库路径 |
| `-maven-settings` | 指定 `settings.xml` |
| `-maven-command` | 指定 Maven 可执行文件 |
| `-java-version` | 指定用于 profile `<jdk>` 判定的 JDK 版本 |
| `-profiles a,b` / `-profiles '!c'` | 显式激活 / 禁用 profile |
| `-cache-dir` | 覆盖缓存目录（也可用 `OPENSCA_CACHE_DIR`） |

**commit**：`962194c`、`be536e0`

### 3.3 动态解析三态

`optional.dynamic` 从 `bool` 改为 `auto` / `on` / `off`：

- `auto`（默认）：Maven 可执行且可用时才走 `mvn dependency:tree`，否则静默回退静态解析。
  其它动态解析器（Gradle、Python venv）仍是 opt-in——只有 `on` 才启用
- `on`：强制走构建法
- `off`：只做静态解析

未知取值降级为静态解析并记一条诊断，而不是被当成 true。
Maven 回退时（找不到 mvn / mvn 失败 / 输出解析不了）都会记诊断，
不再静默返回一棵更短的树。

**commit**：`be536e0`

### 3.4 诊断机制

新增 `opensca/model/diagnostics.go`：解析过程中的降级、跳过、不支持都会进诊断列表，
随报告输出。已经覆盖：

- Maven 回退到静态解析的原因
- 不支持的清单（最初覆盖 `pnpm-lock.yaml`、`packages.config`；这两者现在都已实现解析，见 §七）
- 无法判定的 profile activation
- 无 purl 的依赖（CycloneDX 里写成 `opensca:diagnostic` 属性）

**commit**：`962194c`、`aef5ad2`、`51b41c0`

### 3.5 purl 生成

`opensca/model/language.go` 集中维护「生态 → purl type」映射，CycloneDX 与 SPDX 共用。
没有对应 purl 类型的生态不硬造，交由诊断提示。

**commit**：`962194c`

---

## 四、行为变更（可能影响现有用法）

| 变化 | 影响 |
|---|---|
| 缓存目录从「可执行文件旁」改到 `os.UserCacheDir()/opensca` | 依赖旧路径预置缓存的环境需要迁移，或用 `-cache-dir` 指定回旧路径 |
| `optional.dynamic` 从 bool 改字符串 | 老配置里的 `"dynamic": true/false` 仍被接受（`true`→`on`，`false`→`off`），但建议改成三态 |
| 目录扫描默认不加载 SBOM | 想扫 SBOM 文件要显式 `-input-type sbom` |
| `components` 默认不含工程自身 | 需要的话加 `-include-project` |
| `dynamic` 默认 `auto` | 装了 mvn 的机器上，Maven 解析会走构建法（更慢但更准）；内网无 mvn 时行为不变 |
| `mvn -P` 会带上 POM 里所有 profile | **已知缺陷，见下** |
| 仅依赖模式参数与配置键改名 | CLI 改为 `-deps-only`，配置键改为 `deps_only`；旧名称不再支持 |

---

## 五、验证

```bash
# Maven 4 夹具
opensca -path <fixture> -offline -deps-only -out /tmp/raw.cdx.json
python sca-compare/compare.py tree.txt /tmp/raw.cdx.json --format cdx
# bom       hit 8 | FP 0 | missed 0   P=100.0% R=100.0%
# runtime   hit 3 | FP 0 | missed 0   P=100.0% R=100.0%
# inherit   hit 8 | FP 0 | missed 0   P=100.0% R=100.0%
# relpath   hit 1 | FP 0 | missed 0   P=100.0% R=100.0%

# Go 端到端（三种序列化等价）
opensca -path <go-project> -offline -deps-only -out bom.cdx.json
opensca -path <go-project> -offline -deps-only -out bom.spdx.json
opensca -path <go-project> -offline -deps-only -out bom.spdx
osv-scanner scan source --offline --offline-vulnerabilities --all-packages --lockfile <上述任一>
# 67 packages / 35 advisories
```

单测：`go test ./opensca/... ./cmd/...` 全绿（新增 `java/local_test.go`、`java/profiles.go` 相关、
`sbom/cdx_test.go`、`model/language_test.go`、`model/spdx_test.go`、`sca/golang/golang_test.go`、
`cmd/format/cyclonedx_test.go` 等）。

---

## 六、commit 索引

| commit | 类型 | 主题 |
|---|---|---|
| `962194c` | fix | OSV 兼容 SBOM 导出 + 依赖解析回归修复（O1–O6，42 文件） |
| `04056a3` | test | 跨生态 OSV 兼容性验证 |
| `a02cceb` | fix | Go 模块集合解析（O7–O10） |
| `7790e77` | fix | Go 单行 `require` 污染块状态（O11） |
| `be536e0` | feat | `dynamic` 三态 + `-maven-command` + 回退诊断 |
| `51b41c0` | feat | CycloneDX 标记无 purl 的依赖 |
| `aef5ad2` | feat | 不支持的清单记诊断 |
| `37170be` | chore | 移除继承的 `.github` |
| `c20804e` | docs+test | OSV 说明迁移到根目录 + 兼容测试扩充 |
| `b8480e7` | chore | `.gitignore` 忽略二进制与日志 |
| `5653670` | fix | SPDX 文档合法性（O12） |
| `82c9ab9` | fix | npm 锁文件独立输入与嵌套依赖图 |
| `9dcd9fd` | feat+test | pnpm 锁文件和 NuGet 解析、NuGet restore / 兼容性测试 |
| `43cca99` | ci | 修复发布工作流 |

---

## 七、新增支持：pnpm 与 NuGet

以下两项最初作为工作区改动记录，现均已提交至 `9dcd9fd`，纳入本仓库当前版本。

### 7.1 pnpm 支持（`pnpm-lock.yaml`）

**之前**：`aef5ad2` 把 `pnpm-lock.yaml` 归为「没有解析器」，扫到只记一条诊断，
依赖清单里什么都没有。

**现在**：新增 `opensca/sca/javascript/pnpm.go`（约 350 行），直接解析 pnpm 锁文件，
**不调用 npm / pnpm**。

| 能力 | 说明 |
|---|---|
| 版本布局 | 支持 lockfileVersion 5 / 6 / 9（对应 pnpm 5–9）；v9 的 `importers` / `snapshots` 与 v5/v6 的 `dependencies` 结构分别处理 |
| optional dependencies | 保留，并按 pnpm 的解析规则标记 |
| workspace links | `link:` 协议解析到 workspace 成员，不产生伪版本 |
| peer-specific snapshots | `pkg@1.0.0(peer@2.0.0)` 这类 key 拆成「包身份 + peer 上下文」，避免同一包被拆成多条 |
| 版本归一 | `1.0.0`、`1.0.0(react@18.2.0)`、`/pkg@1.0.0` 等写法统一解析 |

接入方式：`isPnpmLock()` 加进 javascript 的 `Filter`；`scanPnpm` 独立成图，
并在 `package-lock.json` / `yarn.lock` 的处理里跳过已由 pnpm 认领的目录，避免同一工程出两份图。

`run.go` 里「pnpm-lock.yaml 不支持」的诊断随之删除。

### 7.2 NuGet 支持（新生态）

新增 `opensca/sca/nuget/`（7 个文件），注册进 `sca.AllSca`。OpenSCA 支持的生态从 9 种变成 10 种。

| 输入 | 处理方式 |
|---|---|
| `packages.config` | 扁平清单，直接读 `id`/`version`；校验 ID 与版本格式、确认能生成 purl，`developmentDependency` 标记保留 |
| `*.csproj` / `*.fsproj` / `*.vbproj` | 解析 `<PackageReference>`，含版本变量与中央包管理 |
| `*.sln` | 作为解决方案入口，定位其下的项目文件 |
| `project.assets.json` | `dotnet restore` 的产物，含完整依赖图与目标框架区分 |

- 新增语言 `model.Lan_DotNet`（`"DotNet"`），purl type 映射到 `nuget`
- 可选调用 `dotnet restore`（`restore.go`）：带超时、输出截断，失败不致命，回退到静态解析
- 单测：`sca_test.go`、`project_test.go`，以及仓库根的 `nuget_restore_test.go`

NuGet 项目优先读取未过期的 `project.assets.json`；无法使用时尝试 restore（离线或关闭动态解析时不调用），再回退到静态 PackageReference 清单并记录不完整诊断。`packages.config` 是扁平清单。当前项目格式实现同时支持 VB 项目（`*.vbproj`）。

---

## 附：已知未修复

| 项 | 说明 |
|---|---|
| O4 `relativePath` 根因 | 本地仓库兜底让夹具通过，但只扫子模块且父 pom 不在任何仓库时仍会丢 |
| `mvn -P` 全量激活 profile | 构建法会把 POM 里**所有** profile 的 id 拼进 `-P`，强制激活 `<jdk>`/`<os>` 不匹配的 profile。静态解析（`profiles.go`）是对的，构建法这条路径没有同步修正 |
| 12 种输出里的自定义 XML | `SpdxXml` 用 Go 的 xml encoder 直接序列化结构体，不是 SPDX 官方格式，osv-scanner 不识别；对接请用 `-out x.spdx.json` 或 `-out x.spdx` |
