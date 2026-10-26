# OSV 兼容输出与测试说明

## 使用范围

OpenSCA 负责依赖解析和标准 CycloneDX 输出；OSV 扫描由用户独立执行。无需 bridge、格式转换程序或 OpenSCA 的漏洞库配置。

```powershell
go build -o opensca.exe .
.\opensca.exe -path C:\project -offline -dependencies-only -maven-repo C:\Users\windows\.m2\repository -out C:\reports\bom.cdx.json
osv-scanner scan source --lockfile C:\reports\bom.cdx.json
```

外部 scanner 的联网、离线数据库和漏洞结果由用户自行配置。以上 scanner 命令以 2.x CLI 为例。

## 本次修复

| 项目 | 行为 |
|---|---|
| CycloneDX 图 | 统一稳定 bom-ref，组件和边去重，保留根依赖与匿名容器下的依赖；组件排序稳定 |
| PURL | 使用 packageurl 库构造和解析；不把未知生态猜成 Maven，不把版本范围当成确定版本 |
| SBOM 输入 | 目录扫描默认排除 SBOM；单文件或 `-input-type sbom` 显式导入；按格式识别，避免一个 JSON 被多个 SBOM parser 重复读取 |
| Maven 仓库 | `-maven-repo` / `java.local_repository` > `MAVEN_REPO_LOCAL` > 用户 settings.xml > `~/.m2/repository`；设置文件可通过 `-maven-settings` 指定 |
| 父 POM | 支持默认 `../pom.xml`、目录路径、显式空 relativePath 和属性版本；校验 group/artifact 及确定版本 |
| Profile | `-profiles a,!b`，支持 activeByDefault、常用 JDK 范围、OS family/arch、用户属性和文件条件；不支持的条件输出诊断。`java.properties` 提供用户属性，`-java-version` 指定 JDK |
| 工程模块 | Maven 工程节点显式标记；默认保留 application 节点与关系，工程子模块不带 PURL；`-include-project` 可包含。metadata 根节点保留项目身份 |
| 缓存 | `-cache-dir` / `cache_dir` > `OPENSCA_CACHE_DIR` > 系统用户缓存目录，不再写到安装目录 |
| 纯依赖输出 | `-dependencies-only` 跳过漏洞查询和 SaaS 报告上传，不需要 token |
| 离线与诊断 | `-offline` 禁止共享 HTTP client 联网并关闭动态构建；元数据缺失、未解析坐标等记录到诊断中。JSON 使用 `task_info.diagnostics`，CycloneDX 使用 `opensca:diagnostic` 属性 |
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

# 可选外部消费者兼容性测试（生产代码没有 scanner 依赖）
$env:OPENSCA_TEST_OSV_SCANNER = 'C:\tools\osv-scanner.exe'
go test . -run TestOSVCompatibility -count=1 -v -timeout 100s

# 可选：本机需安装 Maven，并允许访问 fixture 所需仓库
$env:OPENSCA_TEST_LIVE_MAVEN = '1'
go test ./test/java -run Test_JavaWithMvn -count=1 -v -timeout 300s
```

兼容性测试用临时项目、本地 Maven POM 和最小 OSV 离线测试库，验证 OpenSCA 连续两次导出、外部 scanner 直接消费、Log4j 2.14.1 命中及 2.17.1 不命中。固定测试库只用于格式和流程验收，不能作为真实漏洞覆盖率证明。

## 本机验证记录（2026-10-26）

### OpenSCA → CycloneDX → osv-scanner 场景矩阵

`osv_compatibility_test.go` 会构建 OpenSCA CLI、扫描临时项目、检查输出 PURL，再调用本机 osv-scanner 2.7.0 离线扫描同一份 CycloneDX。每个生态的 OSV 记录是临时生成的精确版本测试公告，不依赖公开漏洞库，也不代表真实库的覆盖程度。共 10 个子场景，检查受影响/修复版本、传递依赖、scoped PURL、工程根排除、同名多版本以及最终 OSV 命中。

| 开发场景 | 输入 | 输出/OSV 验证 | 结果 |
|---|---|---|---|
| Maven 直接依赖 | POM + 本地 Maven 仓库 | log4j-core 2.14.1 命中，2.17.1 不命中 | 通过 |
| Maven 传递依赖 | app → wrapper → log4j-core | 两层组件与依赖边保留，OSV 命中传递组件 | 通过 |
| npm scoped 依赖 | package.json + lock v3 | `pkg:npm/%40acme/demo@1.2.3` 命中 | 通过 |
| Go module | go.mod | Go PURL 和 OSV 漏洞关联 | 通过 |
| Python 固定版本 | requirements.txt | PyPI PURL 和 OSV 漏洞关联 | 通过 |
| Composer | composer.json + composer.lock | Packagist PURL 和 OSV 漏洞关联 | 通过 |
| RubyGems | Gemfile.lock | gem PURL 和 OSV 漏洞关联 | 通过 |
| Cargo | Cargo.lock | crates.io PURL 和 OSV 漏洞关联 | 通过 |
| Cargo 多版本 | 同一个 lockfile 含 serde 1.0.188/1.0.200 | 两个独立 PURL 均输出，仅公告影响版本命中 | 通过 |

### 本轮联测发现并修复

- Go module 和 Composer 项目根最初未标记为工程节点，被误输出成无版本依赖并让任务错误返回 3。现已标记项目根并保留在 CycloneDX metadata。
- Cargo 解析曾用 crate 名作为唯一 key，同名多版本会互相覆盖；依赖引用携带 registry source 时也会污染版本字符串。现改用 name + version 区分组件，并从依赖引用提取具体版本。两个版本的外部扫描回归通过。
- 不同生态的组件身份都由 PURL 供 scanner 匹配。测试确认 `%40` scoped npm 名称和 Maven group/artifact 结构可命中对应公告。

- 以上均为直接依赖的独立生态测试；已另测 Maven 传递依赖。没有验证各生态所有 lockfile 版本、workspace、平台条件或私有 registry 行为。

- 全量默认测试（`go test ./... -count=1`）：通过，同时显式启用并通过外部 OSV 兼容性测试。
- 全量竞态检查（`go test -race ./... -count=1`）：通过。
- `go vet ./...`、`git diff --check`：通过。
- 外部消费者：本机 osv-scanner 2.7.0，测试完全使用临时离线数据库。
- 真实 Maven 进程集成：本机没有 mvn，未启用；固定 Maven 输出解析回归和静态 POM 回归已通过。默认跳过该外部环境测试不代表真实 Maven 集成已验证。
- 原有 Java 静态和部分 JavaScript 用例仍会使用下载源/缓存，全量套件尚不是完全隔离的离线测试集。
