# 总控台

**Preview / Alpha · 源码预览**

总控台是一个本地服务、Docker 资源、批处理任务与常用程序快速启动和运行监测工具。macOS 版本保留完整现有功能；Windows 当前是通过 exact-commit CI 的 Phase 5 unsigned engineering candidate，提供安全的本地监听与进程观察、结构化命令配置、显式 macOS 配置导入，以及仅面向 Local Ops 自己创建的 Job Object 进程树控制。Windows 10、独立干净无 Python VM、Defender/SmartScreen、原生集成、品牌审核与签名门禁尚未完成，因此仍是 Preview / Alpha，而不是 Windows Beta。共享核心只绑定回环地址；前端是无构建、无 CDN 的原生 HTML/CSS/JavaScript。

> 当前版本仍处于 Preview / Alpha 阶段，以源码预览形式提供。接口、配置格式和安装方式仍可能调整；`总控台.app` 目前不是可单独复制的自包含应用，也尚不代表经过签名、公证的最终 macOS 发行版。

总控台只服务当前机器和当前用户，不是远程运维、多人协作或公网管理面板。macOS 完整版能够以当前用户权限执行保存的 shell 命令；Windows 只允许控制经 SID、generation、PID 创建时间、HMAC/受保护回执和 Job Object 完整验证的自建进程树。外部进程认领与结束仍禁用。不要将监听地址、反向代理、SSH 隧道或端口映射暴露到不受信任的网络。

## 维护说明

总控台由作者个人维护：功能的新增、修改与完善以作者日常使用中的实际需求为准，迭代节奏不定；PR 不承诺审阅或合入。

如果你希望增加功能、修复问题或适配其他平台，欢迎 **Fork 本仓库自行修改**，并在 Discussions 中提交衍生版本说明。经过试用评估后，优秀的衍生版本会收录到下方 [社区衍生版本](#社区衍生版本) 列表推荐给大家；衍生版本由各自作者维护，未经原作者审阅或测试，使用前请自行评估。

## 功能

- 每 2 秒查看当前用户的本地监听服务、CPU、内存和运行时长。
- 保存常用服务、程序或批处理任务，集中启动、停止、重启、查日志和诊断。
- 收藏 Docker Compose 项目或任意单容器，并按保存的精确身份执行启动、停止；不会执行 `down`、删除或 prune。
- Windows 可关联现有 Task Scheduler 任务，读取其真实状态，并单独启用或禁用该注册项；长期 Guard 归入“服务”，一次性任务归入“批处理任务”。
- Windows 打包版可一次 UAC 安装固定管理员代理；每次打开 Local Ops 输入一次自定义密码后，可在本次进程存活期间启动收藏的任意绝对路径 EXE。
- 在当前页面会话中发现新出现的、尚未管理的监听端口。macOS 可原子认领后加入启动台；Windows 只观察或创建未认领配置，不会控制现有进程。
- 运行前检查工作目录、脚本和运行时；明确失效时直接给出修复入口，不必先失败一次。
- 从项目文件夹识别常用启动命令，但不安装依赖、不执行项目代码。
- macOS 通过运行 token、进程组和当前 UID 联合识别受控进程；Windows 通过 SID、generation、PID 创建时间、签名回执和 Job 成员关系识别受管 Job。两个平台都不会因端口相同就结束外部进程。
- Ops 指挥台单一主题：深空蓝黑/雾灰双色，左侧导航轨、KPI 概览卡、实时动态侧栏，浅色、深色和跟随系统。
- 全局命令面板可直接添加服务、程序或批处理任务；启动台卡片支持鼠标拖拽和键盘排序。

## 界面预览

以下截图使用脱敏演示数据，不包含真实用户名、目录、命令或服务信息。

| 启动台 | 服务监控 |
| --- | --- |
| ![Ops 指挥台 · 启动台](docs/screenshots/ops-launchpad.jpg) | ![Ops 指挥台 · 服务监控](docs/screenshots/ops-services.jpg) |

## 系统要求

- macOS 12 或更高版本。
- Python 3.12。运行时仅使用 Python 标准库。
- macOS 自带的 `ps`、`lsof`、`osascript` 等系统工具。
- Safari、Chrome 或其他支持 ES Modules 的现代浏览器。
- Docker 收藏功能需要可用的 Docker CLI；Compose 收藏还需要 Docker Compose v2。

Windows 源码运行要求 Windows 11 x64、Python 3.12，以及 `requirements-windows.txt` 中锁定的依赖；unsigned onedir 候选把 Python 3.12 runtime 和 Windows runtime dependencies 一并打包。Phase 5 implementation commit `5daddece8a06d1fdd382d1814e58be7b777ceae4` 已通过 exact-commit CI run `31780819809`，其 exact-CI engineering candidate 为 `PASS`。完整 Phase 5 Gate 尚未关闭，因此 `phaseStatus=IMPLEMENTED_UNVERIFIED`、`lastGreenPhase=P4`、`windowsBetaReady=false`；状态以 `docs/windows-port/STATE.json` 为准。Windows 10、干净无 Python VM、Defender/SmartScreen、原生选择器/通知、素材审核和签名仍未完成，因此当前不是 Windows Beta 发布。

## Windows 适配版：生命周期与安全

在 PowerShell 中从项目根目录运行：

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-windows.txt
.\.venv\Scripts\python.exe server.py
```

Windows 用户数据固定写入 `%LOCALAPPDATA%\LocalOps\`。最终私有对象必须由当前用户 SID 拥有，并只向当前用户、SYSTEM 和 Administrators 授予受保护 DACL。Windows 新对象 owner 来自 token 的 `TokenOwner`；若管理员 token 的默认 owner 是 Builtin Administrators，只有 creation-time apply 才会在一次安全描述符更新中把 owner 归一为当前用户并同时写入 protected DACL。既有记录是 verify-only，Admin-owned 或其他 owner 一律拒绝。同一用户、同一数据目录通过 Named Mutex 保证只有一个写者。自定义数据或日志目录会拒绝盘符根、用户主目录、项目根目录、UNC 共享根以及 symlink/junction 路径。ACL 验证失败时配置进入只读保护。

本阶段保留 Phase 3 的 IPv4/IPv6 监听、进程信息、Windows picker adapter、结构化 `commandSpec`、项目识别和显式导入，并把配置迁移到 schema v4，增加 Docker 收藏、程序收藏与管理员代理字段。真实 Windows native picker 与 Notification Center 投递仍是发行前验收项，现有 headless/API 测试不能替代。旧 `command` 字段继续保留；POSIX 命令仍只会标记为 `needs_review`，不会被猜测性转换或执行。

Windows 不会自动发现或导入项目内旧 `data/` 或 macOS 配置。设置中心的导入向导只接受用户明确选择的本地 JSON 文件，并按“预览 → 路径映射 → 选择 → 提交”执行；预览零写入，提交不覆盖同 ID 应用、清空旧运行身份，并可在目标未发生后续修改时回滚。UNC/设备路径不会被探测或导入。

Windows runner 是每个受管应用 Job Object 的唯一长期句柄持有者。目标进程先以 `CREATE_SUSPENDED` 创建，加入受保护 Job 并持久化精确 runtime identity 后才允许恢复；普通停止超时会保留身份，只有用户明确确认的 Force 操作才能通过 `TerminateJobObject` 结束该 Job。控制台关闭不会关闭 Job，runner 异常退出则通过 kill-on-close 清理自己的 Job。

request/receipt 原子写入会先保护临时文件的 DACL，再替换为公开可见的最终文件。释放 active generation 前必须验证目录恰好包含三个私有 runtime records、terminal receipt 签名有效、Job 已空且 runner 不再存在；随后将 active 目录原子 rename 为严格派生的 cleanup tombstone，这次 rename 是 release commit。commit 后的恢复只删除 private、nonlink tombstone 中三个 runtime record 的 allowlisted subset，不做任何进程观察或控制；未知项、宽 ACL 或 link 会 fail closed 并保留 tombstone。

Windows 仍不支持外部进程认领、外部进程结束和总控台重启。不要通过修改前端或直接调用接口绕过 capability 与每应用 `controlAvailable` 门禁。破坏性生命周期测试只能设置 `LOCALOPS_RUN_WINDOWS_LIFECYCLE_TESTS=1` 后在隔离夹具作用域或 hosted runner 中运行，并且只能操作测试夹具创建的进程；禁止控制任何现有用户进程。

### Windows 计划任务控制

添加或编辑卡片时可以选择一个现有 Windows 计划任务。总控台保存规范化的 `scheduledTaskPath`，状态刷新时只查询已经关联的任务；任务选择器按需读取非 Microsoft 系统任务，因此不会在每次轮询时遍历完整任务库。

- 持续运行的 Guard、守护器和常驻服务应选择“长期服务”；运行中的卡片显示 Task Scheduler 的真实运行态和引擎 PID。
- 同步、导入、备份等执行后退出的入口应选择“批处理任务”；卡片显示最近运行时间与 Task Scheduler 的结果码。
- “运行”调用 Task Scheduler COM API，由原任务自身的账号、提权级别和 `MultipleInstances` 策略决定行为。总控台不会复制任务动作，也不会绕开 `IgnoreNew`。
- 卡片上的启用开关只设置该规范化任务路径对应注册项的 `Enabled`。它不会修改触发器、动作、主体、运行级别或 `MultipleInstances`，也不会自动运行或停止实例。
- 外部任务不是 Local Ops Job。“停止”只调用 Task Scheduler COM `Stop(0)` 停止该注册项的运行实例，不按 PID 结束进程，也不禁用或删除任务；强制停止和重启仍不提供。删除卡片只移除监控配置，不停止、禁用或删除 Windows 计划任务。
- 受保护系统进程或工作目录不可读取属于预期的 Windows 可见性限制，只显示提示，不再把健康状态错误标记为“降级”。任务库读取失败、配置损坏或关键组件扫描失败仍会进入降级状态。

接口和状态字段见 [`docs/windows-task-scheduler.md`](docs/windows-task-scheduler.md)。

### Docker 收藏

添加卡片时可从当前 Docker daemon 发现 Compose 项目和单容器。Compose 身份保存项目名、工作目录和完整配置文件列表；单容器身份保存 Docker 返回的完整容器 ID。启动和停止时会再次按该精确身份调用 Docker CLI，状态仍由 daemon 的只读发现结果决定。

- Compose 启动/停止分别使用 `docker compose ... up --detach` 与 `docker compose ... stop`。
- 单容器启动/停止分别使用 `docker container start <完整 ID>` 与 `docker container stop <完整 ID>`。
- Local Ops 不执行 `compose down`、`rm`、`prune`，也不会因为显示名相同而控制另一个容器。

接口与持久化字段见 [`docs/docker-resources.md`](docs/docker-resources.md)。

### Windows 管理员程序收藏

管理员启动使用一个固定、无触发器的 Task Scheduler broker，而不是为每个 EXE 新建提权任务。首次安装代理时会出现一次 UAC，并设置至少 8 个字符的自定义密码；此后每次 Local Ops 进程启动只需输入一次密码，解锁状态只保存在该进程内存中。Local Ops 退出、进程身份变化、代理重启或会话令牌失效后都必须重新输入。

代理只接受绝对 `.exe` 路径、字符串参数数组和绝对工作目录，并以 `shell=False` 启动。收藏 EXE 时会通过固定的系统图标 API 读取关联图标，不执行目标程序；用户选择的 glyph 或后续上传图片仍会覆盖自动图标。收藏记录不授予权限；删除收藏不会卸载代理。打包版可直接安装代理；源码模式会自动发现数据目录 `packages/` 下最近部署且通过元数据与运行时检查的 Windows onedir `LocalOps.exe`，只有未发现有效包时才打开人工选择兜底，再由该打包程序完成 UAC 安装。计划任务始终固定到复制进 `%ProgramFiles%\LocalOps\Broker\<hash>` 的受保护 EXE，不会指向用户可写的 Python 源码。新代理与首次 UAC 路径仍属于本分支的工程实现，尚未完成签名包、干净 VM、Defender/SmartScreen 和真实 UAC 材料门禁，因此不改变 `phaseStatus=IMPLEMENTED_UNVERIFIED` 或 `windowsBetaReady=false`。

安装、解锁、会话与安全边界见 [`docs/windows-elevation-broker.md`](docs/windows-elevation-broker.md)。

本地 Phase 4 门禁已通过 Windows real discovery 174/174（406.426s）、frontend 24/24、HTTP hardening 6/6（合计 30/30）和 Node 30/30。其中包括 `WIN-LIFE-001..012` 的 12/12、`WIN-SEC-001..014` 的 14/14、HTTP 总控台测试子进程终止后重开，以及 100 次完整启动/Force/释放循环。相同实现已通过上述 exact-commit CI；只有 Phase 5 的 Windows 10、self-contained clean-machine 和发行审计全部通过后，才会把 `windowsBetaReady` 改为 `true`。

## Windows 适配版：打包与验证

Phase 5 增加 Python 3.12 + PyInstaller 6.21.0 的 onedir/windowed/x64 unsigned zip、可复现 sidecar/manifest 和发行内容审计。源码 venv 启动 runner 时改用 base Python 并保留 `__PYVENV_LAUNCHER__`，避免 venv redirector 的短命 PID 被误当成受管根；runner 先脱离继承 console 再创建私有 console group。冻结程序以同一 executable 派生 runner 时设置 `PYINSTALLER_RESET_ENVIRONMENT=1`，构建显式包含 `win32timezone`，所有目标 executable 在启动前解析为绝对路径。

在 Windows Python 3.12 环境从项目根目录构建和审计：

```powershell
py -3.12 -m pip install -r requirements-windows.txt -r requirements-build-windows.txt
py -3.12 tools\build_windows.py build --output-dir dist\windows
py -3.12 tools\build_windows.py audit --archive dist\windows\local-ops-1.0.0-windows-x64-unsigned.zip
```

当前本地证据包括：Windows lifecycle gate 207 tests `OK`、1 个 package-smoke gate skip、120.941s；packaging unit 25 ran / 24 passed / 1 gated skip；focused 109/109、shared contracts 31 passed + 1 symlink-privilege skip、frontend+HTTP hardening 30/30、Node 30/30、common 10/10、project checks 6/6、compile 45，以及 Ruff/diff PASS。最新 audited package smoke 为 1/1 PASS（24.209s）：解压到只读中文与空格路径，剥离 child PATH 后完成真实 start/log/port、controller close/reopen、Force stop/release/delete，并确认 bundle tree hashes 未变化。测试 harness 本身仍有 Python 和依赖，因此这项证据不等价于“干净 VM 未安装 Python”。

exact-commit CI run `31780819809` 的 common job `94705997033`、macOS full/source-release job `94705997092` 和 Windows lifecycle/contracts/frontend/hardening/reproduce/audit/package-smoke/upload job `94706274519` 均成功。CI 两次独立 build 生成字节一致的 18,649,468-byte archive，SHA-256 为 `b227e6244bf18d337d0244cd032e58c20ed84afe7d56286b9f73cb59d408eebe`；107-byte checksum sidecar SHA-256 为 `347154c1cdafe03777a56bbda23e5ad37610d203823cc44105c54b28fec44009`；219,889-byte manifest SHA-256 为 `e78bb8bda187094689c7d78585f8c7c2c3855379b779c337c885050bb99bf0ae`。上传的 GitHub artifact id `9211730738`、name `local-ops-windows-x64-unsigned`、size 18,870,044 bytes、digest `sha256:a084fcc3794e9a57d5cd116992f2b42637df6f11ebd1d71f32568b6f8cff35c6`；该 digest 是 GitHub artifact 容器摘要，不是内层 zip SHA。开发产物仍为 unsigned；Windows 10、干净无 Python VM、Defender/SmartScreen、原生 picker、Windows Notification Center 和 favicon 品牌审核分别保持 `SKIPPED`、`NOT_RUN` 或 `REVIEW_REQUIRED`，不得从 CI 或本地 smoke 推断通过。

`VERSION` 是项目版本的唯一权威来源。`Info.plist`、发行包名和发行说明应与它保持一致。

## 安装

### Windows 适配版

源码模式使用上文的 Python 3.12 环境。打包候选无需目标机器预装 Python：

1. 从 Windows CI artifact 或本地 `tools\build_windows.py build` 输出取得 `local-ops-<VERSION>-windows-x64-unsigned.zip`、同名 `.sha256` 与 manifest。
2. 校验 SHA-256，并将 ZIP 完整解压到当前用户可读取的固定目录；不要只移动 `LocalOps.exe`，它依赖同目录的 `_internal` 与静态资源。
3. 双击 `LocalOps.exe`。程序只绑定回环地址，并自动打开浏览器；用户配置、图标、日志和 runtime records 写入 `%LOCALAPPDATA%\LocalOps\`，不会写入程序目录。

当前 ZIP 明确标记为 `UNSIGNED DEVELOPMENT BUILD`，不是 Windows Beta 或签名发行版。若 Defender/SmartScreen 阻止运行，应保留并记录结果，使用源码模式或自行从已审核源码构建；不要关闭系统安全保护来绕过门禁。

### macOS

总控台以完整项目目录运行，`总控台.app` 是项目内启动器，不是可以单独复制的自包含应用。

1. **下载并解压**：将发行 zip 解压到一个你有读写权限的位置（如 `~/Applications` 或文稿下的固定目录）。解压后请保持目录结构完整，不要单独移动 `总控台.app`。
2. **确认 Python 3.12**：在「终端」运行：

   ```bash
   python3 --version
   ```

   显示 3.12 或更高即可。未安装或版本过低时，到 <https://www.python.org/downloads/> 下载官方 macOS 安装包，按向导安装一次即可（之后不再需要操作）。
3. **首次打开（未签名应用，二选一）**：
   - 图形方式：在 `总控台.app` 上**点右键 → 打开**，在弹窗中再点「打开」。只需做一次。
   - 命令行方式（等价，适合批量或远程）：

     ```bash
     xattr -dr com.apple.quarantine "总控台.app"
     ```

     之后即可正常双击。这是 macOS 对互联网下载应用的常规隔离提示，不是程序损坏。

## 运行

### Windows

| 方式 | 操作 | 适用场景 |
| --- | --- | --- |
| 打包候选 | 双击解压目录中的 `LocalOps.exe` | 日常试用，无终端窗口，不要求预装 Python |
| 源码 | `.\.venv\Scripts\python.exe server.py` | 开发、调试和查看终端输出 |

源码模式可指定浏览器与优先端口；打包候选接受相同参数：

```powershell
.\.venv\Scripts\python.exe server.py --no-browser
.\.venv\Scripts\python.exe server.py --preferred-port 9603
.\LocalOps.exe --no-browser --preferred-port 9603
```

Windows 当前不提供总控台自身的网页“重启 / 停止”操作。需要结束总控台时，只结束这次启动的精确 `LocalOps.exe`/Python 控制台进程；不要按端口、进程名或模糊 PID 批量结束。由启动台创建的受管 Job 不会因为浏览器关闭而停止。

### macOS

启动总控台有三种方式，效果相同，按习惯选择：

| 方式 | 操作 | 适用场景 |
| --- | --- | --- |
| 双击应用 | 双击 `总控台.app` | 日常使用。后台运行，无 Terminal 窗口和 Dock 图标 |
| 双击脚本 | 双击 `start.command` | 想在 Terminal 里看实时输出 |
| 命令行 | `python3 server.py` | 调试、脚本化或远程 SSH 启动 |

命令行还有两个可选参数：

```bash
python3 server.py --no-browser        # 只启动服务，不自动打开浏览器
python3 server.py --preferred-port 9603  # 在 9600-9609 内指定优先端口
```

两个平台启动后都只绑定 `127.0.0.1`，从 9600 起尝试端口，被占用则递增（最多 10 个），并默认打开浏览器。命令行参数、环境变量（`CONSOLE_DATA_DIR` / `CONSOLE_LOG_DIR`）见下文“数据、隐私与备份”。

**实际地址在哪里看**：macOS 顶栏「重启 :9600」按钮显示当前端口；Windows 可看浏览器地址、源码终端输出或 `%LOCALAPPDATA%\LocalOps\logs\console.log`。浏览器手动访问 `http://127.0.0.1:端口号/` 即可。

**停止与重启**：macOS 顶栏「重启 / 停止」控制的是总控台自身（网页服务）。停止总控台**不会**停止启动台里已经运行的应用——它们是独立进程组，会继续运行；下次打开总控台时会自动重新识别。重启总控台会加载磁盘上的最新代码，同样不影响运行中的应用。Windows Phase 4 的总控台重启/停止控制保持禁用；受管 Job 由独立 runner 持有，因此测试创建的总控台进程退出并重开后仍可重新验证和控制同一 generation。

## 使用

打开页面后，左侧是导航轨，右侧是信息栏；所有数据每 2 秒自动刷新。

### 启动台（管理你的服务与任务）

- **添加服务/任务**：点「+ 添加服务」卡片或页头快捷按钮。选择工作区文件夹后会自动识别项目类型（Node/pnpm、Hexo/Hugo、Django/FastAPI、Go、Rust、静态站点等）并给出候选命令；也可以「选择脚本」或完全手动填写。`service` 是长期服务（带端口语义），`task` 是有明确结束时间的批处理（强制无端口）。
- **卡片**：大按钮启动/停止（任务是运行/中止）；右侧一排小按钮（复制链接/日志/诊断/重启/编辑/删除）常显，不用悬浮。运行中显示端口与时长；配置失效（目录/脚本丢失）会直接标出原因并禁用启动，点开「启动诊断」有修复建议。
- **筛选**：每个分区右上角可按 全部/运行中/已停止/异常（任务为 全部/运行中/成功/失败/已取消）过滤，点按即时切换。
- **排序**：鼠标拖拽，或聚焦卡片后按空格进入键盘排序（方向键移动，空格确认）。
- **批量停止**：右侧「快捷操作」里可一键停止全部运行中的应用（有确认框，逐个安全停止，绝不按端口杀进程）。

### 服务监控（查看本机服务）

- **概览卡**：在线服务/后台应用/总 CPU/总内存（带最近一分钟负载曲线）/端口警告/最后更新。
- **服务表格**：每个服务的 PID、端口、目录、负载、时长、状态，以及**启动者徽标**——溯源显示这个进程是哪个 AI 助手（Codex/Claude/Kimi 等）、编辑器（VS Code/Cursor 等）、终端或总控台启动的。点端口直接打开服务；macOS 可认领或安全结束符合所有权校验的进程，Windows 只观察、置顶、隐藏或创建未认领配置，外部认领/结束入口保持禁用。
- **发现新端口**：页面打开期间新出现的监听端口会单独提醒。macOS 可自动识别并原子认领；Windows 可保存未认领配置或忽略隐藏，但不会把监听端口、PID 或 cwd 当作控制权证明。
- **后台与已隐藏**：系统/GUI 应用进程默认折叠在「应用后台」；被隐藏的服务可随时恢复。
- **关注的进程**：输入关键字（如 `ffmpeg`）回车，匹配进程实时列出。

### 日志中心（⌘J / Ctrl+J）

导航轨「日志中心」，或使用 macOS `⌘J` / Windows `Ctrl+J`：所有应用按运行中优先排列，点开任意一行看实时日志；底部固定总控台自身日志入口。

### 设置中心

导航轨齿轮：任务完成通知开关、外观三态（自动/浅色/深色）、版本/端口/工作目录/数据目录信息。浏览器 Notification API 已接入；Windows Notification Center 真实投递仍未完成发行验收。

### 命令面板（⌘K / Ctrl+K）

使用 macOS `⌘K` / Windows `Ctrl+K` 全局搜索并执行：添加服务/任务、启动/停止/重启任意应用、打开页面、查看日志、切换视图、开关任务通知、查看总控台日志等，全键盘操作。

### 使用要点

- 红色按钮会结束进程或删除应用，需要二次确认。
- 批处理任务自然退出 `0` 表示成功，其他非零退出码表示失败；脚本内部用户主动取消请退出 `130`（显示为「已取消」）；总控台按钮主动中止单独显示为「已中止」。
- 选择批处理脚本时，总控台只保存脚本的绝对路径和生成的执行命令，不会复制或托管脚本内容。脚本移动、改名或删除后，任务会失效；建议将个人脚本放在长期稳定、会单独备份的自动化目录中。
- 停止总控台不会自动停止已启动的独立服务；配置里的应用、图标、关注关键字和隐藏/置顶标记都会保留。

### 批处理退出码约定

任务自然退出 `0` = 成功，其他非零 = 失败；脚本内部用户主动取消请退出 `130`（显示为「已取消」而非失败）；总控台按钮中止显示为「已中止」。Python 用 `raise SystemExit(130)`，Shell 用 `exit 130`，Node.js 设 `process.exitCode = 130`。此约定只用于 `task`，长期服务仍按普通退出处理。

### 新端口发现的基线规则

「服务监控」只提醒**页面打开后新出现**、尚未纳入启动台的本地服务。首次载入、页面从后台恢复、断线重连或总控台重启后的第一份状态只用于建立静默基线，不会把已有端口全部弹一遍。「忽略并隐藏」写入配置并可恢复；「暂时关闭」只影响当前页面会话。

## 数据、隐私与备份

运行数据与程序目录分离：

| 平台 | 数据目录 | 日志目录 |
| --- | --- | --- |
| macOS | `~/Library/Application Support/总控台/` | `~/Library/Logs/总控台/` |
| Windows | `%LOCALAPPDATA%\LocalOps\` | `%LOCALAPPDATA%\LocalOps\logs\` |

`config.json`、`config.json.bak` 和 `icons/` 应备份；日志通常不需要。Windows 的 `runtime/` 保存受管 generation 的私有 request/token/receipt，不应手动复制到另一台机器或纳入普通配置备份。

macOS 目录权限会收紧为 `0700`，配置、图标和日志文件为 `0600`。Windows 私有目录和文件必须由当前用户 SID 拥有，DACL 只允许当前用户、SYSTEM 与 Administrators；既有宽权限、错误 owner、link/junction 或不可信 runtime record 会 fail closed。这些数据可能含个人路径、完整命令和日志内容，不应进入 Git、发行包或未脱敏的故障报告。

### 旧版数据首次迁移

macOS 新目标目录尚不存在时，首次启动会将项目内旧 `data/config.json{,.bak}` 和 `data/icons/` 安全复制到 Application Support，将 `data/logs/` 复制到 Library Logs。迁移使用临时目录后原子落位，并且：

- 旧 `data/` 始终保留，不会自动删除。
- 目标已存在时绝不覆盖或合并，避免把更新的用户数据换回旧版。
- 符号链接和非普通文件不会被复制。
- 显式设置 `CONSOLE_DATA_DIR` 或 `CONSOLE_LOG_DIR` 时，对应目录不执行旧数据自动迁移。

Windows 不会自动复制项目内旧 `data/` 或猜测转换 macOS 配置。需要迁移时，在设置中心显式选择 JSON，先预览并映射路径，再选择应用提交；blocked/conflict 项不会被静默覆盖，提交后在目标配置未继续变化时可以回滚。

需要自定义路径时：

```bash
CONSOLE_DATA_DIR="/private/path/console-data" \
CONSOLE_LOG_DIR="/private/path/console-logs" \
python3 server.py
```

```powershell
$env:CONSOLE_DATA_DIR = 'D:\LocalOpsData'
$env:CONSOLE_LOG_DIR = 'D:\LocalOpsData\logs'
.\.venv\Scripts\python.exe server.py
```

自定义值必须是非空绝对路径，并指向总控台专用的非链接子目录；不要直接填盘符根、用户主目录或项目根目录。Windows 还会拒绝 UNC 共享根、symlink 和 junction 路径。

### 备份

1. 不再执行新的启动、停止或编辑操作。
2. Windows 必须先在启动台逐个停止并释放全部受管 generation，再停止总控台；macOS 也建议先停止不希望继续运行的应用。
3. 将 macOS `~/Library/Application Support/总控台/` 或 Windows `%LOCALAPPDATA%\LocalOps\`（排除 `runtime/` 和通常不需要的 `logs/`）复制到受保护的备份目录。
4. 记录当前 `VERSION`，以便恢复时匹配配置格式。

### 恢复

1. 确保总控台已停止，并另存当前平台的数据目录。
2. 将备份中的 `config.json` 和 `icons/` 复制回对应位置。macOS 恢复 `0600`/`0700` 权限；Windows 由程序重新验证当前用户 owner 与私有 DACL，不要复制其他机器的 `runtime/`。
3. 重新启动，逐项确认命令、工作目录和端口。

如果主配置损坏，程序会验证 `config.json.bak` 并恢复主文件。如果两份都不可用，服务进入只读保护状态，不会用空配置覆盖它们。`config.json.bak` 保留的是每次修改之前的上一份良好配置，而不是主文件的同内容副本。

## 升级

1. 阅读 `CHANGELOG.md`，确认是否有配置或平台变更。
2. 停止总控台并备份当前平台的数据目录。
3. 用新版本替换程序文件；Windows onedir 包必须整体替换，不能只覆盖 `LocalOps.exe`。用户数据保持在独立数据目录中。
4. 源码 checkout 在 macOS 运行 `make check`，在 Windows 运行 `py -3.12 tools\check_project.py --scope windows`；打包用户使用已经通过对应审计的完整 ZIP。
5. 启动后检查应用数量、主题、关注关键字和一个可控服务的完整启停。

当前配置为 schema v4，启动时逐版执行显式、幂等迁移。v3 为应用增加 `dockerResource`，v4 增加 `elevated` 与 `program` 类型；旧 `command` 仍保留，Windows 只执行通过静态预检的结构化 `commandSpec`。新程序不会静默降级它不认识的更高 schema；回退程序时仍应同时恢复与该版本匹配的数据备份。

## 卸载

1. 如果不希望已启动的服务继续运行，先在启动台逐个停止它们。
2. 停止总控台。
3. 按需导出当前平台的数据目录备份。
4. 将整个项目目录或 Windows 解压后的完整 onedir 目录移到废纸篓/回收站。
5. 确认不再需要数据后，手动删除 macOS Application Support/Library Logs，或 Windows `%LOCALAPPDATA%\LocalOps\`。

程序不会安装系统服务或系统启动项，卸载时也不会自动删除用户数据。

## 安全边界

总控台不是多用户服务器或远程管理面板。它能以当前用户权限执行已保存并通过平台校验的命令，因此：

- 只添加你已检查且信任的命令和工作目录。
- 不要将服务绑定到 `0.0.0.0`，不要通过反向代理、SSH 隧道或端口映射对外暴露。
- 不要在共享或不受信任的用户账户中运行。
- 不要把平台数据目录中的 `config.json`、日志或故障截图未经脱敏就上传。
- 本地回环绑定只是第一层边界，不能替代写接口的 Host/Origin/控制令牌防护。发布验收时必须执行 `RELEASE_CHECKLIST.md` 中的安全项。

Windows 只会启动和控制由本次 Local Ops generation 创建、加入 Job Object 并通过 SID/PID 创建时间/HMAC 回执复验的进程树。外部认领、外部结束和总控台重启保持禁用；不要用 `taskkill /T`、端口匹配或裸 PID 替代产品的所有权校验。

## 故障排查

### 双击后没有界面

- macOS：确认 `python3 --version` 可用，查看 `~/Library/Logs/总控台/console.log`，并可用 `python3 server.py` 查看终端错误；不要单独移动 `总控台.app`。
- Windows 源码：确认 Python 3.12 与 `requirements-windows.txt` 已安装，用 `.\.venv\Scripts\python.exe server.py` 查看错误。
- Windows 打包候选：保持 `LocalOps.exe` 与 `_internal`/静态资源的完整目录结构，查看 `%LOCALAPPDATA%\LocalOps\logs\console.log`。当前 unsigned 构建被 Defender/SmartScreen 阻止时应保留原始结果，不要绕过系统保护。

### 9600 打不开

程序可能已选择 9601–9609。查看浏览器地址、终端输出或当前平台的 `console.log`。服务可访问时，`GET /api/health` 会返回程序版本、配置 schema 和降级原因，且不会执行进程扫描。

### 应用启动失败

- 先打开该应用的日志和“启动诊断”。
- 确认工作目录仍然存在、命令可在普通 shell 中运行。
- 检查启动瞬间配置端口是否正被其他进程占用；不同项目允许保存相同的常见开发端口。
- macOS Finder 启动不会读取 shell 配置；总控台会补入常用 Node/Homebrew 路径，但非标准安装仍可能需要显式绝对路径。
- Windows 只执行已通过预检的结构化 `commandSpec`；确认 executable 能从工作目录或 `PATH`/`PATHEXT` 唯一解析。POSIX 命令和待复核 shell 文本不会被猜测性转换后执行。

### 配置丢失或损坏

停止总控台，保留当前 `config.json`，然后按上文“恢复”流程使用已知良好的 `config.json.bak` 或离线备份。

## 开发

macOS runtime 无第三方 Python 依赖；Windows runtime 使用 `requirements-windows.txt` 中精确锁定的 `psutil` 与 `pywin32`，Windows 打包工具链单独锁定在 `requirements-build-windows.txt`。重新生成品牌图标派生文件或图标库时需要开发依赖：

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements-dev.txt
```

主要目录：

```text
server.py                 共享 Python HTTP、配置与业务核心
localops/platform/        macOS/Windows 原生 adapter
localops/windows/         Windows runner、Job、IPC 与冻结入口
static/                   原生前端、主题、品牌、图标和字体
tests/                    后端、前端契约、发布与交付检查
tools/build_windows.py     构建并审计 unsigned Windows x64 onedir zip
tools/gen_brand_assets.py 从品牌主图生成 favicon 与 macOS App Icon
tools/gen_icons.py         由 vendored SVG 生成 icons.js
tools/check_project.py     统一的只读项目检查
data/                      旧版运行数据（仅首次迁移源，不进 Git/发行包）
```

### 检查

提交前的权威命令是：

```bash
make check
```

它会检查 Python/JavaScript/Bash/plist/JSON 语法、版本一致性、主题和资源引用、生成的图标是否同步，并显式发现和运行测试。测试数量为 0 时会失败，不会出现“0 tests 也算通过”。

只运行后端测试：

```bash
make test
# 等价的显式命令：
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

正式发布前还应运行：

```bash
make release-check
```

它会额外检查 Git 状态和不应进入发行范围的文件；不会代替 `RELEASE_CHECKLIST.md` 中的人工验收。

### 重新生成资源

```bash
make generate-icons
make generate-brand
make check
```

`static/icons.js` 是生成文件，不应手工修改。`generate-brand` 以 `static/assets/console-app-icon.png` 为主源，需要 macOS 自带的 `iconutil`。重新生成品牌图标后，只提交预期的差异，并同步更新 `ASSET_PROVENANCE.md` 的 SHA-256。

## 发布

请按 `RELEASE_CHECKLIST.md` 逐项验收。一个可对外交付的版本至少需要：

- 与根目录 MIT 许可证一致的版权信息，以及全部第三方素材和项目图像的来源、许可与授权凭证。
- 干净、可追溯的 Git commit 和带签名版本 Tag。
- 通过 `make release-check` 和人工 UI/安全/升级/回滚验收。
- 不含任何项目内旧 `data/`、用户 Library 数据、日志、绝对路径、token 或缓存的发行包。
- 针对目标 Mac 的签名、公证、完整性校验、全新安装和回退证据。
- Windows exact-commit engineering candidate 已通过 CI，但还必须完成真实 Windows 10 非管理员环境、独立干净无 Python VM、Defender/SmartScreen、原生 picker/Notification Center、素材审核和签名门禁，才可标记为 Beta；当前 unsigned 产物不满足该门禁。

## 社区衍生版本

以下衍生版本由社区贡献者各自维护，未经原作者审阅或测试，收录仅作推荐。提交新衍生版本或更新说明，请前往 Discussions。

| 衍生版本 | 说明 | 出处 |
| --- | --- | --- |
| Windows 10/11 适配（双平台运行） | 共享代码 + 平台分支收敛，不新增运行时依赖，含 Windows 专属测试与 CI | PR [#2](https://github.com/laogou717/local-ops/pull/2)（dontpanic1） |
| Windows 11 安全优先移植（Draft） | Job Objects、签名回执、CREATE_SUSPENDED 等更严格的进程所有权模型，含打包体系 | PR [#3](https://github.com/laogou717/local-ops/pull/3)（songconmaisaix31-design） |
| Windows 后端 `server_win.py` | 独立 Windows 后端（纯标准库），复用本仓库前端 | PR [#4](https://github.com/laogou717/local-ops/pull/4)（Hexvork） |
| sysops.py 跨平台抽象层方案 | psutil 唯一新增依赖，macOS 分支零改动，作者已在日常使用 | [Issue #1 提案](https://github.com/laogou717/local-ops/issues/1)（FL411） |

## 参与贡献与安全

- 提交代码前请阅读 [`CONTRIBUTING.md`](CONTRIBUTING.md) 与上方「维护说明」，并运行 `make check`。
- 行为规范见 [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)。
- 安全问题不要作为普通公开 Issue 披露；报告方式和脱敏要求见 [`SECURITY.md`](SECURITY.md)。
- 新增或替换字体、图标、插画、纹理等素材时，必须同步更新 [`ASSET_PROVENANCE.md`](ASSET_PROVENANCE.md) 和 [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)。

## 许可与第三方素材

项目自有代码和文档采用 [`MIT License`](LICENSE)。Lucide、Geist Mono 以及项目生成图像等素材可能适用各自的许可或发布限制，不因根目录 MIT 许可证而自动改变，详见 [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) 与 [`ASSET_PROVENANCE.md`](ASSET_PROVENANCE.md)。
