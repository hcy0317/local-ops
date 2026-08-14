# 总控台

**Preview / Alpha · 源码预览**

总控台是一个本地服务与批处理任务快速启动、运行监测工具。macOS 版本保留完整现有功能；Windows 当前处于 Phase 4 生命周期源码候选，提供安全的本地监听与进程观察、结构化命令配置、显式 macOS 配置导入，以及仅面向 Local Ops 自己创建的 Job Object 进程树控制。共享核心只绑定回环地址；前端是无构建、无 CDN 的原生 HTML/CSS/JavaScript。

> 当前版本仍处于 Preview / Alpha 阶段，以源码预览形式提供。接口、配置格式和安装方式仍可能调整；`总控台.app` 目前不是可单独复制的自包含应用，也尚不代表经过签名、公证的最终 macOS 发行版。

总控台只服务当前机器和当前用户，不是远程运维、多人协作或公网管理面板。macOS 完整版能够以当前用户权限执行保存的 shell 命令；Windows Phase 4 只允许控制经 SID、generation、PID 创建时间、HMAC/受保护回执和 Job Object 完整验证的自建进程树。外部进程认领与结束仍禁用。不要将监听地址、反向代理、SSH 隧道或端口映射暴露到不受信任的网络。

## 功能

- 每 2 秒查看当前用户的本地监听服务、CPU、内存和运行时长。
- 保存常用服务或批处理任务，集中启动、停止、重启、查日志和诊断。
- 在当前页面会话中发现新出现的、尚未管理的监听端口，可直接加入启动台或忽略隐藏。
- 运行前检查工作目录、脚本和运行时；明确失效时直接给出修复入口，不必先失败一次。
- 从项目文件夹识别常用启动命令，但不安装依赖、不执行项目代码。
- macOS 通过运行 token、进程组和当前 UID 联合识别受控进程；Windows 通过 SID、generation、PID 创建时间、签名回执和 Job 成员关系识别受管 Job。两个平台都不会因端口相同就结束外部进程。
- Ops 指挥台单一主题：深空蓝黑/雾灰双色，左侧导航轨、KPI 概览卡、实时动态侧栏，浅色、深色和跟随系统。
- 全局命令面板可直接添加服务或批处理任务；启动台卡片支持鼠标拖拽和键盘排序。

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

Windows Phase 4 源码候选要求 Windows 11 x64、Python 3.12，以及 `requirements-windows.txt` 中锁定的依赖。当前 `LOCAL_PASS_CI_PENDING`：Windows NT build 26200（25H2）非管理员本地门禁已通过，但本地使用的是 Python 3.13.13。精确提交 `fc29e5637d93b95026a5dbca5e46c638c51b5439` 的 CI run `31766584905` 因 Windows owner semantics 与 macOS test principal isolation 失败；该 run 只是历史失败尝试，修复后的新 exact-commit Windows Python 3.12 CI 与完整 macOS 回归尚未运行。状态以 `docs/windows-port/STATE.json` 为准。Windows 10、self-contained 打包和干净机器验收属于 Phase 5，因此不构成 Windows Beta 发布。

## Windows Phase 4 生命周期源码候选

在 PowerShell 中从项目根目录运行：

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-windows.txt
.\.venv\Scripts\python.exe server.py
```

Windows 用户数据固定写入 `%LOCALAPPDATA%\LocalOps\`。最终私有对象必须由当前用户 SID 拥有，并只向当前用户、SYSTEM 和 Administrators 授予受保护 DACL。Windows 新对象 owner 来自 token 的 `TokenOwner`；若管理员 token 的默认 owner 是 Builtin Administrators，只有 creation-time apply 才会在一次安全描述符更新中把 owner 归一为当前用户并同时写入 protected DACL。既有记录是 verify-only，Admin-owned 或其他 owner 一律拒绝。同一用户、同一数据目录通过 Named Mutex 保证只有一个写者。自定义数据或日志目录会拒绝盘符根、用户主目录、项目根目录、UNC 共享根以及 symlink/junction 路径。ACL 验证失败时配置进入只读保护。

本阶段保留 Phase 3 的 IPv4/IPv6 监听、进程信息、原生选择器、schema v2、结构化 `commandSpec`、项目识别和显式导入，并增加受 generation CAS 保护的启动、普通停止、显式强制停止与重启。旧 `command` 字段继续保留；POSIX 命令仍只会标记为 `needs_review`，不会被猜测性转换或执行。

Windows 不会自动发现或导入项目内旧 `data/` 或 macOS 配置。设置中心的导入向导只接受用户明确选择的本地 JSON 文件，并按“预览 → 路径映射 → 选择 → 提交”执行；预览零写入，提交不覆盖同 ID 应用、清空旧运行身份，并可在目标未发生后续修改时回滚。UNC/设备路径不会被探测或导入。

Windows runner 是每个受管应用 Job Object 的唯一长期句柄持有者。目标进程先以 `CREATE_SUSPENDED` 创建，加入受保护 Job 并持久化精确 runtime identity 后才允许恢复；普通停止超时会保留身份，只有用户明确确认的 Force 操作才能通过 `TerminateJobObject` 结束该 Job。控制台关闭不会关闭 Job，runner 异常退出则通过 kill-on-close 清理自己的 Job。

request/receipt 原子写入会先保护临时文件的 DACL，再替换为公开可见的最终文件。释放 active generation 前必须验证目录恰好包含三个私有 runtime records、terminal receipt 签名有效、Job 已空且 runner 不再存在；随后将 active 目录原子 rename 为严格派生的 cleanup tombstone，这次 rename 是 release commit。commit 后的恢复只删除 private、nonlink tombstone 中三个 runtime record 的 allowlisted subset，不做任何进程观察或控制；未知项、宽 ACL 或 link 会 fail closed 并保留 tombstone。

Windows 仍不支持外部进程认领、外部进程结束和总控台重启。不要通过修改前端或直接调用接口绕过 capability 与每应用 `controlAvailable` 门禁。破坏性生命周期测试只能设置 `LOCALOPS_RUN_WINDOWS_LIFECYCLE_TESTS=1` 后在隔离夹具作用域或 hosted runner 中运行，并且只能操作测试夹具创建的进程；禁止控制任何现有用户进程。

本地 Phase 4 门禁已通过 Windows real discovery 174/174（406.426s）、frontend 24/24、HTTP hardening 6/6（合计 30/30）和 Node 30/30。其中包括 `WIN-LIFE-001..012` 的 12/12、`WIN-SEC-001..014` 的 14/14、HTTP 总控台测试子进程终止后重开，以及 100 次完整启动/Force/释放循环。该结果不是精确提交 CI，也不把 `windowsBetaReady` 改为 `true`。

`VERSION` 是项目版本的唯一权威来源。`Info.plist`、发行包名和发行说明应与它保持一致。

## 安装

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

启动总控台有且只有三种方式，效果相同，按习惯选择：

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

启动后程序只绑定 `127.0.0.1`，从 9600 起尝试端口，被占用则递增（最多 10 个），并自动打开浏览器。命令行参数、环境变量（`CONSOLE_DATA_DIR` / `CONSOLE_LOG_DIR`）见下文“数据、隐私与备份”。

**实际地址在哪里看**：顶栏「重启 :9600」按钮上直接显示当前端口；或看终端输出 / `~/Library/Logs/总控台/console.log`。浏览器手动访问 `http://127.0.0.1:端口号/` 即可。

**停止与重启**：macOS 顶栏「重启 / 停止」控制的是总控台自身（网页服务）。停止总控台**不会**停止启动台里已经运行的应用——它们是独立进程组，会继续运行；下次打开总控台时会自动重新识别。重启总控台会加载磁盘上的最新代码，同样不影响运行中的应用。Windows Phase 4 的总控台重启/停止控制保持禁用；受管 Job 由独立 runner 持有，因此测试创建的总控台进程退出并重开后仍可重新验证和控制同一 generation。

## 使用

打开页面后，左侧是导航轨，右侧是信息栏；所有数据每 2 秒自动刷新。

### 启动台（管理你的服务与任务）

- **添加服务/任务**：点「+ 添加服务」卡片或页头快捷按钮。选择工作区文件夹后会自动识别项目类型（Node/pnpm、Hexo/Hugo、Django/FastAPI、Go、Rust、静态站点等）并给出候选命令；也可以「选择脚本」或完全手动填写。`service` 是长期服务（带端口语义），`task` 是有明确结束时间的批处理（强制无端口）。
- **卡片**：大按钮启动/停止（任务是运行/中止）；右侧一排小按钮（复制链接/日志/诊断/重启/编辑/删除）常显，不用悬浮。运行中显示端口与时长；配置失效（目录/脚本丢失）会直接标出原因并禁用启动，点开「启动诊断」有修复建议。
- **筛选**：每个分区右上角可按 全部/运行中/已停止/异常（任务为 全部/运行中/成功/失败/已取消）过滤，点按即时切换。
- **排序**：鼠标拖拽，或聚焦卡片后按空格进入键盘排序（方向键移动，空格确认）。
- **批量停止**：右侧「快捷操作」里可一键停止全部运行中的应用（有确认框，逐个安全停止，绝不按端口杀进程）。

### 服务监控（看这台 Mac 在跑什么）

- **概览卡**：在线服务/后台应用/总 CPU/总内存（带最近一分钟负载曲线）/端口警告/最后更新。
- **服务表格**：每个服务的 PID、端口、目录、负载、时长、状态，以及**启动者徽标**——溯源显示这个进程是哪个 AI 助手（Codex/Claude/Kimi 等）、编辑器（VS Code/Cursor 等）、终端或总控台启动的。点端口直接打开服务；行尾按钮可加入启动台、置顶、隐藏、展开完整命令或安全结束进程。
- **发现新端口**：页面打开期间新出现的监听端口会单独提醒，可一键「加入启动台」（自动识别项目并原子认领进程）、「忽略并隐藏」或「暂时关闭」。
- **后台与已隐藏**：系统/GUI 应用进程默认折叠在「应用后台」；被隐藏的服务可随时恢复。
- **关注的进程**：输入关键字（如 `ffmpeg`）回车，匹配进程实时列出。

### 日志中心（⌘J）

导航轨「日志中心」或快捷键 ⌘J（⌘L 是浏览器保留键）：所有应用按运行中优先排列，点开任意一行看实时日志；底部固定总控台自身日志入口。

### 设置中心

导航轨齿轮：任务完成通知开关（系统通知，切走页面也能收到）、外观三态（自动/浅色/深色）、版本/端口/工作目录/数据目录信息。

### 命令面板（⌘K）

全局搜索并执行：添加服务/任务、启动/停止/重启任意应用、打开页面、查看日志、切换视图、开关任务通知、查看总控台日志等，全键盘操作。

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

运行数据与程序目录分离，默认放在 macOS 用户资料库：

| 路径 | 内容 | 备份建议 |
| --- | --- | --- |
| `~/Library/Application Support/总控台/config.json` | 应用命令、本地路径、端口、标记和运行识别信息 | 必须 |
| `~/Library/Application Support/总控台/config.json.bak` | 上一份已知良好的配置 | 必须 |
| `~/Library/Application Support/总控台/icons/` | 用户上传的图标和站点图标 | 按需 |
| `~/Library/Logs/总控台/` | 应用与总控台运行日志 | 通常不需 |

目录权限会收紧为 `0700`，配置、图标和日志文件为 `0600`。这些文件仍可能含个人路径、完整 shell 命令和日志内容；不应进入 Git，也不应随发行包或故障报告对外传播。

### 旧版数据首次迁移

如果新目标目录尚不存在，首次启动会将项目内旧 `data/config.json{,.bak}` 和 `data/icons/` 安全复制到 Application Support，将 `data/logs/` 复制到 Library Logs。迁移使用临时目录后原子落位，并且：

- 旧 `data/` 始终保留，不会自动删除。
- 目标已存在时绝不覆盖或合并，避免把更新的用户数据换回旧版。
- 符号链接和非普通文件不会被复制。
- 显式设置 `CONSOLE_DATA_DIR` 或 `CONSOLE_LOG_DIR` 时，对应目录不执行旧数据自动迁移。

需要自定义路径时：

```bash
CONSOLE_DATA_DIR="/private/path/console-data" \
CONSOLE_LOG_DIR="/private/path/console-logs" \
python3 server.py
```

自定义值必须是非空的绝对路径，并指向总控台专用的非符号链接子目录；不要直接填 `/`、用户主目录或项目根目录。

### 备份

1. 不再执行新的启动、停止或编辑操作。
2. 停止总控台。
3. 将 `~/Library/Application Support/总控台/` 复制到受保护的备份目录。
4. 记录当前 `VERSION`，以便恢复时匹配配置格式。

### 恢复

1. 确保总控台已停止，并另存当前 `~/Library/Application Support/总控台/`。
2. 将备份中的 `config.json` 和 `icons/` 复制回对应位置，权限分别设为 `0600` 和 `0700`。
3. 重新启动，逐项确认命令、工作目录和端口。

如果主配置损坏，程序会验证 `config.json.bak` 并恢复主文件。如果两份都不可用，服务进入只读保护状态，不会用空配置覆盖它们。`config.json.bak` 保留的是每次修改之前的上一份良好配置，而不是主文件的同内容副本。

## 升级

1. 阅读 `CHANGELOG.md`，确认是否有配置或平台变更。
2. 停止总控台并完整备份 `~/Library/Application Support/总控台/`。
3. 用新版本替换程序文件；用户数据保持在 Library 目录中。
4. 运行 `make check`。
5. 启动后检查应用数量、主题、关注关键字和一个可控服务的完整启停。

当前配置为 schema v2，启动时逐版执行显式、幂等迁移。v2 保留旧 `command`，Windows Phase 4 只会执行通过静态预检的结构化 `commandSpec`；POSIX/待复核命令仍不可执行。新程序不会静默降级它不认识的更高 schema；回退程序时仍应同时恢复与该版本匹配的数据备份。

## 卸载

1. 如果不希望已启动的服务继续运行，先在启动台逐个停止它们。
2. 停止总控台。
3. 按需导出 `~/Library/Application Support/总控台/` 备份。
4. 将整个项目目录移到废纸篓。
5. 确认不再需要数据后，手动删除 `~/Library/Application Support/总控台/` 和 `~/Library/Logs/总控台/`。

程序不会安装系统启动项，卸载时也不会自动删除用户数据。

## 安全边界

总控台不是多用户服务器或远程管理面板。它能以当前 macOS 用户的权限执行你保存的 shell 命令，因此：

- 只添加你已检查且信任的命令和工作目录。
- 不要将服务绑定到 `0.0.0.0`，不要通过反向代理、SSH 隧道或端口映射对外暴露。
- 不要在共享或不受信任的用户账户中运行。
- 不要把 Application Support 中的 `config.json`、Library Logs 日志或故障截图未经脱敏就上传。
- 本地回环绑定只是第一层边界，不能替代写接口的 Host/Origin/控制令牌防护。发布验收时必须执行 `RELEASE_CHECKLIST.md` 中的安全项。

## 故障排查

### 双击后没有界面

- 确认 `python3 --version` 可用且符合要求。
- 查看 `~/Library/Logs/总控台/console.log`。
- 用 `python3 server.py` 从终端启动，直接查看错误。
- 不要单独移动 `总控台.app`；它必须保持在项目根目录。

### 9600 打不开

程序可能已选择 9601–9609。查看终端输出或 `~/Library/Logs/总控台/console.log` 中的实际地址。服务可访问时，`GET /api/health` 会返回程序版本、配置 schema 和降级原因，且不会执行 `ps/lsof` 扫描。

### 应用启动失败

- 先打开该应用的日志和“启动诊断”。
- 确认工作目录仍然存在、命令可在普通 shell 中运行。
- 检查启动瞬间配置端口是否正被其他进程占用；不同项目允许保存相同的常见开发端口。
- Finder 启动的应用不会读取你的 shell 配置；总控台会补入常用 Node/Homebrew 路径，但非标准安装仍可能需要显式绝对路径。

### 配置丢失或损坏

停止总控台，保留当前 `config.json`，然后按上文“恢复”流程使用已知良好的 `config.json.bak` 或离线备份。

## 开发

macOS runtime 无第三方 Python 依赖；Windows runtime 使用 `requirements-windows.txt` 中精确锁定的 `psutil` 与 `pywin32`。重新生成品牌图标派生文件或图标库时需要开发依赖：

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements-dev.txt
```

主要目录：

```text
server.py                 共享 Python HTTP、配置与业务核心
localops/platform/        macOS/Windows 原生 adapter
static/                   原生前端、主题、品牌、图标和字体
tests/                    后端、前端契约、发布与交付检查
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

## 参与贡献与安全

- 提交代码前请阅读 [`CONTRIBUTING.md`](CONTRIBUTING.md)，并运行 `make check`。
- 行为规范见 [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)。
- 安全问题不要作为普通公开 Issue 披露；报告方式和脱敏要求见 [`SECURITY.md`](SECURITY.md)。
- 新增或替换字体、图标、插画、纹理等素材时，必须同步更新 [`ASSET_PROVENANCE.md`](ASSET_PROVENANCE.md) 和 [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)。

## 许可与第三方素材

项目自有代码和文档采用 [`MIT License`](LICENSE)。Lucide、Geist Mono 以及项目生成图像等素材可能适用各自的许可或发布限制，不因根目录 MIT 许可证而自动改变，详见 [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) 与 [`ASSET_PROVENANCE.md`](ASSET_PROVENANCE.md)。
