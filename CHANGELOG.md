# 变更记录

本项目的重要变更记录在此。格式参考 Keep a Changelog，版本号使用语义化版本。`VERSION` 是当前版本的唯一权威来源。

每个面向用户的重要功能、修复、安全或兼容性变化先写入
`Unreleased`；发布时再移动到带版本号和日期的章节。纯缓存清理、
一次性构建产物和不影响行为的内部整理由 Git 历史记录，不在此逐项罗列。

## [Unreleased]

### Added

- 增加可选的 Tailscale Serve 身份代理会话：回环 Caddy 网关以 Tailscale 用户头和受保护代理 bearer 双重证明身份，只读 `/api/state` 首请求可换取 Secure/HttpOnly/SameSite 浏览器会话；写请求和管理员能力仍分别要求会话与二次密码解锁。
- 增加 Windows Phase 5 本地打包候选：Python 3.12 + PyInstaller onedir/windowed/x64 unsigned zip、确定性 checksum/manifest sidecars、包内容/版本/依赖/许可/敏感数据审计，以及只操作隔离夹具的最终 package smoke。
- 增加冻结 windowed 入口；在无标准流时把诊断写入受保护的 Local AppData console log，并由同一 executable 分派 HTTP console 与 per-generation runner。
- 增加 Windows Phase 4 生命周期源码候选：per-app runner、受保护 Named Pipe/回执、`CREATE_SUSPENDED` 启动、Named Job Object、generation compare-and-swap，以及普通停止与显式 Force 的分离流程。
- 增加 `docs/windows-port/API-CONTRACT-v3.md`，冻结 11 字段公开 runtime identity、生命周期状态、稳定错误码和前端 generation 规则；隔离 Windows CI 仅运行测试夹具进程。
- 增加 Windows Phase 3 兼容性源码预览：schema v2、`commandSpec`、静态命令预检、Windows 脚本/PATHEXT/npm/pnpm/Python 3.12 项目候选，以及平台化快捷键、路径和能力说明。
- 设置中心增加显式 macOS 配置导入向导，支持零写入预览、路径映射、逐项选择、原子提交、幂等重试与 CAS 回滚；旧运行身份和进程状态不会被导入。
- 增加 `docs/windows-port/API-CONTRACT-v2.md`，冻结 Phase 3 的配置、命令、路径选择、导入和稳定错误码契约。
- 增加 Windows Phase 2 只读源码预览：Local AppData、SID/DACL、Named Mutex、`psutil` 进程/监听快照、原生路径选择器、独占回环端口语义和 Windows Python 3.12 CI。
- `/api/state` 增加 `platform` 与 `capabilities`，供调用方识别当前平台实际开放的能力。
- 顶栏新增 GitHub 仓库图标按钮，点击在新标签页打开项目源码仓库。
- 增加用户/开发文档、备份恢复和升级卸载指南。
- 布局升级为指挥台结构：左侧图标导航轨、启动台与服务监控双视图 KPI 概览卡（含 CPU/内存火花线）、右侧实时动态/实时告警与端口/资源 TOP 5 信息栏、小贴士、页头快捷操作，以及服务/任务分区筛选芯片；服务表格增加 PID、状态列与 CPU 迷你负载条。结构样式集中于 `base.css`。
- 导航轨与侧栏补齐聚合能力：日志中心弹层（⌘J 呼出，应用与总控台日志目录页，⌘L 为浏览器保留键故用 ⌘J）、设置中心弹层（任务完成通知开关、浅色/深色/自动外观、版本与目录信息）、快捷操作部件的批量停止服务（确认后逐个安全停止，绝不按端口结束进程）。
- 服务表格新增**进程溯源**：沿 PPID 链识别并显示每个服务的启动者（AI 编程助手/编辑器/终端/总控台），副标题行展示来源图标与名称。
- 新增「Ops 指挥台」为唯一 UI 主题（深空蓝黑/雾灰双色、柔和圆角细边、蓝色强调），主题清单中固定排首位；保留 `#themeCss` 整包加载与 `uiTheme` 配置机制，但不再提供多主题与主题选择界面。
- 增加统一项目检查入口、显式测试发现和发布核对表。
- 增加项目权利声明与第三方素材清单。
- 增加根目录 `VERSION` 统一版本源，`/api/state` 暴露版本/schema/降级信息，并增加不执行进程扫描的 `/api/health`。
- 增加 `schemaVersion=1` 和显式、幂等的逐版配置迁移器。
- 增加 `SECURITY.md`、`CONTRIBUTING.md`、社区行为规范以及 GitHub Issue/PR 模板。
- 增加 `ASSET_PROVENANCE.md`，并用路径、SHA-256 与发布状态检查覆盖字体、品牌图片、插画和程序化纹理。
- 增加统一品牌标识、网页 favicon、Apple Touch Icon、macOS App Icon 与可重建的品牌导出脚本。
- 命令面板增加“添加服务”和“添加批处理任务”入口；应用卡片增加可取消的键盘排序。
- 服务监控增加会话级新端口发现栏，可将新监听服务加入启动台、忽略隐藏或暂时关闭。
- 应用状态增加只读配置健康检查，在运行前识别丢失的工作目录、脚本和运行时，并提供修复入口。

### Changed

- Windows 常驻总控台改为受保护 onedir `LocalOps.exe` 的 `RunLevel Limited` 计划任务；控制器若意外处于提权 token，会在创建普通受管进程前 fail closed。计划任务引用/启停、Docker Compose/单容器引用/启停和管理员程序启停能力保持不变。
- Windows 管理员代理协议升级为 v2：除结构化启动外，还负责受保护程序的精确观察与非 Force 停止；旧 launch-only 代理必须显式升级后才显示停止入口。
- 管理员代理升级会在新任务定义注册成功后精确停止旧固定实例，再由解锁流程启动新协议，避免旧进程继续占用 Named Pipe。
- 管理员代理的 UAC 安装事务固定到当前用户 `%LOCALAPPDATA%\LocalOps\runtime\elevation-install`，不依赖提权进程可能丢失的 `CONSOLE_DATA_DIR` 环境覆盖，修复自定义数据目录下只显示 ACL 校验失败的问题。
- broker 计划任务启动后，控制器会在有界期限内重试 Named Pipe 尚未出现、繁忙或短暂断开的状态，修复安装成功后立即解锁却提示 `WaitNamedPipe` 找不到文件的问题。
- 管理员代理协议升级为 v3：当 Limited 控制器被系统拒绝连接 Task Scheduler COM 时，代理仅按规范化路径执行固定的计划任务查询、运行、停止、启禁和历史频道操作；写操作要求当前浏览器管理员会话，CLI 不继承权限。
- 浏览器控制改为一次性 fragment bootstrap 换取 HttpOnly/SameSite 会话；本地 CLI 改用当前用户私有目录中的每进程 bearer，敏感 GET 与所有写接口不再接受 headerless loopback 请求。
- Windows Phase 5 exact-CI engineering candidate `5daddece8a06d1fdd382d1814e58be7b777ceae4` 已通过 run `31780819809` 的 common、macOS full/source-release 与 Windows lifecycle/package gates，并上传可审计 unsigned artifact；完整 Phase 5 外部验收仍未关闭，因此状态保持 `IMPLEMENTED_UNVERIFIED`、`windowsBetaReady=false`。
- Windows capability 现在只为完整验证的 Local Ops Job 开启 `launch_managed/stop_managed/force_stop_managed`；`kill_external/attach_external/restart_console` 保持关闭。
- Windows 浏览器界面现在同时按全局 capability 与每应用 `lifecycleStatus/controlAvailable` 呈现操作，并为每次启动、停止、重启、运行中修改和删除冻结 `expectedGeneration`；外部进程控制入口仍保持禁用。
- 默认将配置/图标移至 `~/Library/Application Support/总控台`，日志移至 `~/Library/Logs/总控台`。新目标不存在时仅首次复制旧 `data/`，不删除原文件。
- `config.json.bak` 现保留修改前的上一份良好配置，而不是与主配置相同的副本。
- 运行目录权限收紧为 `0700`，配置、图标和日志文件为 `0600`。
- 项目自有代码和文档改用 MIT License；README 明确 Preview / Alpha、源码预览和非远程运维边界。
- 公开发行检查会拒绝仍标记为 `BLOCKED` 或 `TO_REPLACE` 的素材，并要求对 `REVIEW_REQUIRED` 项形成人工结论。
- 表单把外观设置收进可选区域，服务/任务分别优先聚焦“选择项目”和“选择脚本”。
- 修正 900px 附近顶栏导航异常放大，并补齐移动端、高对比度、键盘焦点和表格语义。
- 移除来源和再分发链路不完整的精简中文字体，改用 macOS 系统字体栈。
- 批处理结果改为成功、取消、失败、中止四态；脚本内部用户取消统一使用退出码 130。
- 任务运行中的动作统一使用“中止”，服务继续使用“停止”，诊断和编辑提示随类型变化。
- 多个启动配置现在可以共享同一端口；项目归属由受管进程身份和工作目录判断，只有实际启动时的监听占用才会阻止运行。

### Fixed

- 修复管理员程序解锁后 `/api/state` 冷缓存约 12.7 秒、导致远程页面周期误报断连的问题：broker 现在先按进程名和完整 EXE 路径过滤，再只对匹配候选查询 SID/创建时间；现场冷缓存降至约 2.5–2.6 秒。
- 收紧管理员代理安装边界：源码 checkout 现在会在包发现、路径选择和 UAC 前拒绝安装；HTTP 安装接口不再接受 `packageExecutable` 覆盖，只有当前冻结 Windows 包可以安装或升级自身。
- 修复 Windows 单实例 Mutex 句柄默认可继承的问题：句柄现显式不可继承并轮换到新命名空间，旧控制器退出后，仍在运行的业务子进程不会阻塞新的 Limited 控制器。
- 修复冻结 windowless 总控台轮询 Docker 时反复创建可见 `cmd/conhost` 窗口的问题；Docker CLI 默认 runner 现在始终使用 Windows `CREATE_NO_WINDOW`，Guard/Watchdog 定义未改动。
- 修复受保护 `LocalOps-Console` 任务升级时停止后立即启动、与旧实例退出争抢 Mutex 的竞态；安装脚本会等待旧任务离开 Running/Queued 后再注册并启动新定义。
- 修复 Windows 源码 venv redirector 在启动后立即退出、使短命 PID 被误作 runner 根身份的问题：runner 改由 base Python 承载，并通过 `__PYVENV_LAUNCHER__` 保留目标 venv 上下文。
- 修复 runner 继承控制台导致目标没有私有 console group、冻结同 executable child 复用 PyInstaller 父进程环境、`win32timezone` 漏打包和相对 executable 解析不稳定的问题；现在先 `FreeConsole`/`AllocConsole`，为冻结 child 设置 `PYINSTALLER_RESET_ENVIRONMENT=1`，显式加入 hidden import，并在创建目标前解析绝对 executable。
- 修复从服务监控加入启动台时只创建卡片、未认领来源进程的问题；创建与进程认领现由后端原子完成，项目命令识别完成前不能提前保存。明确认领的服务在 Next/Vite 等框架重建监听子进程、PID 变化后，会按端口、当前用户与真实项目目录唯一重新关联。
- 修复 Candy 主题超大标题的英文粗体描边出现双重轮廓，并让英文副标题在窄屏明确换行。
- 修复批处理脚本内取消被误报为运行成功，以及任务成功退出被诊断成“服务过早退出”。
- 重启服务前先检查当前配置，避免脚本或目录失效时先停止仍在工作的旧进程。
- 修复外部进程碰巧监听停止卡片的配置端口时被误认成该卡片、且不会触发新端口发现的问题；端口诊断增加打开占用服务和修改原卡片两种非破坏性处理方式。
- 修复测试服务器、热重载等短命监听停止后仍长期残留在“发现新的监听端口”列表的问题。
- 修复从服务监控把正在运行的进程加入启动台后，新卡片反而把来源进程识别成端口占用者的问题；保存时现在会立即认领来源 PID。

### Removed

- 移除已被统一品牌图、Candy 新插画和系统字体栈替代的旧 Logo、旧插画及两份中文字体文件。
- 移除 Apollo/Candy/8-Bit 三套 UI 主题与主题选择面板、命令面板主题切换项及 Candy 专用 hero 卡；产品收敛为单一「Ops 指挥台」主题，旧的 `uiTheme` 偏好自动回退到 ops。
- 随主题移除不再使用的 Apollo 程序化纹理（deck/metal-brush 系列）、Candy 启动台插画与 `tools/gen_textures.py`；`ASSET_PROVENANCE.md` 与 `THIRD_PARTY_NOTICES.md` 同步核销。

### Security

- 管理员代理安装、解锁、启动和停止现在只接受完成 bootstrap 的浏览器会话；broker token 与逐浏览器 elevation 标记双重校验，避免另一个页面或本地 CLI 复用已解锁的管理员权限。
- 管理员程序停止由 Highest broker 对完整 `pid + executable + createTime + owner SID` 集合先全部复验再执行；受限、混合、过期或部分可验证身份不授予停止，且不提供 force/restart。
- 增加受保护 `control-credential.json` 与 CLI-only `/api/console/open`；浏览器 URL 中的短期 token 只放在 fragment、消费一次后立即从地址栏移除，不写配置或日志。
- 增加 `tools/install_windows_console_task.ps1`，拒绝用户可写源码/venv 和 `Highest` 控制器入口，只允许受保护 `%ProgramFiles%\LocalOps\Broker` 冻结 EXE 注册为 Limited 常驻任务。
- Windows Phase 5 发行审计拒绝用户数据、日志、runtime/token、凭据、缓存、个人绝对路径、不受支持的架构和缺失许可；本地 unsigned artifact 不会因 stripped child PATH smoke 被误标为干净无 Python VM 或 Beta。
- Windows 受管生命周期仅信任当前 SID、generation、runner/root PID 创建时间、HMAC 回执和 Job Object 成员关系；普通停止不会自动升级为 Force，强制停止只终止验证通过的专属 Job。
- raw control token 仅保存在受保护 runtime 文件和 runner 内存中，不进入配置、前端、命令行、日志或诊断；runner 异常退出通过 Job kill-on-close 仅清理自己的进程树。
- request/receipt 原子写入在替换为权威记录前先保护临时文件 DACL；清理恢复只接受签名有效、Job 已空且目录内容精确匹配的 terminal generation，不删除模糊记录、日志或无关文件。
- Phase 3 静态预检和配置导入在任何文件系统探针前拒绝 UNC/设备命名空间；导入源限制为 1 MiB 本地常规文件，事务回执可从 prepared 状态恢复，配置在原子替换后的 ACL 校验失败时保持内存/磁盘一致并转入只读保护。
- Windows 私有目录和文件使用仅当前 SID、SYSTEM 与 Administrators 可访问的受保护 DACL；验证失败时配置进入只读保护。
- Windows Phase 2 检查点曾在 adapter 与 HTTP 路由双重禁用外部认领、进程结束、应用启停/重启和总控台重启；Phase 4 只放开已验证 Job 的受管启停/Force，外部控制与总控台重启继续关闭。
- 将用户配置、日志、图标、token 和临时发行产物排除出版本控制默认范围。
- 主配置与备份均无法验证时进入只读保护，防止用空默认配置覆盖尚可恢复的用户数据。
- 增加私密漏洞报告、Issue/PR 脱敏和公开仓库安全披露门禁。

## [1.0.0] - 2026-07-23

### Added

- Python 3 标准库本地 HTTP 后端，只绑定 `127.0.0.1`。
- 启动台：服务与批处理任务的创建、编辑、排序、启动、停止、重启、日志与诊断。
- 服务监控：端口、进程、CPU、内存、运行时间、关注关键字与分组。
- 读取常见项目配置并提供候选启动命令的本地项目识别。
- 基于 run token、进程组和 UID 的受控进程识别。
- 原子配置写入、同步备份、有界日志读取与轮转。
- Apollo/Candy 双 UI 主题、深浅色模式、命令面板和原生 macOS 文件选择。
- `总控台.app` 后台启动器与 `start.command` 调试入口。
