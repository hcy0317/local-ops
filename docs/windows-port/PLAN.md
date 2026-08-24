# Windows Native Port Implementation Plan

- 状态：`PROPOSED`
- 范围：规划，不包含 Windows 实现
- 规格来源：[`../specs/windows-native-port.md`](../specs/windows-native-port.md)
- 审查基线：`main@a5c3adae1f1fa0bd9f0ac7b090ec422e285d0c0f`

## 1. 结论

项目可以迁移到原生 Windows，执行结论为 **GO，按 Phase 0→5 严格门禁推进**。

这不是简单的路径和命令替换。真正的高风险是 Windows 上的进程所有权、跨控制台重连、优雅停止、强制停止和本地多用户边界。最短可靠路径是：

1. 先冻结现有 macOS 行为和 API；
2. 只抽取操作系统边界，不重写共享 core；
3. 先交付 Windows 存储、单实例和只读监控；
4. 再迁移 schema、命令模型和平台 UI；
5. 最后单独实现并验证 runner + Job Object 生命周期；
6. 真实 Win10/Win11 和干净机器打包验收通过前，不声明 Beta Ready。

Phase 4 验收前，Windows 上的启动、停止、重启、外部认领和任意进程结束必须保持禁用。这样用户可以先安全获得监控价值，又不会在所有权证明不完整时暴露破坏性能力。

## 2. 已验证基线

| 项目 | 当前事实 | 规划影响 |
| --- | --- | --- |
| Git 基线 | `main` HEAD 与 Spec 基线完全一致 | 无需处理基线后的平台漂移 |
| 代码形态 | `server.py` 4,071 行；HTTP、配置、扫描、生命周期和启动器集中在一个文件 | 只抽平台边界，保留兼容入口，不做 controllers/services 重写 |
| 运行时 | Python 标准库；前端为原生 HTML/CSS/ES Modules | Windows 依赖必须使用平台 marker/独立 requirements，不影响 macOS |
| 平台耦合 | 顶层导入 `fcntl`，并直接使用 `os.getuid()`、`lsof`、macOS `ps`、`osascript`、`killpg`、`/bin/bash` | Phase 1 必须先解决导入和依赖方向，不能直接在原函数内堆 `if win32` |
| Windows 当前状态 | 在 Windows 导入 `server.py` 立即因缺少 `fcntl` 失败 | 当前 Windows 还不能运行任何后端测试或服务 |
| 自动测试 | 159 个 Python test method、7 个 Node test | 现有行为可作为 macOS contract 基线，但要拆出平台无关和平台专属测试 |
| CI | 只有 `macos-15` 的 check/release job | Phase 2 前必须增加 Windows job，并拆分 common/macOS/Windows checks |
| 发布工具 | allowlist 只包含 `server.py`、`static/` 和 macOS `.app` 等现有内容 | 新 `localops/` 包、runner、Windows 资源必须显式进入发行审计 |
| 本轮环境 | Windows 11 x64，非管理员；Python 3.13.13、Node 24.16.0 | 可做 Windows 非管理员开发验证，但不能替代 Python 3.12、Win10、干净 VM 或 macOS 验收 |

当前状态：`WINDOWS_BETA_READY=false`。Windows 工程实现尚未开始。

## 3. 产品与工程边界

### 3.1 必须保持

- 单一双平台代码库；共享 HTTP/API、配置、日志、项目识别和前端。
- HTTP 仅绑定 `127.0.0.1`；Host、Origin、Sec-Fetch、控制会话和 Content-Type 校验 fail closed。
- 配置临时文件 + 原子替换 + 上一份良好备份。
- macOS 的运行 token、进程组和 UID 安全属性不降级。
- 关闭控制台不停止已受管服务。
- 身份不完整时显示 `unknown/orphaned/degraded`，不猜测、不控制。

### 3.2 明确不做

- Windows-only 复制工程、Electron/Tauri 重写、WSL 正式运行时。
- 自动翻译 POSIX shell 命令。
- Windows v1 外部进程树认领和停止。
- 按端口、裸 PID、进程名或 cwd 证明所有权。
- 管理员模式、Windows Service、ARM64 正式发行、自动签名或自动发布。

## 4. 目标依赖关系

```mermaid
flowchart LR
    P0["P0: Freeze baseline"] --> P1["P1: Platform contract + macOS adapter"]
    P1 --> P2["P2: Windows storage, lock, read-only monitoring"]
    P2 --> P3["P3: Schema v2, commandSpec, import, UI"]
    P3 --> P4["P4: Runner, Job Object, lifecycle"]
    P4 --> P5["P5: CI, packaging, real-machine Beta gate"]
```

任何 Phase 未通过时，只允许继续与阻塞项独立的只读分析、文档和单元测试，不进入下一阶段的破坏性能力。

## 5. 关键实现决定

### D1. Core 只依赖 `PlatformBackend`

`server.py` 保留入口、HTTP 路由和业务编排。平台能力移到窄包中，业务层不得直接 import `fcntl`、`psutil`、`pywin32` 或调用 `lsof/ps/osascript`。

用户影响：同一套配置和 UI 可跨平台演进；平台修复不会在 HTTP handler 中形成大量分支。

### D2. 扫描能力与控制所有权完全分离

Windows scanner 可以展示可读取的监听进程，但普通扫描结果不构成停止权限。受管进程破坏性操作只接受强类型 `RuntimeIdentity`；程序入口是独立的窄例外，仅接受前端冻结、服务端与平台双重复验的当前用户 `pid + executable + createTime` 观察快照。

用户影响：即使某个外部进程占用了相同端口，Local Ops 也不会误杀它。

### D3. Windows 生命周期默认关闭

后端通过 `platform` 和 `capabilities` 告知前端可用能力。Phase 2/3 的 Windows 后端只启用只读扫描、配置和选择器；生命周期能力直到 Phase 4 全部门禁通过才开启。

用户影响：未完成能力不会显示成可点击但危险的按钮。

### D4. `commandSpec` 是执行事实来源

保留旧 `command` 字段用于展示、旧 macOS 行为和渐进迁移；Windows 执行只使用经校验的 `commandSpec`。`direct` 不经过 shell，`cmd` 和 `powershell` 使用各自明确的启动及引用规则。

用户影响：中文、空格和特殊字符路径不会因字符串重新解析而产生注入或错误执行。

### D5. Runner 不写主配置

Windows runner 只写受 ACL 保护、带 generation 的 runtime receipt。主控制台验证 receipt 后以 compare-and-swap 更新配置。

用户影响：控制台与 runner 不会并发破坏 `config.json`，延迟的旧请求也不能控制新实例。

### D6. 依赖按平台隔离

- macOS/shared：继续不引入 Windows runtime dependency；
- Windows runtime：固定已验证版本的 `psutil`、`pywin32`；
- Windows build：固定已验证版本的 PyInstaller；
- 不为已有标准库或依赖能完成的工作增加新包。

## 6. 分阶段执行计划

## Phase 0：基线冻结与风险登记

目标：建立可恢复、可审计的迁移起点，不改业务代码。

任务：

- 创建 `docs/windows-port/STATE.json`、`STATUS.md`、`DECISIONS.md`、`TEST-EVIDENCE.md`；
- 记录分支、实际 HEAD、工作树、工具链和环境能力；
- 将现有 API/state/config 关键输出固化为脱敏 fixture/golden；
- 列出所有 macOS-only import、系统命令、路径、权限和 UI 文案；
- 在 macOS 运行现有权威检查，在 Windows 记录当前 `fcntl` import failure；
- 确认测试只操作夹具进程和动态端口。

Gate：

- 没有业务代码差异；
- 基线测试命令、数量、通过/失败/未运行状态有证据；
- macOS-only 耦合清单覆盖 import、caller、API 和 UI；
- `STATE.json` 与 Git 实际状态一致。

## Phase 1：平台契约与 macOS 零回归

目标：让 shared core 不再直接依赖 macOS，并保持现有行为。

预计文件：

```text
localops/__init__.py
localops/platform/contracts.py
localops/platform/loader.py
localops/platform/macos.py
tests/contract/
tests/fakes/
server.py
```

任务：

- 定义 `PlatformBackend`、快照状态和强类型身份对象；
- 将路径、锁、进程、端口、cwd、启动、停止、选择器、浏览器和控制台重启搬到 macOS adapter；
- 注入 fake backend，覆盖成功、权限拒绝、超时和部分结果；
- 保持 `server.py` 兼容入口和现有 API shape；
- 将扫描失败从“空机器”改为显式 degraded。

Gate：

- macOS 现有检查和测试全部通过；
- shared core 在 Windows 可导入；
- golden API/config 无未解释差异；
- core 不直接引用 macOS-only API；
- 不包含 Windows 生命周期伪实现。

当前环境上 Phase 1 最高只能达到 `IMPLEMENTED_UNVERIFIED`；最终 `PASS` 需要 macOS CI 或真实 macOS。

## Phase 2：Windows 存储、单实例和只读监控

目标：普通 Windows 用户可以安全启动控制台并查看本地服务，但不能控制进程。

预计文件：

```text
localops/platform/windows.py
requirements-windows.txt
tests/windows/
.github/workflows/ci.yml
```

任务：

- 使用 Known Folder API 解析 `%LOCALAPPDATA%\LocalOps`；
- 实现当前 SID、关键 DACL 验证、Named Mutex 和 Windows 路径防护；
- 使用 `psutil`/Win32 生成 listener/process snapshot，显式处理 AccessDenied、NoSuchProcess 和竞态；
- 实现 Windows 原生路径选择器 adapter；
- 为 HTTP server 使用 Windows 独占地址语义；
- 增加 Windows import/syntax/unit CI；
- 返回 capability flags，禁用 kill/attach/start/stop/restart。

Gate：

- Windows 10/11 普通用户只读控制台可运行；
- 系统进程权限拒绝不会使 `/api/state` 崩溃；
- 扫描失败为 degraded，不返回误导性空结果；
- 同一数据目录只有一个 writer；
- ACL、盘符根、UNC、junction、中文和空格路径测试通过；
- 破坏性 API 在 Windows 明确拒绝且无副作用。

## Phase 3：Schema v2、命令模型、配置导入和兼容 UI

目标：建立可执行但尚不启动进程的 Windows 配置和前后端契约。

编码前先创建 `docs/windows-port/API-CONTRACT-v2.md`，定义新增字段、稳定错误 code、generation 语义和导入预览/提交契约。

预计文件：

```text
localops/command_spec.py
server.py
static/app.js
static/index.html
static/js/overlays.js
static/js/launchpad.js
static/js/services.js
static/js/widgets.js
tests/contract/
tests/windows/
```

任务：

- 实现 schema v1→v2 幂等迁移和 future-schema 只读保护；
- 增量增加 `platform`、`capabilities`、`commandSpec`、`platformCompatibility` 和错误 `code`；
- 实现 direct/cmd/PowerShell 构造、静态预检和特殊字符测试；
- 扩展 `.cmd/.bat/.ps1`、PATHEXT、npm/pnpm shim 和 Python launcher 检测；
- 实现 macOS 配置导入的 preview → map → validate → staged write → commit/rollback；
- 删除前端 POSIX quote 和 `/` 路径解析；
- 按平台显示快捷键、路径、启动方式和能力说明；
- Windows 隐藏外部认领并保持生命周期按钮禁用。

Gate：

- v1→v2 迁移幂等，N-1 与 future-schema 测试通过；
- 导入不覆盖目标，运行身份全部清空，重复导入幂等；
- POSIX 命令默认 `needs_review`，不自动转换；
- 特殊字符和结构化 argv 注入测试通过；
- macOS API/UI 无回归；
- Windows 没有可触发未实现生命周期的 UI/API 路径。

## Phase 4：Windows runner、Job Object 与安全生命周期

目标：只控制 Local Ops 自己启动且身份完整的 Windows 进程树。

预计文件：

```text
localops/windows/runner.py
localops/windows/job_object.py
localops/platform/windows.py
tests/windows/test_runner.py
tests/integration/test_windows_lifecycle.py
```

任务：

- 实现 SID + PID/create-time + generation + token digest + runner/Job identity；
- 创建当前用户 ACL 的 Named Job Object、runtime receipt 和控制 IPC；
- suspended 启动 → 加入 Job → 持久化身份 → resume，失败时事务清理；
- 控制台关闭后 runner/Job/目标继续；控制台重开后 challenge/response 严格重连；
- 所有 start/stop/restart/delete 使用 expected generation；
- 普通停止尝试兼容协议，超时保留身份且不强杀；
- 显式 Force 重新完成全身份校验后才终止 Job；
- IPC、receipt、ACL 或身份校验不完整时 fail closed；
- 完成添加—启动—日志—诊断—停止—重启 UI 流程。

Gate：

- Spec 的 `WIN-LIFE-001..012` 与 `WIN-SEC-001..014` 全部通过；
- 不使用 `taskkill /T`、裸 PID `TerminateProcess` 或 `os.kill(pid, 0)`；
- runner 异常只影响自己的 Job；
- 旧 generation 请求不能影响新实例；
- 普通停止超时不清身份、不自动 Force；
- 安全测试只在隔离 Windows VM 操作夹具进程。

任何误杀、未授权 HTTP 副作用、加入 Job 前执行命令、token 泄露或 ACL 泄露立即设置 `BLOCKED_SECURITY` 并关闭 Windows 生命周期能力。

## Phase 5：CI、打包和 Beta 验收

目标：生成可追溯的 x64 Windows Beta，并在真实目标环境验收。

任务：

- CI 拆为 common、macOS、Windows，Windows 不依赖 Make/Bash/plutil；
- 更新 `tools/check_project.py` 和 `tools/build_release.py` 的平台检查及显式 allowlist；
- 新增 `tools/build_windows.py`，构建 `PyInstaller onedir + windowed + x64 zip`；
- 检查版本资源、静态资源、依赖、许可证、敏感数据和发行内容；
- 在 Win10、Win11、无 Python 干净 VM、中文路径环境完成 smoke test；
- 在 macOS 重跑完整回归；
- 记录产物大小、SHA-256、Defender 结果、已知限制和回滚步骤。

Gate：

- common/macOS/Windows CI 全绿；
- 未安装 Python 的干净 Windows 可启动；
- 程序目录只读时仍运行，用户数据只写 Local AppData；
- 真实非管理员生命周期 smoke test 通过；
- 发行包不含用户数据、日志、token、凭据、缓存或绝对路径；
- 素材权利和 `REVIEW_REQUIRED` 项有发布结论；
- 只有 Spec 第 3.2 节全部满足，才设置 `WINDOWS_BETA_READY=true`。

## 7. 验证矩阵与环境门槛

| Gate | 最低环境 | 当前机器可完成 | 不可替代证据 |
| --- | --- | --- | --- |
| Shared unit/contract | Windows 或 macOS，受支持 Python/Node | 是，但需先完成 Phase 1 import 边界 | macOS/Windows CI 同时运行 |
| macOS regression | macOS 12+、Python 3.12 | 否 | `make check` 和真实 macOS UI/生命周期 |
| Windows read-only | Win10/11 x64 非管理员 | Windows 11 可做开发验证 | Win10 + Win11 两套 smoke evidence |
| Windows lifecycle | 隔离 Windows VM | 不应在日常进程环境做破坏性测试 | 全部 LIFE/SEC fixture tests |
| Packaging | 干净 Windows x64、无 Python | 否 | onedir zip 启动、内容审计和 hash |
| Release | macOS + Win10 + Win11 + 资产审批 | 否 | 完整 release checklist 和签字 |

测试状态只使用 `PASS | FAIL | NOT_RUN | SKIPPED`；`SKIPPED` 必须写原因。没有运行的真实平台测试不得由 mock 或 CI 配置存在代替。

## 8. 风险登记

| 风险 | 严重度 | 控制措施 |
| --- | --- | --- |
| PID 复用或错误身份导致误杀 | Critical | create-time、SID、generation、token/IPC、Job 全量校验；失败关闭 |
| 启动后才加入 Job，产生逃逸进程 | Critical | suspended create；Job 与 receipt 成功后才 resume |
| 控制台与 runner 并发破坏配置 | High | runner 只写 receipt；控制台 CAS 更新主配置 |
| cmd/PowerShell 特殊字符注入 | High | direct argv 优先；各 shell 独立引用；展示字符串不可执行 |
| v1→v2 或 macOS 导入造成数据损失 | High | preview、备份、staged write、原子落位、幂等和 rollback |
| 平台抽取引入 macOS 回归 | High | 先搬运 macOS adapter；golden + 原测试 + macOS gate |
| 开发目录可用但打包漏模块/资源 | High | 显式 allowlist、包内容测试、干净 VM 启动 |
| Python 3.13 开发结果掩盖 3.12 问题 | Medium | CI 固定受支持 Python；本机结果注明版本 |
| 素材或签名状态阻断公开发布 | Medium | 工程 Beta 与公开 Release Gate 分离，台账未清不发布 |

## 9. 提交与审查边界

建议提交边界：

1. `docs: add Windows port specification and planning state`
2. `refactor: introduce platform contract and macOS adapter`
3. `feat: add Windows read-only platform backend`
4. `feat: add schema v2 and structured Windows commands`
5. `feat: add Windows managed process runner`
6. `build: add Windows CI and Beta packaging`

重构与行为变化分开；每个提交只包含一个可验证目的。暂存使用显式路径，不使用 `git add .` 或 `git add -A`。未经用户授权不 commit、push、创建 PR、发布或签名。

## 10. Phase 0 实施入口

下一次开始实现时，先执行：

1. 读取 `AGENTS.md`、`MEMORY.md`、本 Spec、README、SECURITY、RELEASE_CHECKLIST 和全部测试；
2. 核对分支、HEAD、工作树和 `docs/windows-port/STATE.json`；
3. 创建 Phase 0 四个状态文件；
4. 运行当前环境可运行的基线检查并记录 `NOT_RUN`；
5. 完成平台耦合清单和 golden fixtures；
6. Phase 0 Gate 通过后才开始平台抽取。

本计划不授权实现、push、PR、Release、签名证书或真实进程破坏性测试。
