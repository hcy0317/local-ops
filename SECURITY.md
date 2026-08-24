# 安全政策

macOS 总控台会以当前用户权限执行保存的 shell 命令，并提供启动、停止和结束本地进程的接口。Windows Phase 4 只允许控制由 Local Ops 自己启动、且经 SID、generation、PID 创建时间、HMAC/受保护回执和 Job Object 完整验证的进程树；外部进程结束与认领仍禁用。请把命令执行、身份校验、写接口授权、路径处理、配置完整性和敏感信息泄露问题视为高影响安全问题。

## 支持范围

项目仍处于 Preview / Alpha 阶段。安全修复优先面向默认分支和最新发布版本；旧版本是否继续支持会在对应发行说明中注明。尚未发布的本地开发提交不承诺兼容修复。

## 私下报告漏洞

请优先使用 GitHub 仓库 **Security → Report a vulnerability** 提交私密报告。公开仓库建立后，维护者必须先启用 GitHub Private Vulnerability Reporting，再对外发布版本。

如果私密报告入口暂不可用，请不要在公开 Issue、讨论区或 Pull Request 中披露漏洞细节。请通过仓库所有者 GitHub 个人资料中已经验证的联系方式，只发送“不含漏洞细节、请求建立私密通道”的简短消息；在私密通道确认前不要附带复现代码、日志、配置或路径。

一份有用的私密报告应包含：

- 受影响版本或 commit；
- 操作系统版本/Windows build 与 Python 版本；
- 影响范围和攻击前提；
- 最小化复现步骤；
- 预期行为与实际行为；
- 已完成脱敏的相关日志或请求；
- 你认为安全的修复方向（可选）。

## 必须脱敏的内容

不要提交下列原始数据：

- `~/Library/Application Support/总控台/config.json{,.bak}`；
- `~/Library/Logs/总控台/` 中的日志；
- `%LOCALAPPDATA%\LocalOps\config.json{,.bak}` 与其 `imports/`、`logs/`、`runtime/` 内容；
- 完整 shell 命令、个人工作目录、用户名和主目录路径；
- PID、进程启动 token、访问令牌、密钥或环境变量；
- 用户上传图标或其他不具备公开授权的文件。

请使用 `/Users/example/project`、`TOKEN_REDACTED` 等明确占位符，并在提交前复核截图和录屏。

## 项目安全边界

- HTTP 服务只应绑定 `127.0.0.1`，不得暴露到局域网或公网。可选远程入口仅限私有 tailnet 的 Tailscale Serve/Caddy 回环代理；禁止 Funnel。
- 本项目不是通用多用户权限系统。Tailscale 远程入口只接受网关已过滤的用户身份，并要求 Local Ops 私有代理 bearer 后才可建立普通浏览器会话。
- 只有受信任的本地用户或被网关明确允许的 tailnet 用户才能添加和执行命令。
- 本地回环绑定不能替代 Host、Origin、控制令牌、当前 UID/SID 和受控进程身份校验。
- 静态入口与 `/api/health` 可以在本机回环上读取；所有其他 API GET 和全部写接口必须通过一次性 URL fragment 换取的 HttpOnly/SameSite 浏览器会话，或使用当前用户私有目录中的每进程 CLI bearer。可选 Tailscale 入口只有在回环代理、`.ts.net` HTTPS 同源、有效 `Tailscale-User-Login` 与 `tailscale-proxy-secret` bearer 同时成立时，才允许只读 `/api/state` 首请求签发 `Secure; HttpOnly; SameSite=Strict` 会话；代理身份头不能直接授权写请求。Headerless loopback、仅 `Content-Type` 或端口可达都不是授权证据；CLI bearer 不授予管理员代理安装、解锁、启动或停止权限。
- 管理员程序权限同时要求有效 broker token 与当前浏览器会话的独立 elevation 标记。解锁一个页面不得授权其他页面或 CLI；锁定、控制器退出、PID/create-time/SID 变化和 broker 会话失效都必须撤销权限。
- Windows 私有文件和目录最终必须由当前用户 SID 所有，仅向当前用户、SYSTEM 和 Administrators 授权；`chmod` 结果不能作为 Windows 权限证明。Windows 新对象 owner 来自 access token 的 `TokenOwner`，平台只允许其为当前用户或 Builtin Administrators。仅 creation-time apply 路径可在观察到 token 的 Admin 默认 owner 时，通过一次安全描述符更新把 owner 归一为当前用户并同时应用原 protected DACL；verify-only 的既有记录必须已经是 current-user-owned，Admin-owned 记录也必须拒绝。
- Windows Phase 4 的 `launch_managed/stop_managed/force_stop_managed` 只授权完整验证的 Local Ops Job；`kill_external/attach_external/restart_console` 必须保持 `false`。任一 runner、Job、IPC、回执、ACL 或 generation 证据不完整都必须 fail closed。
- Windows 常驻控制器必须以 Limited token 从 `%ProgramFiles%` 中的受保护冻结包运行。控制器若检测到自身已提权，必须在创建 runtime records 或目标进程前拒绝普通 managed launch；不得以 `Highest` 运行用户可写源码、venv 或其他可替换入口。
- Windows 单实例 Mutex 必须不可继承，并使用与旧版可继承锁隔离的命名空间；冻结 windowless 控制器调用固定系统/Docker CLI 时必须使用 `CREATE_NO_WINDOW`，避免业务子进程持有写锁或轮询产生可见控制台窗口。
- 固定 elevation broker 可以 Highest 运行，但只接受绑定到实际 pipe client PID/create-time/SID 的会话。管理员程序停止只能经 broker 对请求中的全部 `pid + executable + createTime + owner SID` 两阶段复验后执行，不提供 force/restart；任一实例身份不完整时全部 fail closed。
- 管理员代理安装只允许当前冻结 Windows 包安装自身；源码 checkout 必须在包发现、路径选择和 UAC 前拒绝，HTTP 安装请求不得接受可调用方覆盖的包路径。
- 若 Limited 控制器被系统拒绝连接 Task Scheduler COM，固定 broker 只接受有界、规范化的任务路径和 `list/query/run/stop/toggle/history` 操作。计划任务写操作还必须来自已提升的当前浏览器会话；不得接受 shell、任意命令、PID 控制或 CLI bearer 继承。
- broker 观察管理员程序时必须先拒绝进程名/EXE 路径不匹配的噪声候选，再查询 SID 与创建时间；这项性能过滤不得替代停止前对全部 `pid + executable + createTime + owner SID` 的两阶段复验。
- Windows 的 `commandSpec` 是原生命令执行边界；不得解析展示字符串，也不得把 POSIX shell 文本自动翻译成 cmd 或 PowerShell。目标必须先以 suspended 状态加入专属 Job 并持久化身份，才能恢复执行。
- 公开 runtime identity 恰好包含 11 个非敏感字段。raw token、HMAC、pipe 名、runtime 路径和回执路径不得进入配置、API、命令行、日志、诊断或错误响应。
- 普通停止超时必须保留身份且不得自动强杀。显式 Force 必须重新校验相同 generation 和全部所有权证据，只能调用该 runner 持有 Job 的 `TerminateJobObject`。
- request/receipt 原子写入必须在临时文件对其他读取者可见前应用并验证私有 DACL；`os.replace` 之后才可成为权威记录。重连和清理只能验证现有 ACL，不能把已放宽权限的记录静默“修好”后继续控制。
- runtime 释放使用两阶段协议：active generation 在 rename 前必须包含恰好三个私有 runtime records，并通过 token digest、签名 terminal 回执、精确公开身份、空 Job 与 runner absent 验证；原子 rename 到严格派生的 cleanup tombstone 是 release commit。commit 后的 tombstone 恢复只允许删除 runtime root 直属、严格派生命名、private、nonlink 目录中的三个 record allowlisted subset，并且不得执行任何进程观察或控制。任何未知项、宽 ACL、link、非派生路径或模糊证据都必须 fail closed 并保留现场。
- `LOCALOPS_RUN_WINDOWS_LIFECYCLE_TESTS=1` 只允许在隔离夹具作用域或 hosted runner 中对测试自身创建的进程使用；不得控制既有用户进程。
- 配置导入只接受不超过 1 MiB 的显式本地常规文件。预览不得写配置或回执；提交与回滚必须使用配置哈希 CAS，拒绝 UNC、设备命名空间、冲突 ID 和发生后续修改的目标。
- 导入和路径接口的错误响应只返回稳定错误码与通用说明，不得回显内部路径、命令输出、token、适配器异常或堆栈。

修复准备公开前，维护者会尽量与报告者协调披露时间。请勿在修复可用前公开可直接利用的细节。
