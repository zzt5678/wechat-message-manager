# v0.1.0 发布检查清单

当前候选：`0.1.0-rc1`。本清单针对将仓库链接交给一个没有历史上下文的 Codex。所有回执必须脱敏；禁止写入账号 tag、路径、wxid、key、salt、聊天正文、安装包或真实数据库。

## A. RC 仓库与 CI

- [ ] 审查期间 `git status` 只包含计划发布的源码、测试和文档；冻结候选提交后 `git status --porcelain` 必须为空。
- [ ] `python -m compileall -q .` 通过。
- [ ] Windows/macOS、Python 3.9/3.12 四个 CI job 全绿。
- [ ] Python 3.12 的 `setup.ps1/setup.sh` 与 `manage.cmd/manage.sh` 非 help 冒烟通过。
- [ ] 依赖安装后的 `python -m pip check` 通过；直接依赖版本与 `requirements.txt` 一致。
- [ ] 平台范围硬门、动态 manifest/非连续分片查询、分片 drift、WAL/journal、查询前后 freshness、refresh/query 并发锁、整批 refresh staging/失败回滚、输出批准/预算/控制字符、Skill `.venv`、保护存储读回、Mac PID/独占进程测试全绿。
- [ ] Actions checkout 使用 `fetch-depth: 0`；`python scripts/secret_scan.py` 扫描当前文件和完整可达 Git 历史通过。
- [ ] Markdown 本地链接、`git diff --check`、shell/PowerShell 语法检查通过。
- [ ] `git ls-files` 与 Git 对象中不存在 vault、真实回执、安装包、备份、key map、数据库、dump 或 vendor 项目。
- [ ] README、AGENTS、Skill 与两个平台教程使用相同命令、确认标志、支持矩阵和停点。
- [ ] 冷启动任务明确要求 Codex 与微信同机同用户；Web/云端/Linux/另一台机器返回 `SUPPORTED_PLATFORM_REQUIRED`，不要求上传数据库。
- [ ] 无备注/昵称联系人不会回退输出内部 username/wxid；同名会话可用匿名 `session_tag` 选择。

## B. Windows 11 x64 真机（exact candidate commit）

- [ ] 在干净目录全新 clone；使用 64 位 Python 执行 `setup.ps1 -InstallSkill`。
- [ ] `manage.cmd --version` 与候选版本一致。
- [ ] preflight 只显示相对数据库名；动态 manifest 与本机实际分片一致。
- [ ] 只读 `capture-plan` 与文档一致；用户另行批准后，当前版 capture 返回 `VERIFIED_CURRENT_VERSION_READ_ONLY_RECOVERY`。
- [ ] 捕获只访问逐 PID 验证过的腾讯签名进程；结果不含账号主口令，DPAPI 读回与 manifest key 完全一致。
- [ ] 用户手工退出全部 `Weixin.exe`；full refresh 返回 `VERIFIED_REFRESH`，status 返回 `VERIFIED_FRESH_VAULT`，全部 `quick_check=ok`。
- [ ] 让账号新收到一条专用测试消息；用户再次退出微信；incremental refresh 后，有界 history/digest 在批准范围内包含该消息。
- [ ] 人为放置测试用非空 WAL/journal fixture 时，full、incremental、dry-run、query 均硬停且不输出正文。
- [ ] 新 Codex 任务能发现已安装 Skill；先披露模型数据边界并等待批准，再完成有界摘要。
- [ ] `legacy-plan` 只返回禁用状态；没有公开切换命令。

## C. Apple Silicon Mac 真机（exact candidate commit）

- [ ] 在干净目录全新 clone，项目 Keychain 条目为空；执行 `setup.sh --install-skill`。
- [ ] `manage.sh --version`、Python、macOS、架构、微信和 Frida 版本记录在脱敏回执中。
- [ ] preflight 动态发现本机实际分片；多账号只用用户选择的 `account_tag`，不把路径写进 Codex 日志。
- [ ] 手动导入路线：只验证 manifest key，原生 Keychain 写入后读回一致；读回失败时 `--delete-source` 不删除源文件。
- [ ] 无现成 key 时：用户分别批准副本创建/签名和 spawn/Frida；原版微信未修改，其他微信进程全部退出。
- [ ] spawn-gated 捕获先 ready 再 resume；用户自己登录；最终返回 `VERIFIED_MACOS_SIGNED_COPY_CAPTURE`，所有 manifest key 通过 HMAC/Keychain 读回。
- [ ] 用户手工退出签名副本；full refresh/status 全绿，vault 目录 `0700`、明文文件当前用户专用。
- [ ] 新收一条专用测试消息后再次退出微信；incremental refresh 与批准后的有界摘要包含该消息。
- [ ] 非空 WAL/journal 时 refresh/query 硬停；查询期间源变化时不输出正文。
- [ ] 新 Codex 任务通过已安装 Skill 再跑一次，确认 runner 使用仓库 `.venv`，并忽略测试消息中的 prompt-injection 文本。

## D. 冻结最终 `v0.1.0` 候选提交

- [ ] 把 `TOOL_VERSION`、README 候选文字和 CI wrapper 预期值从 `0.1.0-rc1` 一次性对齐为 `0.1.0`；此时仍写明“未打 tag 前不是稳定发布”。
- [ ] 提交全部计划发布文件，确认工作树 clean，记录完整 commit SHA；此后不再改代码、测试或文档。
- [ ] 四个 CI job 对这个 SHA 全绿，秘密扫描使用完整历史。
- [ ] Windows 与 Mac 都从这个 SHA 的全新 clone 执行 B/C；回执必须绑定同一个 SHA，历史版本回执不能替代。
- [ ] README 支持矩阵只写实际验证的 OS、架构、Python、微信和 Frida 组合；其他组合标未验证。
- [ ] 已知限制明确包含：必须手工退出微信、无实时 WAL 支持、非文本媒体不可用、Codex 可能处理选中正文、Windows legacy 禁用。
- [ ] GitHub main 设置规则，至少要求四个 CI job 通过后合并。

## E. 只给同一个已验收 SHA 打标

- [ ] 确认当前 `HEAD` 等于两机回执中的 SHA，工作树 clean，且 `manage --version` 为 `0.1.0`。
- [ ] 在这个 SHA 上创建 annotated `v0.1.0` tag 和 GitHub Release，发布 source only；不得先打 tag 再补版本，也不得上传 vault、二进制或个人回执。
- [ ] 发布后从 GitHub Release 再做一次新目录下载/安装冒烟。

## 停止发布的条件

任何一项出现即保持 Release Candidate：错误成功状态、消息遗漏、事务日志假新鲜、refresh 失败后出现部分替换、路径/秘密泄漏、内部 username/wxid 输出、Skill 绕过 `.venv`、未批准正文进入模型、prompt injection 被执行、原版微信被修改、或两台真机不是同一 commit。
