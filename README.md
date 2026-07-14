# WeChat Message Manager

一个面向本人本机微信数据的只读消息管理工具：验证并解密微信 4.x 本地数据库，在私密 vault 中查询会话、限定时间范围的历史消息，并交给 Codex 做每日摘要。项目不会发送消息，不会点击微信界面，也不使用截图、OCR、剪贴板或无障碍接口。

## 当前验证状态

| 平台 | 密钥路径 | 验证状态 |
|---|---|---|
| Windows 11 / 微信 4.1.11.54 | 当前版本 `ReadProcessMemory` + 已签名 `Weixin.dll` 掩码恢复；无注入、无 Hook、无需降级 | 2026-07-13 真机验证：7/7 核心库 HMAC 通过；2026-07-14 再次完成增量解密与 7/7 `quick_check` |
| macOS / 微信 4.x | 导入已有 key，或明确同意后对单独的 ad-hoc 签名副本使用 Frida Hook | 跨平台核心与 Hook 消息处理已做静态/模拟验证；本仓库的 macOS 捕获脚本尚未在 Mac 真机验收 |

Windows 直接恢复是默认方案。临时降级到 4.1.9.x 只保留为[应急思路](docs/emergency-downgrade.md)，不是正常安装步骤。微信升级可能改变内部结构，因此“当前已验证”不等于永久兼容；每次恢复仍须通过数据库 HMAC，失败时不会猜测或保存候选。

## 安全边界

- 仅处理当前用户有权访问的本机账号数据。
- Windows 默认路径只申请 `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`，不写内存、不注入、不 Hook、不重启微信。
- macOS Hook 是独立、显式同意的高风险选项，只允许连接到用户准备的微信副本，不修改 `/Applications/WeChat.app` 原件。
- key 在 Windows 由 DPAPI 保护，在 macOS 存入 Keychain；明文数据库和审计回执只进入应用私密目录。
- 任何核心 key/HMAC、源文件一致性、SQLite `quick_check` 或 freshness 校验失败都会停止。
- 项目不包含微信安装包、个人 key、wxid、聊天数据，也不包含不允许公开再分发的第三方源码。

完整威胁模型见 [docs/security.md](docs/security.md)。

## 安装

需要 Python 3.9+、桌面微信 4.x，以及本人已经登录的账号。

### Windows

```powershell
git clone https://github.com/zzt5678/wechat-message-manager.git
cd wechat-message-manager
.\setup.ps1 -InstallSkill
.\manage.cmd preflight --configure
```

不使用 Codex 时省略 `-InstallSkill`。

### macOS

```bash
git clone https://github.com/zzt5678/wechat-message-manager.git
cd wechat-message-manager
./setup.sh --install-skill
./manage.sh preflight --configure
```

不使用 Codex 时省略 `--install-skill`。

发现多个 `db_storage` 时必须显式传入：`preflight --configure --db-storage <路径>`。程序输出只显示不可逆的账号标签，不显示真实账号目录。

## Windows：当前版本直接恢复

先查看不会执行扫描的计划：

```powershell
.\manage.cmd capture-plan
```

理解其影响并明确同意后，保持微信已登录并执行一次：

```powershell
.\manage.cmd capture --i-understand-read-process-memory
```

成功状态必须是 `VERIFIED_CURRENT_VERSION_READ_ONLY_RECOVERY`。候选只在七个核心数据库全部通过 page-1 HMAC 后写入 DPAPI；终端和回执都不输出 key、salt、wxid 或私密路径。通常不需要管理员权限，若 Windows 拒绝读取目标进程才考虑提升权限。细节见 [docs/windows.md](docs/windows.md)。

## macOS：已有 key 或签名副本

macOS 捕获、HMAC 验证、解密、Keychain 存储和查询代码都已包含在本仓库；不需要再克隆教程来源或另一个微信项目。安装过程只会从 PyPI 安装 `pycryptodome`、`zstandard`、`keyring` 和 `frida` 等普通 Python 依赖。

最安全的方式是导入本人已有的数据库 key JSON：

```bash
./manage.sh import-keys --file ~/private/wechat-keys.json --delete-source
```

导入前逐库 HMAC 校验，成功后存入 Keychain。没有 key 时，本仓库提供显式 opt-in 的签名副本 Hook；它不属于只读默认路径，且目前需要 Mac 真机用户复验。先运行：

```bash
./manage.sh capture-macos-plan
```

继续前请完整阅读 [docs/macos.md](docs/macos.md)。

## 刷新、查询和摘要

首次全量解密：

```powershell
.\manage.cmd refresh --mode full
.\manage.cmd query status --format text
```

日常使用必须先增量刷新：

```powershell
.\manage.cmd refresh --mode incremental
.\manage.cmd query sessions --limit 30 --unread-only --format text
.\manage.cmd query history "群显示名" --since 2026-07-14T00:00:00 --limit 200 --format text
.\manage.cmd query digest-source --date today --format json
```

macOS 把 `.\manage.cmd` 换成 `./manage.sh`。

`digest-source` 只用于向本机 Codex 提供有界数据，不会调用云端接口。Codex Skill 的安装和用法见 [skill/manage-wechat-messages/SKILL.md](skill/manage-wechat-messages/SKILL.md)。

## Codex Skill

`setup.ps1 -InstallSkill` 或 `setup.sh --install-skill` 会把 Skill 安装到 `$CODEX_HOME/skills/` 并安全记录当前仓库位置，不需要手工设置环境变量。也可以单独执行：

```text
python scripts/install_skill.py
```

安装后开启一个新的 Codex 会话，让 Codex 重新发现 Skill。之后可说：

> 使用 `$manage-wechat-messages` 刷新今天的微信消息，按重要事项、待办、截止时间、风险和有价值链接汇总。

Skill 不会绕过捕获批准门，也不会自动操作微信界面。

## 单仓库与第三方来源

本项目没有 Git submodule、vendor 仓库、运行时 `git clone` 或需要另外下载的 key DLL。macOS 流程参考了公开项目的研究思路，但捕获、验证、解密和查询实现均在本仓库内。来源、许可证边界和“未复制上游源码”的说明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## 文档

- [Windows 教程](docs/windows.md)
- [macOS 教程](docs/macos.md)
- [安全模型](docs/security.md)
- [架构和兼容性](docs/architecture.md)
- [开源方案调研](docs/research.md)
- [降级应急附录](docs/emergency-downgrade.md)
- [第三方来源与许可证边界](THIRD_PARTY_NOTICES.md)
- [安全报告](SECURITY.md)
- [贡献指南](CONTRIBUTING.md)

本项目采用 MIT License。微信及 WeChat 是腾讯的商标；本项目与腾讯无隶属或背书关系。
