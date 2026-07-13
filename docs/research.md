# 开源方案调研记录

调研日期：2026-07。此表用于解释安全取舍；项目状态和许可证可能变化，使用前请到上游复核。

| 项目 | 能力 | 未作为默认方案的原因 |
|---|---|---|
| [LifeArchiveProject/WeChatDataAnalysis](https://github.com/LifeArchiveProject/WeChatDataAnalysis) | 微信 4.x 分析、V4 恢复、可视化 UI | 部分图片 key 流程存在远程回退；调研时未找到清晰 LICENSE。本项目不采用上传配置的回退 |
| [H3CoF6/py_wx_key](https://github.com/H3CoF6/py_wx_key) | 新版 key 捕获 | 使用进程内 Hook/shellcode，风险高于 Windows 只读扫描 |
| [ylytdeng/wechat-decrypt](https://github.com/ylytdeng/wechat-decrypt) | 解析、导出、MCP 和大量格式研究 | 旧 `key+salt` 扫描在 4.1.10/4.1.11 已有失败报告；调研时仓库许可证不清晰，不复制源码 |
| CipherTalk | UI/CLI/MCP | key 路径依赖不可审计的原生 DLL/Hook，且许可证限制商业用途 |
| DbkeyHook | key Hook | 新二进制并非完全开源；旧路线会替换腾讯 DLL |
| wx-dump-4 | 多版本声称 | 依赖已移除的二进制和不稳定的熵扫描 |
| WeFlow / PyWxDump / chatlog | 历史上功能完整 | 相关解密代码已因维护或合规原因移除，不适合作为新教程基础 |

与新版兼容性直接相关的公开讨论包括 `ylytdeng/wechat-decrypt` 的 issue #96、#152、#155。结论不是“新版一定无法读取”，而是旧式明文 key 扫描不再通用；本项目验证的是“当前版本恢复账号口令候选，再以每个数据库 HMAC 为权威”的不同路径。

可视化管理工具适合浏览，但 UI 本身不会消除 key 获取、第三方二进制审计、数据上传和许可证风险。默认教程因此保持一个小型本地 CLI，后续可在私密 vault 之上增加只读 Web UI，而不改变捕获安全边界。
