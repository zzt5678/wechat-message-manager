# 架构与兼容性

## 模块

- `preflight.py`：发现账号数据库，只输出不可逆账号标签。
- `capture_keys_windows.py`：当前 Windows 版本只读恢复和 HMAC 门。
- `capture_keys_macos.py`：显式 opt-in 的签名副本 Hook。
- `import_keys.py`：跨平台验证已有 key map。
- `secret_store.py`：Windows DPAPI / macOS Keychain。
- `refresh_vault.py`：逐页 HMAC、AES-256-CBC 解密、原子替换、SQLite 校验。
- `vault_query.py`：freshness gate 后的会话、历史和日期摘要数据查询。
- `wechat_manager.py`：统一入口。

## 微信升级

数据库密码学参数和内存布局都不是公开稳定 API。Windows 捕获器将 DLL 内存结构当作不可信的候选来源；真正的兼容性判断来自数据库 HMAC。因此升级后的最坏结果应该是“无法恢复并停止”，而不是保存错误 key。

已有账号 key 可能跨客户端升级继续有效，但不能依赖这一点。每次 refresh 都重新验证页面 HMAC和文件一致性。

## 数据覆盖

当前核心范围是联系人、会话、四个消息分片和消息资源索引。文本消息与基本元数据可查询；图片、语音、视频、文件和贴纸默认只标记为非文本，不做媒体解密或语音转写。

## 第三方研究

项目实现受公开研究和本机行为验证启发，但仓库不复制无许可证项目代码，也不再分发限制公开打包的上游 Skill。参考项目和版本只用于研究记录：

- `ylytdeng/wechat-decrypt`：微信 4.x 数据库结构与兼容性讨论。
- `LifeArchiveProject/WeChatDataAnalysis`：V4 可视化和只读恢复思路；本项目不使用其远程图片配置回退。
- `mcncarl/yichen-skills`：原 macOS 工作流教程；因许可证限制，本项目的查询与管理代码为独立实现。

请分别查看这些项目的当前许可证和安全边界，不要把它们的二进制或源码直接打包进本仓库。

这些项目不是运行时依赖。本仓库没有 Git submodule、vendor checkout 或调用另一个仓库的包装器；macOS 捕获、密钥验证、解密、Keychain 存储和查询均由本仓库文件完成。详细归属见根目录 `THIRD_PARTY_NOTICES.md`。
