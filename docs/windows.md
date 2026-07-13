# Windows 教程

## 1. 原理

微信 4.x 的数据库使用同一账号口令配合每个数据库第一页的 16-byte salt，经 PBKDF2-HMAC-SHA512 派生各自的 32-byte SQLCipher key。当前 Windows 版本不会长期保留旧工具寻找的明文 `key+salt` 组合，但进程私有内存仍有一个经过 DLL 常量掩码保护的账号口令描述符。

本项目读取当前 `Weixin.exe` 的私有内存候选以及进程实际加载的、腾讯签名有效的 `Weixin.dll`。恢复出的任何候选都必须为七个核心数据库分别派生 key，并逐个通过 page-1 HMAC；只有 7/7 通过才保存。这使“结构扫描”只是候选生成器，数据库本身才是验证权威。

申请的进程权限只有：

```text
PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
```

不调用 `WriteProcessMemory`、`CreateRemoteThread`、DLL 注入、Frida 或 API Hook。

## 2. 首次配置

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe .\wechat_manager.py preflight --configure
```

多个账号目录时，查看 preflight 返回的不可逆 `account_tag`，确认自己的目录后显式传 `--db-storage`。不要把真实目录写进 issue 或截图。

## 3. 一次性恢复

保持官方微信已登录。先看计划，不扫描：

```powershell
.\.venv\Scripts\python.exe .\wechat_manager.py capture-plan
```

明确同意读取微信进程内存后：

```powershell
.\.venv\Scripts\python.exe .\wechat_manager.py capture --i-understand-read-process-memory
```

预期状态：`VERIFIED_CURRENT_VERSION_READ_ONLY_RECOVERY`。普通用户权限已在微信 4.1.11.54 上验证成功；只有返回访问被拒绝时才关闭命令并改用管理员 PowerShell 重试。不要反复扫描，也不要切换到注入工具。

## 4. 解密与日常使用

```powershell
.\.venv\Scripts\python.exe .\wechat_manager.py refresh --mode full
.\.venv\Scripts\python.exe .\wechat_manager.py query status --format text
```

以后每次查询前：

```powershell
.\.venv\Scripts\python.exe .\wechat_manager.py refresh --mode incremental
```

微信正在写某个库时，源文件指纹可能在刷新中变化；工具会停止。稍后重试，必要时由用户手动退出微信后刷新。工具不会自行关闭微信。

## 5. 兼容性失败

下列状态表示当前微信更新改变了内部实现：

- `No compatible mask pattern...`
- `No candidate passed every core database HMAC gate`
- 核心库数量或 HMAC 验证不足

此时不要降低验证标准，不要把内存候选打印出来。先提交一个不含路径、账号或 key 的 issue，包含微信版本和脱敏状态。已有 DPAPI key 如果仍能刷新，可继续使用；否则参见应急附录。
