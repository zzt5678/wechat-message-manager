# macOS 教程

macOS 的数据库、解密、freshness 和查询流程与 Windows 共用；不同点只有 key 的来源和落盘方式。key 最终存入当前用户的 macOS Keychain。

本教程是单仓库流程：不需要克隆最初参考的教程项目，也不需要外部 key DLL。`capture_keys_macos.py`、`import_keys.py`、`refresh_vault.py`、`secret_store.py` 和 `vault_query.py` 已包含所需实现。setup 只安装 `requirements.txt` 中的 PyPI 包。

## 推荐：导入本人已有 key

如果原教程或本人已有工具产生了数据库相对路径到 64 位十六进制 key 的 JSON：

```json
{
  "keys": {
    "contact/contact.db": "<64 hex characters>",
    "session/session.db": "<64 hex characters>"
  }
}
```

不要把真实文件提交到 Git。导入命令会逐库 HMAC 验证，不会打印 key：

```bash
.venv/bin/python wechat_manager.py preflight --configure
.venv/bin/python wechat_manager.py import-keys --file ~/private/wechat-keys.json --delete-source
```

只有七个核心库全部通过才会写入 Keychain。

## 可选：对单独签名副本进行 Hook

这是侵入性较高的 opt-in 路径，不是默认安全路径。本仓库不会修改原版 `/Applications/WeChat.app`，不会自动操作微信 UI，也不会自动发消息；但 Frida 会在一个单独副本进程里 Hook `CCKeyDerivationPBKDF`。请先备份并理解公司设备政策、微信条款和本地法律。

1. 退出所有微信进程，由用户手工复制官方应用到自己的 Applications 目录。
2. 只对副本移除 Hardened Runtime/进行 ad-hoc 签名；原应用保持不变。
3. 用户手动启动副本并登录，记录这个副本进程的 PID。
4. 查看非执行计划：

```bash
.venv/bin/python wechat_manager.py capture-macos-plan
```

5. 明确同意 Hook 后运行：

```bash
.venv/bin/python wechat_manager.py capture-macos \
  --i-understand-frida-hook \
  --pid <副本PID> \
  --signed-copy "$HOME/Applications/WeChat-Capture.app" \
  --duration 240
```

脚本只 attach 到声明的副本 PID，不启动应用、不点击界面。期间由用户自行打开需要读取的会话/功能以触发数据库派生。候选只在内存中与数据库 HMAC 匹配；控制台不输出候选或 key。

### 准备副本的示例

以下命令会创建并修改副本，执行前必须由用户明确确认目标路径：

```bash
mkdir -p "$HOME/Applications"
ditto /Applications/WeChat.app "$HOME/Applications/WeChat-Capture.app"
codesign --force --deep --sign - "$HOME/Applications/WeChat-Capture.app"
codesign --verify --deep --strict "$HOME/Applications/WeChat-Capture.app"
```

真实 Mac 上的签名行为会随微信和 macOS 版本变化。本仓库当前没有 Mac 真机，所以上述捕获实现必须视为“待真机复验”，不能把模拟测试当作成功捕获。

## 解密与查询

key 就绪后：

```bash
.venv/bin/python wechat_manager.py refresh --mode full
.venv/bin/python wechat_manager.py query status --format text
.venv/bin/python wechat_manager.py refresh --mode incremental
```

私密目录默认为 `~/Library/Application Support/WechatMessageManager`。不要把它放进 iCloud、网盘或 Git。
