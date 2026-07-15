# 架构与兼容性

## 模块

- `preflight.py`：发现账号数据库，输出相对文件名、伪名化 tag、动态分片和事务日志状态；配置另一个账号时拒绝复用 vault。
- `manager_config.py`：私密目录、动态 manifest、版本、进程停止门和统一错误脱敏。
- `capture_keys_windows.py`：Windows 11 x64 当前版只读候选恢复、逐 PID 签名检查和 manifest HMAC 门。
- `capture_keys_macos.py`：显式 opt-in 的签名副本 spawn/attach Hook；先 ready 再 resume。
- `import_keys.py`：只导入 manifest 中的 key，并验证保护存储读回。
- `secret_store.py`：Windows DPAPI / 原生 macOS Keychain。
- `refresh_vault.py`：事务日志硬停、主库/sidecar 联合指纹、逐页 HMAC、AES-256-CBC 解密、整批私密 staging/失败回滚和 SQLite 校验。
- `vault_query.py`：查询前后 freshness、内容授权、控制字符清理、数量/字符预算和只读 vault 查询。
- `wechat_manager.py`：统一入口与版本输出。
- `legacy_windows.py`：保留研究实现，但公开敏感执行在入口处禁用。

## 动态数据库 manifest

每个账号至少要求：

- `contact/contact.db`；
- `session/session.db`；
- 一个或多个实际存在的 `message/message_N.db`；
- `message/message_resource.db`。

编号分片数量和编号不假定固定。preflight 把规范化清单写入私密配置；捕获、导入、刷新、查询都使用同一清单。新增/删除分片会返回 `CORE_DATABASE_MANIFEST_CHANGED`，防止少分片账号无法使用或高编号分片被静默遗漏。旧 schema-1 Windows vault 暂按历史 7 库门运行，重新 configure 后迁移到动态 manifest。

## 一致性与事务日志

自定义解密器当前只处理加密主 `.db`，不解密/合并 SQLCipher WAL frame。因此任何非空 `.db-wal` 或 `.db-journal` 都是硬停。用户必须手工退出所有微信进程；refresh 会在解密前后联合检查主库和 sidecar 指纹，query 在结果构造前后再次检查。`.db-shm` 本身不承载事务，但工具也不会删除它。

refresh 先把本轮所有变更库解密到同一私密文件系统中的 staging，全部 HMAC、SQLite 与最终源 freshness 通过后才提交；普通提交异常会反向恢复旧明文，STATE 最后原子写入。进程级突然终止即使发生在多文件提交中，旧 STATE 也会让后续查询硬停，必须重新 refresh，不能把部分批次称为新鲜。

refresh 与 query 还共享私密跨进程独占锁；并发请求不会交错读取/替换明文。锁获取失败返回 `MANAGER_OPERATION_IN_PROGRESS`，由用户等待当前操作结束后重试。

这使当前公开能力是“微信完全退出后的验证快照”，不是微信运行中的实时流。未来只有实现一致性快照、加密 WAL 解密/合并和对应真机测试后，才能改变该声明。

## 查询覆盖与数据预算

当前查询联系人、会话、明确的文本消息和基本元数据。非文本类型只输出安全占位，不解密媒体或转写语音。单条正文最多 4,000 字符；sessions 最多 200 条（名称 200/预览 160）；history 最多 200 条；digest 默认 500、最多 1,000 条；可选不可信文本预算默认 30,000、硬上限 120,000 字符，统计会话名、发送者与正文，不含 JSON 结构和可信时间字段。控制/ANSI/Bidi 字符会移除，可识别的 wxid/公众号/群内部 ID 会替换为占位。内容输出还需要显式确认，并标为不可信数据；同名会话用匿名 `session_tag` 选择，内部 username/wxid 不作为显示名回退。

## 微信升级

数据库密码学参数、表结构和内存布局都不是稳定 API。候选生成逻辑失效时，正确结果是停止，而不是保存错误 key。已有账号 key 可能跨版本有效，但不能依赖；每次 refresh 仍重新验证 HMAC、source consistency、SQLite 与 freshness。

Windows 4.1.9 路线与当前版恢复在研究上相互独立，但因程序切换回滚与 payload 完整性尚未达到公开安全门，当前版本不执行该路线。

## 第三方研究

本实现受公开研究和本机行为验证启发，但不复制无许可证项目源码，不包含 Git submodule、vendor checkout、运行时 `git clone` 或另一个仓库的包装器。来源与许可证边界见 [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)。
