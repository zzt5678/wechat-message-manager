# Windows 4.1.9 备用流程

## 适用条件

这不是默认安装路径。只有当前版本 `capture` 返回 `No compatible mask pattern...` 或 `No candidate passed every core database HMAC gate`，且重试、现有 DPAPI key 和手动导入都不可用时，才考虑本流程。

临时切换旧版会改变微信程序文件、要求重新登录，并可能触发安全提示、自动升级或数据迁移。项目不静默安装、不卸载微信、不点击界面；用户必须逐步批准并手动退出、启动和登录微信。发生异常时不要跳过门禁或自行复制未知文件。

## 固定制品和边界

备用制品为腾讯官方 HTTPS 地址上的 Windows 微信 4.1.9 安装包。项目同时固定检查：

- 运行版本：`4.1.9.57`；
- 安装器文件版本：`4.1.9.1000`；
- 大小：`234965064` bytes；
- SHA-256：`8f43225b7388742a9797d31960bf19d6b0902ea58bf1a85b6d8b95d0b71877ed`；
- Authenticode 状态必须为 `Valid`，签名主体必须包含 `Tencent`。

URL、哈希、大小或签名任一变化都会停止，不能改用第三方“绿色版”或仅凭文件名继续。本仓库不再分发腾讯安装包；下载、提取内容、启动器备份和数据库快照只保存在 `%LOCALAPPDATA%` 下的应用私密目录。

私密提取需要约 2 GiB 可用空间和 7-Zip。7-Zip 只在应急路径使用，可从 [7-zip.org](https://www.7-zip.org/) 或系统可信软件源安装；项目不会替用户下载或安装它。

## 第一步：查看计划

以下命令不下载、不读取微信内存，也不修改应用：

```powershell
.\manage.cmd legacy-plan
```

确认默认当前版捕获确实失败后，再分别批准后续每个状态变化。一次总括同意不能替代切换和恢复时的单独确认。

## 第二步：下载并校验旧版

```powershell
.\manage.cmd legacy-download --i-understand-download-legacy-installer
```

成功状态必须为 `VERIFIED_PINNED_TENCENT_LEGACY_INSTALLER`。命令只从固定的 `dldir1v6.qq.com` 路径下载；重定向到其他主机、长度异常、SHA-256 不符或腾讯签名无效都会删除临时文件并停止。

## 第三步：准备私密备份

保持当前官方微信已登录并正在运行，使工具能够确认实际加载的腾讯签名 DLL、当前版本目录和启动器：

```powershell
.\manage.cmd legacy-prepare --i-understand-prepare-private-backup
```

预期状态：`PREPARED_SIGNED_LEGACY_FALLBACK`。这一步会私密提取已验证的安装包并备份当前启动器，但不会修改微信安装目录。若当前启动器、DLL 和实际加载版本不一致，立即停止。

## 第四步：临时切换

1. 用户在微信中确认同步完成，然后手动退出微信。
2. 确认任务管理器中没有 `Weixin.exe`。
3. 打开管理员 PowerShell，进入项目目录后运行：

```powershell
.\manage.cmd legacy-switch --i-understand-temporary-version-switch
```

切换前会稳定复制七个核心数据库及存在的 WAL/SHM，并逐文件校验源文件前后与副本 SHA-256 一致。随后只增加签名有效的 `4.1.9.57` 版本目录并替换根启动器；原当前版本目录保持不动。预期状态：`VERIFIED_TEMPORARY_LEGACY_SWITCH`。

如果命令失败，不要反复执行。工具会尽力恢复已备份启动器；保留私密状态和脱敏错误，先确认当前微信能否正常启动。

## 第五步：旧版只读捕获

用户手动启动微信并完成登录。明确批准一次只读内存扫描后运行：

```powershell
.\manage.cmd legacy-capture --i-understand-read-process-memory
```

旧版捕获器只接受腾讯签名的 `4.1.9.57` 运行时。它读取旧版账号口令描述符，不使用新版 DLL 掩码；候选仍须为七个核心数据库分别派生 key 并全部通过 page-1 HMAC，之后才写入当前用户 DPAPI。预期状态：`VERIFIED_LEGACY_419_READ_ONLY_RECOVERY`。

## 第六步：立即恢复当前版

1. 用户手动退出旧版微信。
2. 在管理员 PowerShell 运行：

```powershell
.\manage.cmd legacy-restore --i-understand-restore-current-version
```

预期状态：`RESTORED_CURRENT_LAUNCHER_PENDING_RUNTIME_VERIFICATION`。工具只从经过版本、签名和 SHA-256 复核的私密备份恢复启动器；旧版目录暂时保留，直到当前版真机启动验证完成。

用户手动启动微信、登录当前版，然后运行：

```powershell
.\manage.cmd legacy-verify-restored
.\manage.cmd refresh --mode full
.\manage.cmd query status --format text
```

成功状态必须依次包含 `VERIFIED_CURRENT_VERSION_RESTORED`、`VERIFIED_REFRESH` 和七个核心数据库 `quick_check`。如果 current key 与恢复后的数据库不兼容，刷新会停止，私密的加密数据库快照仍保留用于人工恢复。

## 第七步：可选清理安装目录

确认当前版已经登录、全量刷新和查询成功后，手动退出微信，并在管理员 PowerShell 运行：

```powershell
.\manage.cmd legacy-cleanup --i-understand-remove-installed-legacy-copy
```

它只删除工具先前增加且仍与已验证制品哈希一致的 `4.1.9.57` 程序目录，不删除当前版本目录、私密安装包或数据库快照。私密应急资料可在确认长期稳定后由用户自行删除。

## 已验证范围

项目验证记录显示：腾讯签名的 4.1.9.57 曾完成临时切换和旧版捕获，随后恢复到官方 4.1.11.54；本仓库当前的状态机和门禁已经做自动化测试。它仍依赖未公开稳定的微信内部结构，不能承诺未来旧版一定能登录或其账号口令继续兼容新版数据库。
