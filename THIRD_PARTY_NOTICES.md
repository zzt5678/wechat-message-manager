# Third-party notices

This repository is a standalone implementation. It does not vendor, import, clone at runtime, or redistribute source code or native binaries from the research projects listed below.

## Workflow and format references

### mcncarl/yichen-skills

- Project: <https://github.com/mcncarl/yichen-skills>
- Referenced area: the `yichen-wechat-local-vault` macOS workflow and its documented use of an ad-hoc-signed WeChat copy.
- License boundary: the upstream repository restricts public redistribution and packaged derivatives. No upstream source file is included here. The capture, validation, decryption, storage, and query code in this repository was written independently.

### zhuyansen/wx-favorites-report

- Project: <https://github.com/zhuyansen/wx-favorites-report>
- License boundary: no top-level license was detected through the GitHub API when reviewed in July 2026. Only high-level technical ideas are referenced; no source code is copied or redistributed.
- Referenced ideas: observing CommonCrypto PBKDF2 calls on macOS and validating SQLCipher-compatible database keys.
- No upstream source file or binary is included here.

### ylytdeng/wechat-decrypt

- Project: <https://github.com/ylytdeng/wechat-decrypt>
- Referenced material: public discussions of WeChat 4.x database formats and compatibility changes.
- The license was unclear when reviewed, so no source code is copied or redistributed here.

## Python dependencies

`pycryptodome`, `keyring`, and the pinned macOS `frida` Python package are installed from PyPI at setup time and remain subject to their respective upstream licenses. They are ordinary package dependencies, not nested project checkouts.

## Optional emergency tools and proprietary software

The repository retains research code that previously used an independently installed 7-Zip executable to inspect a pinned Tencent installer. Public legacy execution is disabled in `0.1.0-rc1`; setup and the supported current-version workflow do not download, install, invoke, vendor, or redistribute 7-Zip. 7-Zip remains subject to its upstream licenses at <https://www.7-zip.org/license.txt>.

WeChat and its installer are proprietary Tencent software. The repository contains only a fixed official download URL and public integrity metadata; it does not contain or redistribute the installer, extracted program files, or program backups. WeChat and Tencent trademarks belong to their respective owners, and this project is not affiliated with or endorsed by Tencent.
