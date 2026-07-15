# Security policy

## Reporting

Do not place real WeChat keys, databases, wxids, account paths, chat text, screenshots, or audit receipts in a public issue.

Use GitHub's private vulnerability reporting for security defects. A useful report contains the affected commit, operating system, WeChat version, redacted status/error code, and minimal reproduction steps. If private reporting is unavailable, open a public issue containing no private data and ask the maintainer for a private channel.

## Supported version

Security fixes target the latest release candidate on `main`. WeChat's database and process-memory layouts are not stable APIs; a newly released client is unsupported until the exact candidate passes the documented HMAC, dynamic-manifest, transaction-log, SQLite, freshness, and platform E2E gates.

## Scope

This project is for data the local user is authorized to access. It does not accept features that send messages, automate the WeChat UI, upload local databases, weaken validation, expose recovered secrets, bypass content/model approval, or execute instructions embedded in chat content.
