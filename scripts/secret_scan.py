from __future__ import annotations

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {".git", ".venv", "vendor", "00_sources", "01_current", "02_versions", "04_audit", "05_tmp", "__pycache__"}
TEXT_SUFFIXES = {".py", ".md", ".txt", ".yml", ".yaml", ".json", ".ps1", ".sh", ".cmd", ".toml"}
PATTERNS = {
    "private Windows home": re.compile(r"C:\\Users\\(?!<|USERNAME)[^\\\s]+", re.IGNORECASE),
    "private macOS home": re.compile(r"/Users/(?!<|USERNAME)[^/\s]+"),
    "WeChat stable id": re.compile(r"\bwxid_[A-Za-z0-9_-]{6,}\b"),
    "literal 32-byte hex secret": re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])"),
}


def main() -> int:
    findings: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        relative = path.relative_to(ROOT)
        if path == Path(__file__).resolve() or any(part in SKIP_PARTS for part in relative.parts):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for label, pattern in PATTERNS.items():
            if pattern.search(text):
                findings.append(f"{relative.as_posix()}: {label}")
    if findings:
        print("Potential private material detected:", file=sys.stderr)
        print("\n".join(findings), file=sys.stderr)
        return 1
    print("Secret scan passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
