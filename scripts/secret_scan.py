from __future__ import annotations

from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {".git", ".venv", "vendor", "00_sources", "01_current", "02_versions", "04_audit", "05_tmp", "__pycache__"}
TEXT_SUFFIXES = {".py", ".md", ".txt", ".yml", ".yaml", ".json", ".ps1", ".sh", ".cmd", ".toml"}
PATTERNS = {
    "private Windows home": re.compile(r"C:\\Users\\(?!<|USERNAME)[^\\\s]+", re.IGNORECASE),
    "private macOS home": re.compile(r"/Users/(?!<|USERNAME)[^/\s]+"),
    "WeChat stable id": re.compile(r"\bwxid_[A-Za-z0-9_-]{6,}\b"),
    "literal 32-byte hex secret": re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])"),
    "access token": re.compile(r"\b(?:gh[opusr]_|sk-)[A-Za-z0-9_-]{20,}\b"),
    "personal QQ email": re.compile(r"\b\d{5,12}@qq\.com\b", re.IGNORECASE),
}


def should_scan(path: Path) -> bool:
    return (
        path.suffix.lower() in TEXT_SUFFIXES
        and path.as_posix() != "scripts/secret_scan.py"
        and not any(part in SKIP_PARTS for part in path.parts)
    )


def scan_text(label: str, value: str, findings: list[str]) -> None:
    for pattern_label, pattern in PATTERNS.items():
        for match in pattern.finditer(value):
            findings.append(f"{label}: {pattern_label}")
            break


def scan_history(findings: list[str]) -> int:
    if not (ROOT / ".git").exists():
        return 0
    completed = subprocess.run(
        ["git", "rev-list", "--objects", "--all"],
        cwd=ROOT, capture_output=True, text=True, timeout=30, check=True,
    )
    metadata = subprocess.run(
        ["git", "log", "--format=%H %an <%ae>"],
        cwd=ROOT, capture_output=True, text=True, timeout=30, check=True,
    )
    scan_text("history:commit-metadata", metadata.stdout, findings)
    blobs: dict[str, Path] = {}
    for line in completed.stdout.splitlines():
        parts = line.split(" ", 1)
        if len(parts) != 2:
            continue
        path = Path(parts[1])
        if should_scan(path):
            blobs.setdefault(parts[0], path)
    scanned = 0
    for object_id, path in blobs.items():
        size = subprocess.run(
            ["git", "cat-file", "-s", object_id], cwd=ROOT,
            capture_output=True, text=True, timeout=10, check=True,
        )
        if int(size.stdout.strip()) > 2 * 1024 * 1024:
            continue
        content = subprocess.run(
            ["git", "cat-file", "-p", object_id], cwd=ROOT,
            capture_output=True, timeout=10, check=True,
        ).stdout.decode("utf-8", errors="replace")
        scan_text(f"history:{path.as_posix()}@{object_id[:12]}", content, findings)
        scanned += 1
    return scanned


def main() -> int:
    findings: list[str] = []
    current_files = 0
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if not should_scan(relative):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        scan_text(relative.as_posix(), text, findings)
        current_files += 1
    history_blobs = scan_history(findings)
    if findings:
        print("Potential private material detected:", file=sys.stderr)
        print("\n".join(findings), file=sys.stderr)
        return 1
    print(f"Secret scan passed ({current_files} current files, {history_blobs} reachable history blobs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
