from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import sys

from manager_config import redact_private_text


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "skill" / "manage-wechat-messages"
SKILL_NAME = "manage-wechat-messages"


def default_codex_home() -> Path:
    return Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")).expanduser()


def install(codex_home: Path, force: bool = False) -> Path:
    codex_home = codex_home.expanduser().resolve()
    skills_dir = codex_home / "skills"
    destination = skills_dir / SKILL_NAME
    marker = destination / ".manager-home"

    if destination.exists():
        same_install = False
        if marker.is_file():
            try:
                same_install = Path(marker.read_text(encoding="utf-8").strip()).resolve() == ROOT
            except OSError:
                same_install = False
        if not same_install and not force:
            raise RuntimeError(
                "A different manage-wechat-messages skill is already installed; use --force to replace it"
            )
        if force and not same_install:
            resolved = destination.resolve()
            expected_parent = skills_dir.resolve()
            if resolved.parent != expected_parent or resolved.name != SKILL_NAME:
                raise RuntimeError("Refusing to replace an unexpected skill path")
            shutil.rmtree(resolved)

    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        SOURCE,
        destination,
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".manager-home"),
    )
    marker.write_text(str(ROOT) + "\n", encoding="utf-8")
    try:
        os.chmod(marker, 0o600)
    except OSError:
        pass
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description="Install the bundled Codex Skill")
    parser.add_argument("--codex-home", type=Path, default=default_codex_home())
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    try:
        install(args.codex_home, args.force)
        print(json.dumps({
            "status": "SKILL_INSTALLED",
            "skill": SKILL_NAME,
            "destination": "$CODEX_HOME/skills/manage-wechat-messages",
            "repository_linked": True,
            "private_path_output": False,
            "next_step": "Start a new Codex session so the installed skill is discovered",
        }, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "FAILED", "error": redact_private_text(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
