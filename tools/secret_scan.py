"""Search the files you will publish for the credential values in .env, without ever printing a value.

    python tools/secret_scan.py                   # scans this project except data/, .venv/, .env and caches
    python tools/secret_scan.py --root <folder>   # scans another folder (for example a fresh clone) for THIS project's .env values
Exit code 1 if any value, or a token-shaped string, is found. Prints file paths only.
"""
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {"data", ".venv", ".git", "__pycache__", ".pytest_cache", ".aqg", "node_modules"}
TOKEN_SHAPES = re.compile(r"tvly-[A-Za-z0-9]{16,}|Bearer\s+[A-Za-z0-9._-]{24,}|-----BEGIN [A-Z ]*PRIVATE KEY-----")


def env_values() -> list[str]:
    path = ROOT / ".env"
    if not path.is_file():
        return []
    values = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            value = line.split("=", 1)[1].strip().strip("\"'")
            if len(value) >= 8:
                values.append(value)
    return values


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, default=ROOT)
    root = parser.parse_args().root.resolve()
    values, findings, scanned = env_values(), [], 0
    if not values:
        print("warning: no credential values found in this project's .env, so only token-shaped strings can be detected")
    for path in root.rglob("*"):
        if not path.is_file() or SKIP_DIRS & set(path.relative_to(root).parts) or path.name == ".env" or (path.name.startswith(".env.") and path.name != ".env.example"):
            continue
        if path.suffix in {".png", ".jpg", ".gz", ".tgz", ".evtx", ".pyc"}:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        scanned += 1
        if any(v in text for v in values) or TOKEN_SHAPES.search(text):
            findings.append(str(path.relative_to(root)))
    print(f"scanned {scanned} files against {len(values)} credential values from .env")
    for f in findings:
        print("FOUND in", f)
    print("clean" if not findings else f"{len(findings)} file(s) need attention")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
