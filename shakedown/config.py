"""Load credentials from a local `.env` file into os.environ.

Values are never printed or returned, only the names that were set. A variable that is
already set in the real environment is left alone.
"""
import os
from pathlib import Path

DEFAULT_ENV_FILE = Path(__file__).resolve().parents[1] / ".env"


def load_dotenv(path: Path = DEFAULT_ENV_FILE) -> list[str]:
    path = Path(path)
    if not path.is_file():
        return []
    loaded = []
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        name, value = name.strip(), value.strip().strip("\"'")
        if name and value and name not in os.environ:
            os.environ[name] = value
            loaded.append(name)
    return loaded
