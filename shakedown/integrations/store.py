"""Saved connection profiles and finished assessments. Neither file ever contains a credential.

Both stores are keyed by `owner` on every call and return "not found" for another owner's record, so one owner cannot learn that another
owner's connection or result exists. Today the app has one local operator; the owner is a constant. The isolation is enforced here so that
adding real accounts later does not require changing it.
"""
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from shakedown.integrations.base import IntegrationError


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _write_json(path: Path, doc) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".{uuid.uuid4().hex[:6]}.tmp")
    tmp.write_text(json.dumps(doc, indent=1, default=str), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)  # best effort; Windows ignores most mode bits
    except OSError:
        pass
    os.replace(tmp, path)


class ProfileStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.RLock()

    def _load(self) -> list:
        try:
            return json.loads(self.path.read_text(encoding="utf-8")).get("connections", [])
        except (OSError, ValueError):
            return []

    def _save(self, rows: list) -> None:
        _write_json(self.path, {"version": 1, "connections": rows})

    def list(self, owner: str) -> list:
        with self._lock:
            return [r for r in self._load() if r["owner"] == owner]

    def get(self, owner: str, conn_id: str) -> dict | None:
        with self._lock:
            return next((r for r in self._load() if r["id"] == conn_id and r["owner"] == owner), None)

    def create(self, owner: str, profile: dict) -> dict:
        with self._lock:
            rows = self._load()
            row = {**profile, "id": uuid.uuid4().hex[:12], "owner": owner, "created_at": _now(), "updated_at": _now()}
            rows.append(row)
            self._save(rows)
            return row

    def update(self, owner: str, conn_id: str, patch: dict) -> dict:
        with self._lock:
            rows = self._load()
            for row in rows:
                if row["id"] == conn_id and row["owner"] == owner:
                    row.update(patch)
                    row["updated_at"] = _now()
                    self._save(rows)
                    return row
        raise IntegrationError("not_found", "no such connection")

    def delete(self, owner: str, conn_id: str) -> bool:
        with self._lock:
            rows = self._load()
            keep = [r for r in rows if not (r["id"] == conn_id and r["owner"] == owner)]
            if len(keep) == len(rows):
                return False
            self._save(keep)
            return True


class AssessmentStore:
    """One JSON file per assessment. The record holds excerpts of the environment's events, so it is as sensitive as the SIEM itself."""

    def __init__(self, directory: Path):
        self.dir = Path(directory)
        self._lock = threading.RLock()

    def _path(self, assessment_id: str) -> Path:
        if not assessment_id.isalnum() or len(assessment_id) > 32:
            raise IntegrationError("not_found", "no such assessment")
        return self.dir / f"{assessment_id}.json"

    def save(self, owner: str, record: dict) -> dict:
        with self._lock:
            record = {**record, "owner": owner}
            record.setdefault("id", uuid.uuid4().hex[:12])
            _write_json(self._path(record["id"]), record)
            return record

    def get(self, owner: str, assessment_id: str) -> dict | None:
        try:
            doc = json.loads(self._path(assessment_id).read_text(encoding="utf-8"))
        except (OSError, ValueError, IntegrationError):
            return None
        return doc if doc.get("owner") == owner else None

    def list(self, owner: str, connection_id: str | None = None) -> list:
        out = []
        for p in sorted(self.dir.glob("*.json"), key=lambda q: q.stat().st_mtime, reverse=True) if self.dir.exists() else []:
            try:
                doc = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if doc.get("owner") == owner and (connection_id is None or doc.get("connection_id") == connection_id):
                out.append(doc)
        return out

    def delete_for_connection(self, owner: str, connection_id: str) -> int:
        n = 0
        with self._lock:
            for doc in self.list(owner, connection_id):
                try:
                    self._path(doc["id"]).unlink()
                    n += 1
                except OSError:
                    pass
        return n
