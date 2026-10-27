"""The example manifest in the docs must stay valid, or readers copy something broken."""
import shutil
from pathlib import Path

import yaml
from test_byo import evtx

from shakedown import byo

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/byo/manifest.example.yml"


def test_the_documented_example_manifest_passes_the_real_validator(tmp_path):
    shutil.copy(EXAMPLE, tmp_path / "manifest.yml")
    doc = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    for i, entry in enumerate(doc["attack"]):
        evtx(tmp_path / entry["file"], f"attack-{i}".encode())
    for entry in doc["benign"]:
        evtx(Path(tmp_path / entry["path"]) / "b1.evtx", b"benign")

    manifest = byo.load_manifest(tmp_path / "manifest.yml")

    assert [a.expect for a in manifest.attack] == ["detect", "no_detect"] and manifest.benign[0].basis == "production_sample"
