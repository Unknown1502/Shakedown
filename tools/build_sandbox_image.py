"""Build the immutable evaluation image in Nebius Token Factory Sandboxes (run once; free during the beta).

Imports the pinned Debian base, uploads the checker, thor.yml and the two benign baseline archives
(after verifying their sha256 against the release's SHA256SUMS), extracts the archives and saves the
result under the tag `shakedown-eval:v1`. The image holds no credentials and no model output.
Writes data/audit/sandbox_image.json with the image UUID and every input hash.
"""
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from shakedown.config import load_dotenv  # noqa: E402
from shakedown.harness.sandbox import BASE_REF, BASE_TAG, IMAGE_TAG, sha256_of  # noqa: E402

BASELINE = ROOT / "data/raw/evtx-baseline/v0.8.5"
THOR = ROOT / "data/raw/sigma/tests/thor.yml"
EXPECTED_FILES = {"win7-x86": 129, "Logs_Client": 352}


def verified_inputs() -> dict[str, dict]:
    sums = {}
    for line in (BASELINE / "SHA256SUMS").read_text().splitlines():
        digest, _, name = line.partition(" *")
        sums[name.strip()] = digest.strip()
    inputs = {}
    for name in ("evtx-sigma-checker", "win7-x86.tgz", "win10-client.tgz"):
        actual = sha256_of(BASELINE / name)
        if actual != sums.get(name):
            raise SystemExit(f"{name}: sha256 {actual} does not match SHA256SUMS")
        inputs[name] = {"path": BASELINE / name, "sha256": actual}
    inputs["thor.yml"] = {"path": THOR, "sha256": sha256_of(THOR)}
    return inputs


async def main() -> None:
    from contree_sdk import Contree
    from contree_sdk.utils.models.file import UploadFileSpec

    load_dotenv()
    inputs = verified_inputs()
    client = Contree()
    print("importing base image ...")
    base = await client.images.oci(BASE_REF, tag=BASE_TAG)
    print("uploading inputs ...")
    staged = await base.apply_files({
        "/opt/checker": UploadFileSpec(source=inputs["evtx-sigma-checker"]["path"], mode=0o755),
        "/work/thor.yml": inputs["thor.yml"]["path"],
        "/data/win7-x86.tgz": inputs["win7-x86.tgz"]["path"],
        "/data/win10-client.tgz": inputs["win10-client.tgz"]["path"],
    })
    print("extracting and saving ...")
    final = await staged.run(
        shell=("cd /data && tar xzf win7-x86.tgz && tar xzf win10-client.tgz && rm win7-x86.tgz win10-client.tgz"
               " && chmod -R a+rX /data /work /opt/checker"
               " && echo win7-x86=$(find /data/win7-x86 -name '*.evtx' | wc -l)"
               " && echo Logs_Client=$(find /data/Logs_Client -name '*.evtx' | wc -l)"),
        disposable=False, tag=IMAGE_TAG, timeout=900)
    if final.exit_code != 0 or final.uuid is None:
        raise SystemExit(f"image build failed: {final.stderr[-500:]}")
    counts = dict(line.split("=") for line in final.stdout.split())
    for name, expected in EXPECTED_FILES.items():
        if int(counts.get(name, -1)) != expected:
            raise SystemExit(f"{name}: found {counts.get(name)} EVTX files, expected {expected}")

    record = {"built_at": datetime.now(timezone.utc).isoformat(), "image_tag": IMAGE_TAG, "image_uuid": str(final.uuid),
              "base": BASE_REF, "evtx_counts": counts,
              "inputs": {k: v["sha256"] for k, v in inputs.items()}}
    out = ROOT / "data/audit/sandbox_image.json"
    out.write_text(json.dumps(record, indent=1), encoding="utf-8")
    print(f"saved {IMAGE_TAG} -> {final.uuid}\ncounts {counts}\nrecord {out}")


if __name__ == "__main__":
    asyncio.run(main())
