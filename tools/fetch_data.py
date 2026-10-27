"""Fetch the third-party datasets and the checker Shakedown evaluates against, at pinned versions, into data/raw/.

    uv run python tools/fetch_data.py            # ~90 MB download + ~60 MB git checkout
    uv run python tools/fetch_data.py --dest /tmp/shakedown-data

Nothing here is redistributed by this repository (see NOTICE and docs/DATASET_AUDIT.md). The expected sha256 of every
release file is pinned below, not read from the release itself, so a swapped release asset is refused.
Needs: git on PATH and network access to github.com.
"""
import argparse
import hashlib
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SIGMA_URL = "https://github.com/SigmaHQ/sigma.git"
SIGMA_COMMIT = "05d1031f537e830b76da53bae2400c5814c89165"
SIGMA_PATHS = ["rules", "rules-threat-hunting", "rules-emerging-threats", "regression_data", "tests", "LICENSE"]
RELEASE = "https://github.com/NextronSystems/evtx-baseline/releases/download/v0.8.5"
PINNED = {  # file -> sha256 (docs/DATASET_AUDIT.md)
    "evtx-sigma-checker": "d672e07a516f3f72eaae8244f99fa2c5b133885a4401eb05a272903857d767e2",
    "win7-x86.tgz": "e755f3cd48f8a3dc8877c46622339cd44fa0929981fcfd79ada63c2bafb62b9f",
    "win10-client.tgz": "d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e",
}
EXPECTED_EVTX = {"win7-x86": 129, "Logs_Client": 352}


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True)


def fetch_sigma(dest: Path) -> None:
    repo = dest / "sigma"
    if (repo / ".git").exists():
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()
        if head == SIGMA_COMMIT:
            print(f"sigma: already at {SIGMA_COMMIT[:10]}")
            return
        raise SystemExit(f"{repo} exists at {head[:10]}, not the pinned {SIGMA_COMMIT[:10]}; remove it and rerun")
    repo.mkdir(parents=True, exist_ok=True)
    git(repo, "init", "-q")
    git(repo, "remote", "add", "origin", SIGMA_URL)
    git(repo, "sparse-checkout", "set", "--no-cone", *[f"/{p}" for p in SIGMA_PATHS])
    git(repo, "fetch", "-q", "--depth", "1", "origin", SIGMA_COMMIT)
    git(repo, "checkout", "-q", "FETCH_HEAD")
    print(f"sigma: checked out {SIGMA_COMMIT[:10]} ({', '.join(SIGMA_PATHS)})")


def download(name: str, target: Path) -> None:
    if target.exists() and sha256_of(target) == PINNED[name]:
        print(f"{name}: already present and verified")
        return
    print(f"{name}: downloading ...")
    with urllib.request.urlopen(f"{RELEASE}/{name}", timeout=120) as resp, target.open("wb") as out:
        while chunk := resp.read(1 << 20):
            out.write(chunk)
    actual = sha256_of(target)
    if actual != PINNED[name]:
        target.unlink()
        raise SystemExit(f"{name}: sha256 {actual} does not match the pinned {PINNED[name]}; file removed")
    print(f"{name}: sha256 verified")


def safe_extract(tar: tarfile.TarFile, target: Path) -> None:
    """Extract regular files and directories only, and only inside `target` (no filter= argument before Python 3.11.4)."""
    root = target.resolve()
    for member in tar.getmembers():
        if not (member.isfile() or member.isdir()):
            raise SystemExit(f"refusing archive member {member.name!r}: not a regular file or directory")
        if root not in (root / member.name).resolve().parents and (root / member.name).resolve() != root:
            raise SystemExit(f"refusing archive member {member.name!r}: outside the target directory")
    tar.extractall(target)


def fetch_baseline(dest: Path) -> None:
    base = dest / "evtx-baseline/v0.8.5"
    base.mkdir(parents=True, exist_ok=True)
    for name in PINNED:
        download(name, base / name)
    for archive in ("win7-x86.tgz", "win10-client.tgz"):
        with tarfile.open(base / archive) as tar:
            safe_extract(tar, base)
    for folder, expected in EXPECTED_EVTX.items():
        found = sum(1 for _ in (base / folder).rglob("*.evtx"))
        if found != expected:
            raise SystemExit(f"{folder}: found {found} EVTX files, expected {expected}")
        print(f"{folder}: {found} EVTX files")
    (base / "evtx-sigma-checker").chmod(0o755)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dest", type=Path, default=ROOT / "data/raw")
    args = parser.parse_args()
    args.dest.mkdir(parents=True, exist_ok=True)
    fetch_sigma(args.dest)
    fetch_baseline(args.dest)
    print(f"done: {args.dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
