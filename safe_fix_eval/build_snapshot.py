"""Download real advisory data from PyPI and save it as a frozen snapshot.

Why a snapshot?
    Advisory databases change every day. If the benchmark asked the live
    database on every run, the numbers in the README could change without
    any code change. So we download once, save the data to
    benchmark/advisory_snapshot.json, and every benchmark run reads that file.
    Re-run this script to refresh the data (then re-run the benchmark).

Where does the data come from?
    PyPI's JSON API (https://pypi.org/pypi/<package>/<version>/json) returns a
    "vulnerabilities" list for each release. PyPI fills that list from the OSV
    database (osv.dev), so every advisory has a real OSV/GHSA/PYSEC ID and an
    osv.dev link. This is the same source pip-audit uses by default.

Usage:
    python -m safe_fix_eval.build_snapshot
"""

from __future__ import annotations

import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from packaging.version import InvalidVersion, Version

from safe_fix_eval.advisories import canonical_id

SNAPSHOT_PATH = Path(__file__).parent / "benchmark" / "advisory_snapshot.json"

# Packages used by the toy projects, and the oldest version we need data for.
# We only download releases from this version upward (that is all the fixer
# can ever propose, because it only upgrades).
PACKAGES = {
    "jinja2": "3.0.3",
    "requests": "2.25.1",
    "urllib3": "1.26.17",
    "idna": "3.6",
    "certifi": "2022.12.7",
    "pygments": "2.7.3",
    "sqlparse": "0.4.3",
    "tqdm": "4.66.1",
    "werkzeug": "2.2.2",
    "babel": "2.9.0",
    "zipp": "3.18.0",
}


def _get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=30) as response:
        return json.load(response)


def _stable_releases(package: str, minimum: str) -> list[str]:
    """All non-yanked, non-prerelease versions >= minimum, oldest first."""
    data = _get_json(f"https://pypi.org/pypi/{package}/json")
    versions = []
    for text, files in data["releases"].items():
        try:
            version = Version(text)
        except InvalidVersion:
            continue
        if version.is_prerelease or version < Version(minimum):
            continue
        if not files or all(f.get("yanked") for f in files):
            continue
        versions.append(version)
    return [str(v) for v in sorted(versions)]


def _advisories_for(package: str, version: str) -> tuple[list[str], dict]:
    """Advisory IDs affecting one release, de-duplicated across aliases."""
    data = _get_json(f"https://pypi.org/pypi/{package}/{version}/json")
    ids: set[str] = set()
    details: dict = {}
    for vuln in data.get("vulnerabilities", []):
        if vuln.get("withdrawn"):
            continue
        cid = canonical_id(vuln["id"], vuln.get("aliases") or [])
        ids.add(cid)
        details[cid] = {
            "aliases": sorted(set([vuln["id"], *(vuln.get("aliases") or [])]) - {cid}),
            "fixed_in": vuln.get("fixed_in") or [],
            "link": f"https://osv.dev/vulnerability/{cid}",
        }
    return sorted(ids), details


def build() -> dict:
    snapshot = {
        "source": "PyPI JSON API vulnerabilities field (populated from OSV, osv.dev)",
        "downloaded_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "packages": {},
        "advisories": {},
    }
    for package, minimum in PACKAGES.items():
        releases = _stable_releases(package, minimum)
        per_version = {}
        for version in releases:
            ids, details = _advisories_for(package, version)
            per_version[version] = ids
            snapshot["advisories"].update(details)
        snapshot["packages"][package] = {"versions": releases, "advisories_by_version": per_version}
        print(f"{package}: {len(releases)} releases checked")
    return snapshot


if __name__ == "__main__":
    data = build()
    SNAPSHOT_PATH.parent.mkdir(parents=True, exist_ok=True)
    SNAPSHOT_PATH.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    print(f"Wrote {SNAPSHOT_PATH}")
