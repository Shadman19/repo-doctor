"""Read requirements files and look up known advisories.

This file is the "scanner" for the safe auto-fix evaluation. It answers one
question: "Which known advisories affect the pinned versions in this
requirements.txt?" The answer comes from the frozen advisory snapshot
(see build_snapshot.py), so results are reproducible.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

SNAPSHOT_PATH = Path(__file__).parent / "benchmark" / "advisory_snapshot.json"

# A pinned requirement looks like "name==1.2.3". Nothing else is accepted.
_PIN_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9.+!-]+)$")


def canonical_id(vuln_id: str, aliases: list[str]) -> str:
    """Pick one stable name for an advisory that has several IDs.

    The same advisory often appears as a GHSA ID, a PYSEC ID and a CVE.
    We prefer GHSA, then PYSEC, then whatever ID we were given, so that one
    advisory is counted once.
    """
    all_ids = [vuln_id, *aliases]
    for prefix in ("GHSA-", "PYSEC-"):
        matches = sorted(i for i in all_ids if i.startswith(prefix))
        if matches:
            return matches[0]
    return vuln_id


def normalize_name(name: str) -> str:
    """PyPI treats Jinja2, jinja2 and jinja_2 as the same name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(text: str) -> dict[str, str]:
    """Return {package: pinned_version} from requirements text.

    Comments (anything after '#') are thrown away before parsing. This is the
    first defense against prompt injection: text hidden in comments never
    becomes data that later steps (including the LLM) can see.
    """
    pins: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        match = _PIN_RE.match(line)
        if not match:
            raise ValueError(f"Only exact pins like 'name==1.2.3' are supported, got: {line!r}")
        pins[normalize_name(match.group(1))] = match.group(2)
    return pins


def render_requirements(original_text: str, package: str, new_version: str) -> str:
    """Rewrite exactly one pin and keep every other line (comments included)."""
    out = []
    for raw_line in original_text.splitlines():
        code = raw_line.split("#", 1)[0].strip()
        match = _PIN_RE.match(code)
        if match and normalize_name(match.group(1)) == package:
            out.append(f"{match.group(1)}=={new_version}")
        else:
            out.append(raw_line)
    return "\n".join(out) + "\n"


class AdvisoryDB:
    """Lookup table: (package, version) -> list of advisory IDs."""

    def __init__(self, snapshot: dict):
        self.snapshot = snapshot

    @classmethod
    def load(cls, path: Path = SNAPSHOT_PATH) -> "AdvisoryDB":
        return cls(json.loads(Path(path).read_text()))

    def knows(self, package: str) -> bool:
        return package in self.snapshot["packages"]

    def versions(self, package: str) -> list[str]:
        """Real released versions of a package, oldest first."""
        return self.snapshot["packages"][package]["versions"]

    def advisories(self, package: str, version: str) -> set[str]:
        """Advisory IDs affecting package==version.

        Raises KeyError for a version we have no data for, so the caller can
        refuse to guess.
        """
        return set(self.snapshot["packages"][package]["advisories_by_version"][version])

    def detail(self, advisory_id: str) -> dict:
        return self.snapshot["advisories"].get(advisory_id, {})

    def scan(self, pins: dict[str, str]) -> dict[str, set[str]]:
        """Return {package: advisory IDs} for every package we have data on."""
        return {pkg: self.advisories(pkg, ver) for pkg, ver in pins.items() if self.knows(pkg)}
