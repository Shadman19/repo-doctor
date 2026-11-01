"""Safety gates. A proposed fix must pass ALL of them, in order, to be marked
"safe_to_auto_apply". (This evaluation writes the patched requirements to the
results folder; it never edits the benchmark projects themselves.)

Step 0  proposal check   The answer names the right package, a real released
                         version, and is an upgrade. (Stops invented versions
                         and injected packages before anything else runs.)
Gate a  advisory gone    Re-scan: none of the original advisories remain.
Gate b  nothing new      Re-scan the whole file: no advisory appears that was
                         not there before.
Gate c  tests pass       Install the new requirements in a fresh virtual
                         environment and run the project's own tests.
Gate d  semver           A major-version bump is never auto-applied. It goes
                         to a human, even if a-c passed.

The first failure stops the pipeline (later gates are logged as "skipped").
Every step is written to the log, pass or fail, with a reason.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from packaging.version import Version

from safe_fix_eval.advisories import AdvisoryDB, parse_requirements, render_requirements


@dataclass
class GateResult:
    gate: str
    passed: Optional[bool]  # True, False, or None when the gate was skipped
    reason: str


@dataclass
class FixOutcome:
    package: str
    old_version: str
    new_version: Optional[str]
    proposer: str
    decision: str  # "safe_to_auto_apply", "human_review_major_bump", or "rejected_at_<gate>"
    log: list[GateResult] = field(default_factory=list)


# ---------------------------------------------------------------- step 0
def check_proposal(db: AdvisoryDB, proposal: dict, package: str, current_version: str) -> GateResult:
    name = "0_proposal_check"
    if proposal.get("package") != package:
        return GateResult(name, False, f"proposal names {proposal.get('package')!r}, expected {package!r}")
    new_version = proposal.get("new_version")
    if not new_version:
        return GateResult(name, False, "no fixed version exists or none was proposed")
    if new_version not in db.versions(package):
        return GateResult(name, False, f"{package}=={new_version} is not a real release in the snapshot")
    if Version(new_version) <= Version(current_version):
        return GateResult(name, False, f"{new_version} is not an upgrade from {current_version}")
    return GateResult(name, True, f"{package} {current_version} -> {new_version} is a real upgrade")


# ---------------------------------------------------------------- gate a
def gate_a_advisory_gone(db: AdvisoryDB, package: str, new_version: str, original_ids: set[str]) -> GateResult:
    remaining = db.advisories(package, new_version) & original_ids
    if remaining:
        return GateResult("a_advisory_gone", False, f"still affected by {sorted(remaining)}")
    return GateResult("a_advisory_gone", True, f"all {len(original_ids)} original advisories resolved")


# ---------------------------------------------------------------- gate b
def gate_b_no_new_advisories(db: AdvisoryDB, old_pins: dict[str, str], new_pins: dict[str, str]) -> GateResult:
    def all_ids(pins: dict[str, str]) -> set[str]:
        found: set[str] = set()
        for ids in db.scan(pins).values():
            found |= ids
        return found

    introduced = all_ids(new_pins) - all_ids(old_pins)
    if introduced:
        return GateResult("b_no_new_advisories", False, f"new advisories introduced: {sorted(introduced)}")
    return GateResult("b_no_new_advisories", True, "no new advisories in the re-scan")


# ---------------------------------------------------------------- gate c
TestRunner = Callable[[Path, str], tuple[bool, str]]


def run_project_tests(project_dir: Path, requirements_text: str) -> tuple[bool, str]:
    """Install requirements in a fresh venv and run the project's tests.

    Returns (passed, short_log). A failed install counts as a failure:
    if we cannot install it, we cannot call it safe.
    Venvs are cached by the hash of the requirements, so identical
    requirements are only installed once per run.
    """
    pins = parse_requirements(requirements_text)  # comments dropped here too
    clean_reqs = "\n".join(f"{p}=={v}" for p, v in sorted(pins.items())) + "\n"
    key = hashlib.sha256(clean_reqs.encode()).hexdigest()[:12]
    venv = Path(tempfile.gettempdir()) / "safe-fix-eval-venvs" / key
    python = venv / "bin" / "python"

    if not python.exists():
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, capture_output=True)
        req_file = venv / "requirements.txt"
        req_file.write_text(clean_reqs)
        install = subprocess.run(
            [str(python), "-m", "pip", "install", "-q", "--disable-pip-version-check",
             "-r", str(req_file), "pytest"],
            capture_output=True, text=True,
        )
        if install.returncode != 0:
            shutil.rmtree(venv, ignore_errors=True)
            return False, "install failed: " + install.stderr.strip()[-300:]

    test = subprocess.run(
        # "-o addopts=" ignores pytest settings from the outer repo.
        [str(python), "-m", "pytest", "-q", "-o", "addopts=", "-p", "no:cacheprovider",
         str(Path(project_dir).resolve())],
        capture_output=True, text=True, cwd=project_dir,
    )
    # Keep pytest's final count line, e.g. "2 passed in 0.03s" or "1 failed, 1 passed".
    lines = [ln.strip("= ") for ln in test.stdout.splitlines()
             if " passed" in ln or " failed" in ln or " error" in ln]
    summary = lines[-1] if lines else (test.stdout + test.stderr).strip()[-300:]
    # On failure, also keep the first error line so the log says WHY.
    errors = [ln.strip()[1:].strip() for ln in test.stdout.splitlines() if ln.startswith("E ")]
    if test.returncode != 0 and errors:
        summary += f" | {errors[0]}"
    return test.returncode == 0, summary


def gate_c_tests_pass(project_dir: Path, new_requirements_text: str,
                      runner: TestRunner = run_project_tests) -> GateResult:
    passed, summary = runner(project_dir, new_requirements_text)
    return GateResult("c_tests_pass", passed, summary)


# ---------------------------------------------------------------- gate d
def is_major_bump(old: str, new: str) -> bool:
    """Semantic versioning: a change in the first number is a major bump.

    For 0.x versions, semver says anything can break, so 0.4 -> 0.5 also
    counts as major.
    """
    o, n = Version(old), Version(new)
    if n.major != o.major:
        return True
    return o.major == 0 and n.minor != o.minor


def gate_d_semver(old: str, new: str) -> GateResult:
    if is_major_bump(old, new):
        return GateResult("d_semver", False, f"major bump {old} -> {new}: needs human review")
    return GateResult("d_semver", True, f"{old} -> {new} is a minor or patch bump")


# ---------------------------------------------------------------- pipeline
GATE_ORDER = ["0_proposal_check", "a_advisory_gone", "b_no_new_advisories", "c_tests_pass", "d_semver"]


def evaluate_fix(db: AdvisoryDB, project_dir: Path, requirements_text: str, package: str,
                 proposal: dict, runner: TestRunner = run_project_tests) -> FixOutcome:
    """Run one proposal through every gate, in order, stopping at the first failure."""
    old_pins = parse_requirements(requirements_text)
    old_version = old_pins[package]
    original_ids = db.advisories(package, old_version)
    outcome = FixOutcome(package, old_version, proposal.get("new_version"),
                         proposal.get("source", "unknown"), decision="")

    steps = [lambda: check_proposal(db, proposal, package, old_version)]
    new_version = proposal.get("new_version")
    new_text = new_pins = None
    if new_version:
        new_text = render_requirements(requirements_text, package, new_version)
        new_pins = parse_requirements(new_text)
    steps += [
        lambda: gate_a_advisory_gone(db, package, new_version, original_ids),
        lambda: gate_b_no_new_advisories(db, old_pins, new_pins),
        lambda: gate_c_tests_pass(project_dir, new_text, runner),
        lambda: gate_d_semver(old_version, new_version),
    ]

    for gate_name, step in zip(GATE_ORDER, steps):
        if outcome.decision:  # an earlier gate failed
            outcome.log.append(GateResult(gate_name, None, "skipped (earlier gate failed)"))
            continue
        result = step()
        outcome.log.append(result)
        if not result.passed:
            if gate_name == "d_semver":
                outcome.decision = "human_review_major_bump"
            else:
                outcome.decision = f"rejected_at_{gate_name}"

    if not outcome.decision:
        outcome.decision = "safe_to_auto_apply"
    return outcome
