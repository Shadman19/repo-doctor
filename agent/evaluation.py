from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

from agent import remediation, tools


def load_cases(path: Path) -> list[dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list):
        raise ValueError("Benchmark cases must be a JSON list.")
    return value


def _safe_div(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def run_benchmark(cases_path: Path | None = None) -> dict[str, Any]:
    if cases_path is None:
        cases_path = Path(__file__).resolve().parents[1] / "benchmarks" / "secret_cases.json"
    cases = load_cases(cases_path)

    expected: set[tuple[str, str]] = set()
    observed: set[tuple[str, str]] = set()
    raw_values: dict[str, str] = {}

    with tempfile.TemporaryDirectory(prefix="repo-doctor-benchmark-") as tmp:
        root = Path(tmp)
        for case in cases:
            case_id = str(case["id"])
            filename = str(case.get("filename") or f"{case_id}.txt")
            content = str(case.get("content") or "")
            path = root / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            for label in case.get("expected_labels", []):
                expected.add((filename, str(label)))
            if case.get("sensitive_value"):
                raw_values[case_id] = str(case["sensitive_value"])

        scanner_output = tools.scan_secrets(root)
        for finding in scanner_output.get("secrets", []):
            observed.add((str(finding.get("file")), str(finding.get("label"))))

        true_positives = len(expected & observed)
        false_positives = len(observed - expected)
        false_negatives = len(expected - observed)
        precision = _safe_div(true_positives, true_positives + false_positives)
        recall = _safe_div(true_positives, true_positives + false_negatives)
        f1 = _safe_div(2 * precision * recall, precision + recall)

        # Privacy invariant: scanner output must not expose full matched values.
        serialized = json.dumps(scanner_output, sort_keys=True)
        redaction_pass = "\"match\"" not in serialized
        for raw in raw_values.values():
            if raw and raw in serialized:
                redaction_pass = False
                break

        findings = remediation.normalize_findings(
            scanner_output,
            {"pip_audit": {"dependencies": []}},
            {"licenses": [], "sbom_path": None},
        )
        plan = remediation.deterministic_remediation_plan(findings)
        remediation_ids = {
            str(item.get("finding_id")) for item in plan.get("remediations", [])
        }
        finding_ids = {str(item.get("id")) for item in findings}
        remediation_coverage = _safe_div(
            len(remediation_ids & finding_ids), len(finding_ids)
        ) if finding_ids else 1.0

        result = {
            "benchmark": "repo-doctor-synthetic-secret-benchmark-v1",
            "cases": len(cases),
            "expected_findings": len(expected),
            "observed_findings": len(observed),
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "redaction_pass": redaction_pass,
            "remediation_coverage": round(remediation_coverage, 4),
            "expected_not_observed": sorted([list(item) for item in expected - observed]),
            "observed_not_expected": sorted([list(item) for item in observed - expected]),
            "notes": [
                "All credentials are synthetic examples and must never be used as real credentials.",
                "This benchmark covers deterministic secret-pattern detection and remediation coverage only.",
                "Dependency vulnerability results are intentionally excluded because advisory databases change over time.",
                "A perfect synthetic score is not evidence of production security effectiveness.",
            ],
        }
        return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Repo Doctor's deterministic synthetic benchmark.")
    parser.add_argument("--cases", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    result = run_benchmark(args.cases)
    text = json.dumps(result, indent=2, sort_keys=True)
    print(text)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
