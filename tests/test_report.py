from pathlib import Path

from agent import remediation, report


def test_report_artifacts_created(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    secrets = {
        "secrets": [
            {
                "file": "a.py",
                "line": 1,
                "column": 1,
                "label": "GitHub PAT",
                "rule_id": "github-pat",
                "redacted_match": "ghp_...AAAA",
                "fingerprint": "abc",
                "snippet": "token=ghp_...AAAA",
            }
        ]
    }
    deps = {"pip_audit": {"dependencies": []}}
    licenses = {"licenses": [], "sbom_path": None}
    findings = remediation.normalize_findings(secrets, deps, licenses)
    plan = remediation.deterministic_remediation_plan(findings)
    sarif, pdf, summary = report.summarize(
        repo,
        secrets,
        deps,
        licenses,
        findings=findings,
        remediation_plan=plan,
    )
    assert Path(sarif).exists()
    assert Path(pdf).exists()
    assert "Findings: 1" in summary
