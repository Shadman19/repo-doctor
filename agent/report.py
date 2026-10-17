from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


def _count_vulnerabilities(deps: dict[str, Any]) -> tuple[int, int]:
    pip_audit = deps.get("pip_audit", {})
    if not isinstance(pip_audit, dict):
        return 0, 0
    dependencies = pip_audit.get("dependencies", [])
    if not isinstance(dependencies, list):
        return 0, 0
    vulnerability_count = sum(
        len(dep.get("vulns", []) or []) for dep in dependencies if isinstance(dep, dict)
    )
    return len(dependencies), vulnerability_count


def _sarif_level(severity: str) -> str:
    return {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }.get(severity, "warning")


def _sarif_result(finding: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding.get("rule_id") or finding.get("category") or "RepoDoctorFinding",
        "level": _sarif_level(str(finding.get("severity", "medium"))),
        "message": {"text": str(finding.get("title", "Repo Doctor finding"))},
        "properties": {
            "findingId": finding.get("id"),
            "category": finding.get("category"),
            "severity": finding.get("severity"),
            "source": finding.get("source"),
        },
    }
    if finding.get("fingerprint"):
        result["properties"]["fingerprint"] = finding.get("fingerprint")
    if finding.get("package"):
        result["properties"]["package"] = finding.get("package")
    if finding.get("fix_versions"):
        result["properties"]["fixVersions"] = finding.get("fix_versions")

    if finding.get("file"):
        region: dict[str, Any] = {}
        if finding.get("line"):
            region["startLine"] = int(finding["line"])
        if finding.get("column"):
            region["startColumn"] = int(finding["column"])
        physical_location: dict[str, Any] = {
            "artifactLocation": {"uri": finding["file"]}
        }
        if region:
            physical_location["region"] = region
        result["locations"] = [{"physicalLocation": physical_location}]
    return result


def summarize(
    repo_dir: Path,
    secrets: dict[str, Any],
    deps: dict[str, Any],
    licenses: dict[str, Any],
    *,
    findings: list[dict[str, Any]] | None = None,
    remediation_plan: dict[str, Any] | None = None,
    block_gpl: bool = True,
) -> tuple[str, str, str]:
    del block_gpl  # retained for backwards compatibility
    findings = findings or []
    remediation_plan = remediation_plan or {}

    outdir = Path(repo_dir) / "_repo_doctor"
    outdir.mkdir(exist_ok=True, parents=True)
    sarif_path = outdir / "report.sarif"
    pdf_path = outdir / "report.pdf"

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "RepoDoctor",
                        "version": "0.2.0",
                        "informationUri": "https://github.com/Shadman19/repo-doctor",
                    }
                },
                "results": [_sarif_result(finding) for finding in findings],
            }
        ],
    }
    sarif_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")

    dependency_count, vulnerability_count = _count_vulnerabilities(deps)
    severity_counts: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity", "info"))
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    pdf = canvas.Canvas(str(pdf_path), pagesize=A4)
    width, height = A4
    y = height - 60

    def new_page() -> None:
        nonlocal y
        pdf.showPage()
        y = height - 60

    def line(text: str, *, dy: int = 16, indent: int = 0, bold: bool = False) -> None:
        nonlocal y
        if y < 70:
            new_page()
        pdf.setFont("Helvetica-Bold" if bold else "Helvetica", 10 if not bold else 11)
        safe = str(text).replace("\n", " ")
        while len(safe) > 105:
            split = safe.rfind(" ", 0, 105)
            if split < 40:
                split = 105
            pdf.drawString(60 + indent, y, safe[:split])
            y -= dy
            safe = safe[split:].lstrip()
            if y < 70:
                new_page()
        pdf.drawString(60 + indent, y, safe)
        y -= dy

    pdf.setFont("Helvetica-Bold", 17)
    pdf.drawString(60, y, "Repo Doctor Security Report")
    y -= 26
    line(f"Repository: {Path(repo_dir).name}")
    line(f"Total normalized findings: {len(findings)}")
    line(
        "Severity: "
        + ", ".join(f"{key}={value}" for key, value in sorted(severity_counts.items()))
        if severity_counts
        else "Severity: no findings"
    )
    line(f"Possible secrets: {len(secrets.get('secrets', []))}")
    line(f"Python dependencies audited: {dependency_count}; vulnerability records: {vulnerability_count}")
    line(f"SBOM generated: {'yes' if licenses.get('sbom_path') else 'no'}")
    line(f"Remediation provider: {remediation_plan.get('provider', 'not generated')}")
    line("Raw secrets are redacted; no remediation is automatically applied.")

    y -= 8
    line("Highest-priority findings", bold=True)
    for finding in findings[:10]:
        location = finding.get("file") or finding.get("package") or "repository"
        line(
            f"[{str(finding.get('severity', 'info')).upper()}] {finding.get('id')}: "
            f"{finding.get('title')} ({location})",
            indent=10,
        )

    remediations = remediation_plan.get("remediations", [])
    if remediations:
        y -= 8
        line("Remediation plan", bold=True)
        for item in remediations[:10]:
            line(f"{item.get('finding_id')}: {item.get('title')}", indent=10, bold=True)
            for action in (item.get("actions") or [])[:3]:
                line(f"- {action}", indent=20)

    pdf.save()

    summary = (
        f"Scan complete. Findings: {len(findings)}; secrets: {len(secrets.get('secrets', []))}; "
        f"dependency vulnerability records: {vulnerability_count}; "
        f"SBOM: {'yes' if licenses.get('sbom_path') else 'no'}; "
        f"remediation: {remediation_plan.get('provider', 'none')}."
    )
    return str(sarif_path), str(pdf_path), summary
