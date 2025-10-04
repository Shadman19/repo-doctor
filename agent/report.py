from pathlib import Path
from typing import Dict, Any
import json
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

def _license_flags(licenses: Dict[str, Any], block_gpl: bool) -> list[str]:
    flags = []
    if block_gpl:
        for lic in licenses.get("licenses", []):
            preview = lic.get("preview","").lower()
            if "gpl" in preview or "agpl" in preview:
                flags.append(f"Potential GPL/AGPL in {lic.get('file')}")
    return flags

def summarize(repo_dir: Path, secrets: dict, deps: dict, licenses: dict, block_gpl: bool = True):
    outdir = Path(repo_dir) / "_repo_doctor"
    outdir.mkdir(exist_ok=True, parents=True)
    sarif_path = outdir / "report.sarif"
    pdf_path = outdir / "report.pdf"

    # Build minimal SARIF (hand-rolled, compatible)
    results = []
    for s in secrets.get("secrets", []):
        results.append({
            "ruleId": "SecretDetected",
            "level": "error",
            "message": {"text": f"{s['label']} possibly exposed"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": s["file"]}}}],
            "properties": {"snippet": s.get("snippet","")}
        })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "RepoDoctor", "version": "0.1.0"}},
            "results": results
        }]
    }
    sarif_path.write_text(json.dumps(sarif, indent=2))

    # PDF summary
    c = canvas.Canvas(str(pdf_path), pagesize=A4)
    W, H = A4
    y = H - 72
    def line(txt, dy=18, indent=0):
        nonlocal y
        c.drawString(72+indent, y, txt)
        y -= dy

    c.setFont("Helvetica-Bold", 16); line("Repo Doctor Report", 24)
    c.setFont("Helvetica", 10); line(f"Repository: {Path(repo_dir).name}")
    line(f"Secrets found: {len(secrets.get('secrets', []))}")
    pa = deps.get("pip_audit", {})
    if isinstance(pa, dict) and "dependencies" in pa:
        vulns = sum(len(d.get("vulns",[])) for d in pa["dependencies"])
        line(f"Python dependencies audited: {len(pa['dependencies'])}, vulnerabilities: {vulns}")
    else:
        line("pip-audit: no Python requirements found or parse error")

    if licenses.get("sbom_path"):
        line(f"SBOM generated: {licenses['sbom_path']}")
    else:
        line("SBOM: not generated")

    for flag in _license_flags(licenses, block_gpl):
        line(f"License flag: {flag}", indent=12)

    line("", 24)
    c.setFont("Helvetica-Bold", 12); line("Top Secret Findings:", 18)
    c.setFont("Helvetica", 10)
    for s in secrets.get("secrets", [])[:6]:
        line(f"- {s['label']} in {s['file']}", indent=12)

    c.showPage(); c.save()

    summary = (
        f"Scan complete. Secrets: {len(secrets.get('secrets', []))}. "
        f"pip-audit: {'ok' if 'dependencies' in pa else 'n/a'}. "
        f"SBOM: {'yes' if licenses.get('sbom_path') else 'no'}."
    )
    return str(sarif_path), str(pdf_path), summary
