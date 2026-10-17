from __future__ import annotations

import json
import os
from typing import Any, Dict

import streamlit as st
from pydantic import BaseModel, Field

from agent import remediation, report, tools

st.set_page_config(page_title="Repo Doctor", page_icon="🩺", layout="wide")

st.title("🩺 Repo Doctor — Code Risk & Remediation Agent")
st.caption(
    "Deterministic scanners find secrets, vulnerable Python dependencies, and license risks. "
    "An optional Amazon Bedrock step turns redacted findings into a human-reviewed remediation plan."
)

with st.sidebar:
    st.header("Security controls")
    block_gpl = st.checkbox("Flag GPL/AGPL licenses", value=True)
    generate_remediation = st.checkbox("Generate remediation plan", value=True)
    use_bedrock = st.checkbox("Use Amazon Bedrock for remediation", value=False)

    default_region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1"
    default_model = os.getenv("REPO_DOCTOR_BEDROCK_MODEL_ID", "")
    region = st.text_input("AWS region", value=default_region, disabled=not use_bedrock)
    model_id = st.text_input(
        "Bedrock model ID / inference-profile ARN",
        value=default_model,
        disabled=not use_bedrock,
        help="No default is assumed because model availability varies by account and region.",
    )
    guardrail_id = st.text_input("Guardrail ID (optional)", disabled=not use_bedrock)
    guardrail_version = st.text_input("Guardrail version (optional)", disabled=not use_bedrock)
    st.info(
        "Only normalized, redacted findings are sent to Bedrock. Repository source and raw credential values are not included."
    )

st.subheader("Repository input")
git_url = st.text_input("Public HTTPS Git URL. Leave empty if you will upload a zip.")
zip_file = st.file_uploader("Or upload a .zip of your repository", type=["zip"])
run_btn = st.button("Run security scan", type="primary")


class Plan(BaseModel):
    intent: str = "scan"
    params: Dict[str, Any] = Field(default_factory=dict)


def _run_all(
    src_url: str,
    zip_bytes: bytes | None,
    *,
    block_gpl: bool,
    generate_remediation: bool,
    use_bedrock: bool,
    model_id: str,
    region: str,
    guardrail_id: str,
    guardrail_version: str,
) -> dict[str, Any]:
    repo_dir = tools.fetch_repo_or_zip(src_url, zip_bytes)

    secrets = tools.scan_secrets(repo_dir)
    deps = tools.audit_deps(repo_dir)
    licenses = tools.sbom_and_licenses(repo_dir)
    findings = remediation.normalize_findings(
        secrets, deps, licenses, block_gpl=block_gpl
    )

    if generate_remediation:
        remediation_plan = remediation.generate_remediation_plan(
            findings,
            use_bedrock=use_bedrock,
            model_id=model_id,
            region_name=region,
            guardrail_identifier=guardrail_id or None,
            guardrail_version=guardrail_version or None,
        )
    else:
        remediation_plan = {
            "provider": "not-generated",
            "summary": {"total_findings": len(findings)},
            "remediations": [],
        }

    sarif_path, pdf_path, summary = report.summarize(
        repo_dir,
        secrets,
        deps,
        licenses,
        findings=findings,
        remediation_plan=remediation_plan,
        block_gpl=block_gpl,
    )
    patch = tools.generate_patch(repo_dir, secrets, deps, licenses)
    return {
        "summary": summary,
        "sarif_path": sarif_path,
        "pdf_path": pdf_path,
        "patch": patch,
        "findings": findings,
        "remediation_plan": remediation_plan,
        "sbom_path": licenses.get("sbom_path"),
    }


if run_btn:
    if not git_url and not zip_file:
        st.error("Provide a public Git URL or upload a zip.")
        st.stop()
    if use_bedrock and not model_id.strip():
        st.error("Enter a Bedrock model ID or inference-profile ARN, or disable Bedrock.")
        st.stop()
    if bool(guardrail_id) ^ bool(guardrail_version):
        st.error("Provide both Guardrail ID and Guardrail version, or leave both blank.")
        st.stop()

    try:
        with st.spinner("Scanning repository and building remediation plan..."):
            out = _run_all(
                git_url,
                zip_file.read() if zip_file else None,
                block_gpl=block_gpl,
                generate_remediation=generate_remediation,
                use_bedrock=use_bedrock,
                model_id=model_id,
                region=region,
                guardrail_id=guardrail_id,
                guardrail_version=guardrail_version,
            )
    except Exception as exc:
        st.exception(exc)
        st.stop()

    st.success("Scan complete.")
    st.write(out["summary"])

    findings = out["findings"]
    severity_counts: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity", "info"))
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    metrics = st.columns(5)
    metrics[0].metric("Total", len(findings))
    metrics[1].metric("Critical", severity_counts.get("critical", 0))
    metrics[2].metric("High", severity_counts.get("high", 0))
    metrics[3].metric("Medium", severity_counts.get("medium", 0))
    metrics[4].metric("Remediation", out["remediation_plan"].get("provider", "none"))

    if findings:
        st.subheader("Normalized findings")
        st.dataframe(findings, use_container_width=True, hide_index=True)
    else:
        st.info("No findings were produced by the enabled checks.")

    st.subheader("Human-reviewed remediation plan")
    plan = out["remediation_plan"]
    if plan.get("bedrock_error"):
        st.warning(
            "Bedrock was unavailable or returned invalid output. Repo Doctor used deterministic fallback guidance. "
            f"Details: {plan['bedrock_error']}"
        )
    for item in plan.get("remediations", []):
        with st.expander(
            f"{item.get('finding_id')} · {item.get('priority', '').upper()} · {item.get('title')}"
        ):
            st.write("**Actions**")
            for action in item.get("actions", []):
                st.write(f"- {action}")
            st.write("**Verification**")
            for check in item.get("verification", []):
                st.write(f"- {check}")
            if item.get("rationale"):
                st.write(f"**Rationale:** {item['rationale']}")
            st.caption("Auto-apply is disabled; a human must review and execute remediation.")

    st.subheader("Artifacts")
    columns = st.columns(5)
    with open(out["sarif_path"], "rb") as handle:
        columns[0].download_button(
            "Download SARIF", handle, file_name="repo-doctor.sarif"
        )
    with open(out["pdf_path"], "rb") as handle:
        columns[1].download_button(
            "Download PDF", handle, file_name="repo-doctor.pdf"
        )
    columns[2].download_button(
        "Download Patch",
        out["patch"].encode("utf-8"),
        file_name="repo-doctor.patch",
    )
    columns[3].download_button(
        "Download Remediation JSON",
        json.dumps(plan, indent=2).encode("utf-8"),
        file_name="repo-doctor-remediation.json",
        mime="application/json",
    )
    if out.get("sbom_path"):
        with open(out["sbom_path"], "rb") as handle:
            columns[4].download_button(
                "Download SBOM", handle, file_name="repo-doctor-sbom.json"
            )
