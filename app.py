import streamlit as st
from pydantic import BaseModel
from typing import Dict, Any
from agent import tools, report

st.set_page_config(page_title="Repo Doctor", page_icon="🩺", layout="wide")

st.title("🩺 Repo Doctor — Code Risk & Fix Agent")
st.caption("Scan a repository for secrets, vulnerable dependencies, and license risks. Get SARIF, PDF, and patch suggestions.")

git_url = st.text_input("Git URL (public). Leave empty if you will upload a zip.")
zip_file = st.file_uploader("Or upload a .zip of your repo", type=["zip"])

block_gpl = st.checkbox("Flag GPL/AGPL licenses if present", value=True)
run_btn = st.button("Run scan")

class Plan(BaseModel):
    intent: str
    params: Dict[str, Any] = {}

@st.cache_data(show_spinner=False)
def _run_all(src_url: str, zip_bytes: bytes, block_gpl: bool):
    repo_dir = tools.fetch_repo_or_zip(src_url, zip_bytes)

    secrets = tools.scan_secrets(repo_dir)
    deps = tools.audit_deps(repo_dir)
    licenses = tools.sbom_and_licenses(repo_dir)

    sarif_path, pdf_path, summary = report.summarize(
        repo_dir, secrets, deps, licenses, block_gpl=block_gpl
    )
    patch = tools.generate_patch(repo_dir, secrets, deps, licenses)
    return {
        "summary": summary,
        "sarif_path": sarif_path,
        "pdf_path": pdf_path,
        "patch": patch
    }

if run_btn:
    if not git_url and not zip_file:
        st.error("Provide a Git URL or upload a zip.")
        st.stop()
    with st.spinner("Scanning repository..."):
        out = _run_all(git_url, zip_file.read() if zip_file else None, block_gpl)
    st.success("Scan complete.")
    st.write(out["summary"])

    c1, c2, c3 = st.columns(3)
    with open(out["sarif_path"], "rb") as f:
        c1.download_button("⬇️ Download SARIF", f, file_name="repo-doctor.sarif")
    with open(out["pdf_path"], "rb") as f:
        c2.download_button("⬇️ Download PDF", f, file_name="repo-doctor.pdf")
    c3.download_button("⬇️ Download Patch", out["patch"].encode(), file_name="repo-doctor.patch")
