---
title: Repo Doctor
emoji: 🩺
colorFrom: indigo
colorTo: green
sdk: docker
pinned: false
---

# 🩺 Repo Doctor — Code Risk & Fix Agent

**What it does**
- Scan any repo (git URL or zip) for:
  - **Possible secrets** (regex rules for keys, tokens, private keys)
  - **Dependency vulnerabilities** (via `pip-audit` for Python projects)
  - **License/SBOM** (via `cyclonedx-py`)
- Generate a **PDF** executive summary, a **SARIF** machine-readable report, and a **patch suggestion** (unified diff) with fixes like `.gitignore` additions and version bumps.
- Clean Streamlit UI. No API keys required.

**Why it’s useful**
- Demonstrates agentic workflow (plan → tools → synthesize → act).
- Produces concrete dev/security artifacts (SARIF, PDF, patches).
- Runs fully in a reproducible Docker Space + tests.

## Run locally
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
