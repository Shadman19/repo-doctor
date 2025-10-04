import re, json, tempfile, zipfile, subprocess, os, io, shutil
from pathlib import Path
from typing import Optional

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key"),
    (r"xox[baprs]-[0-9a-zA-Z]{10,48}", "Slack token"),
    (r"ghp_[0-9A-Za-z]{36}", "GitHub PAT"),
    (r"-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----", "Private key block"),
    (r"sk-live-[0-9a-zA-Z]{24,}", "Stripe live secret"),
    (r"sk-test-[0-9a-zA-Z]{24,}", "Stripe test secret"),
    (r"(?i)secret_key\s*=\s*['\"][^'\"]+['\"]", "Generic secret assignment"),
]

TEXT_EXTS = {".py", ".js", ".ts", ".json", ".yml", ".yaml", ".env", ".txt", ".tf", ".md", ".ini", ".cfg", ".toml"}
BIN_EXTS = {".png", ".jpg", ".jpeg", ".pdf", ".gif", ".ico", ".zip", ".tar", ".gz", ".rar"}

def fetch_repo_or_zip(src_url: Optional[str], zip_bytes: Optional[bytes]) -> Path:
    work = Path(tempfile.mkdtemp(prefix="repo-doctor-"))
    repo_dir = work / "repo"
    repo_dir.mkdir(parents=True, exist_ok=True)
    if zip_bytes:
        zpath = work / "repo.zip"
        zpath.write_bytes(zip_bytes)
        with zipfile.ZipFile(zpath, 'r') as zf:
            zf.extractall(repo_dir)
    elif src_url:
        subprocess.run(["git", "clone", "--depth", "1", src_url, str(repo_dir)], check=True)
    else:
        raise ValueError("Provide a Git URL or upload a zip.")
    return repo_dir

def _is_text_file(path: Path) -> bool:
    suffix = path.suffix.lower()
    if suffix in BIN_EXTS:
        return False
    if suffix in TEXT_EXTS:
        return True
    # Heuristic: small files treated as text
    try:
        b = path.read_bytes()[:1024]
        b.decode("utf-8")
        return True
    except Exception:
        return False

def scan_secrets(repo_dir: Path) -> dict:
    findings = []
    for p in repo_dir.rglob("*"):
        if not p.is_file():
            continue
        if not _is_text_file(p):
            continue
        rel = p.relative_to(repo_dir).as_posix()
        try:
            txt = p.read_text(errors="ignore")
        except Exception:
            continue
        for pat, label in SECRET_PATTERNS:
            for m in re.finditer(pat, txt):
                snippet = txt[max(0, m.start()-20): m.end()+20].replace("\n"," ")
                findings.append({"file": rel, "label": label, "match": m.group(0), "snippet": snippet})
    return {"secrets": findings}

def _run(cmd: list[str], cwd: Path) -> str:
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return r.stdout + "\n" + r.stderr

def audit_deps(repo_dir: Path) -> dict:
    out = {}
    if (repo_dir / "requirements.txt").exists():
        # JSON output is on stderr for pip-audit; capture both
        raw = _run(["pip-audit", "-r", "requirements.txt", "-f", "json"], repo_dir)
        try:
            parsed = json.loads(raw.strip().splitlines()[-1])
        except Exception:
            parsed = {"raw": raw}
        out["pip_audit"] = parsed
    else:
        out["pip_audit"] = {"info": "No requirements.txt found"}
    return out

def sbom_and_licenses(repo_dir: Path) -> dict:
    # Generate CycloneDX SBOM when Python project exists
    sbom_path = repo_dir / "_repo_doctor" / "sbom.json"
    sbom_path.parent.mkdir(exist_ok=True, parents=True)
    if (repo_dir / "requirements.txt").exists():
        _ = _run(["cyclonedx-py", "-r", "-o", str(sbom_path)], repo_dir)
        exists = sbom_path.exists()
    else:
        exists = False
    licenses = []
    for candidate in ["LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING", "COPYING.txt"]:
        c = repo_dir / candidate
        if c.exists():
            try:
                content = c.read_text(errors="ignore")[:2000]
            except Exception:
                content = ""
            licenses.append({"file": candidate, "preview": content})
    return {"sbom_path": str(sbom_path) if exists else None, "licenses": licenses}

def generate_patch(repo_dir: Path, secrets: dict, deps: dict, licenses: dict) -> str:
    """Return a unified diff string with safe baseline improvements."""
    add_gitignore = False
    if not (repo_dir / ".gitignore").exists():
        add_gitignore = True

    patch_lines = []
    if add_gitignore:
        patch_lines += [
            "diff --git a/.gitignore b/.gitignore",
            "new file mode 100644",
            "index 0000000..1111111",
            "--- /dev/null",
            "+++ b/.gitignore",
            "@@",
            "+*.env",
            "+.env*",
            "+*.pem",
            "+*.p12",
            "+__pycache__/",
            "+.pytest_cache/",
            "+.mypy_cache/",
            "+*.pyc",
            ""
        ]

    # Suggest bumps from pip-audit (when available)
    pa = deps.get("pip_audit", {})
    if isinstance(pa, dict) and "dependencies" in pa:
        for dep in pa.get("dependencies", []):
            name = dep.get("name")
            vulns = dep.get("vulns", [])
            if name and vulns:
                # We can’t safely rewrite requirements in-place here, but we can add notes
                patch_lines += [
                    f"# Suggestion: upgrade {name} - found {len(vulns)} vulnerability entries"
                ]

    if not patch_lines:
        patch_lines = ["# No patch suggestions necessary. Repo looks tidy."]
    return "\n".join(patch_lines)
