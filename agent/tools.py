from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

# These patterns intentionally identify likely credentials. Findings are always
# redacted before leaving the scanner; the raw match is never returned.
SECRET_PATTERNS: list[tuple[str, str, str]] = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key", "aws-access-key"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key", "google-api-key"),
    (r"xox[baprs]-[0-9a-zA-Z-]{10,64}", "Slack token", "slack-token"),
    (r"ghp_[0-9A-Za-z]{36}", "GitHub PAT", "github-pat"),
    (r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----", "Private key block", "private-key"),
    (r"sk-live-[0-9a-zA-Z]{24,}", "Stripe live secret", "stripe-live-secret"),
    (r"sk-test-[0-9a-zA-Z]{24,}", "Stripe test secret", "stripe-test-secret"),
    (r"(?i)\bsecret_key\b\s*=\s*['\"][^'\"\n]{4,}['\"]", "Generic secret assignment", "generic-secret"),
]

_COMPILED_SECRET_PATTERNS = [(re.compile(pat), label, rule_id) for pat, label, rule_id in SECRET_PATTERNS]

TEXT_EXTS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rs", ".rb",
    ".json", ".yml", ".yaml", ".env", ".txt", ".tf", ".md", ".ini",
    ".cfg", ".toml", ".properties", ".xml", ".sh", ".ps1",
}
BIN_EXTS = {
    ".png", ".jpg", ".jpeg", ".pdf", ".gif", ".ico", ".zip", ".tar",
    ".gz", ".rar", ".7z", ".jar", ".whl", ".pyc", ".so", ".dll",
}
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "_repo_doctor"}
MAX_TEXT_FILE_BYTES = 1_000_000
MAX_ZIP_BYTES = 100 * 1024 * 1024
MAX_UNCOMPRESSED_ZIP_BYTES = 200 * 1024 * 1024
MAX_ZIP_ENTRIES = 10_000
MAX_FINDINGS = 2_000
ALLOWED_GIT_HOSTS = {"github.com", "gitlab.com", "bitbucket.org"}


def redact_secret(value: str) -> str:
    """Return a display-safe representation of a possible credential."""
    if "PRIVATE KEY" in value:
        return "[PRIVATE KEY HEADER REDACTED]"
    if len(value) <= 8:
        return "[REDACTED]"
    return f"{value[:4]}...{value[-4:]}"


def secret_fingerprint(value: str) -> str:
    """Stable, non-reversible fingerprint useful for deduplication."""
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _validate_public_git_url(src_url: str) -> None:
    parsed = urlparse(src_url.strip())
    if parsed.scheme != "https":
        raise ValueError("Only https:// public Git URLs are accepted.")
    if not parsed.hostname or parsed.hostname.lower() not in ALLOWED_GIT_HOSTS:
        raise ValueError(
            "Git host is not allow-listed. Supported hosts: " + ", ".join(sorted(ALLOWED_GIT_HOSTS))
        )
    if parsed.username or parsed.password:
        raise ValueError("Credentials must not be embedded in a Git URL.")


def _safe_extract_zip(zf: zipfile.ZipFile, destination: Path) -> None:
    """Extract a zip while rejecting traversal and symlink entries."""
    base = destination.resolve()
    entries = zf.infolist()
    if len(entries) > MAX_ZIP_ENTRIES:
        raise ValueError("Zip has too many entries.")
    if sum(info.file_size for info in entries) > MAX_UNCOMPRESSED_ZIP_BYTES:
        raise ValueError("Zip exceeds the uncompressed-size limit.")
    for info in entries:
        if info.flag_bits & 0x1:
            raise ValueError("Encrypted zip entries are not supported.")
        member = Path(info.filename)
        if member.is_absolute() or ".." in member.parts:
            raise ValueError(f"Unsafe zip member: {info.filename}")

        # Unix symlink type bits. Symlinks are rejected because they can point
        # outside the extraction root after extraction.
        mode = info.external_attr >> 16
        if (mode & 0o170000) == 0o120000:
            raise ValueError(f"Symlink entries are not accepted: {info.filename}")

        target = (destination / member).resolve()
        if target != base and base not in target.parents:
            raise ValueError(f"Zip member escapes extraction root: {info.filename}")

        if info.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue

        target.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info, "r") as src, target.open("wb") as dst:
            shutil.copyfileobj(src, dst)


def fetch_repo_or_zip(src_url: Optional[str], zip_bytes: Optional[bytes]) -> Path:
    work = Path(tempfile.mkdtemp(prefix="repo-doctor-"))
    repo_dir = work / "repo"
    repo_dir.mkdir(parents=True, exist_ok=True)

    if zip_bytes:
        if len(zip_bytes) > MAX_ZIP_BYTES:
            raise ValueError(f"Zip exceeds {MAX_ZIP_BYTES // (1024 * 1024)} MB limit.")
        zpath = work / "repo.zip"
        zpath.write_bytes(zip_bytes)
        with zipfile.ZipFile(zpath, "r") as zf:
            _safe_extract_zip(zf, repo_dir)
    elif src_url:
        _validate_public_git_url(src_url)
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"
        subprocess.run(
            ["git", "clone", "--depth", "1", "--", src_url, str(repo_dir)],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )
    else:
        raise ValueError("Provide a Git URL or upload a zip.")
    return repo_dir


def _is_text_file(path: Path) -> bool:
    suffix = path.suffix.lower()
    if suffix in BIN_EXTS:
        return False
    try:
        if path.stat().st_size > MAX_TEXT_FILE_BYTES:
            return False
    except OSError:
        return False
    if suffix in TEXT_EXTS or not suffix:
        return True
    try:
        path.read_bytes()[:1024].decode("utf-8")
        return True
    except Exception:
        return False


def _should_skip(path: Path, root: Path) -> bool:
    try:
        rel_parts = path.relative_to(root).parts
    except ValueError:
        return True
    return any(part in SKIP_DIRS for part in rel_parts)


def scan_secrets(repo_dir: Path) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for path in repo_dir.rglob("*"):
        if len(findings) >= MAX_FINDINGS:
            break
        if _should_skip(path, repo_dir) or not path.is_file() or path.is_symlink():
            continue
        if not _is_text_file(path):
            continue

        rel = path.relative_to(repo_dir).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for pattern, label, rule_id in _COMPILED_SECRET_PATTERNS:
            for match in pattern.finditer(text):
                raw = match.group(0)
                line_number = text.count("\n", 0, match.start()) + 1
                line_start = text.rfind("\n", 0, match.start()) + 1
                column = match.start() - line_start + 1
                line_end = text.find("\n", match.end())
                if line_end == -1:
                    line_end = len(text)
                # Do not return a source line: it may contain additional secrets
                # that were not recognized by this rule or by any regex.
                safe_line = "[SOURCE LINE REDACTED]"
                findings.append(
                    {
                        "file": rel,
                        "line": line_number,
                        "column": column,
                        "label": label,
                        "rule_id": rule_id,
                        "redacted_match": redact_secret(raw),
                        "fingerprint": secret_fingerprint(raw),
                        "snippet": safe_line[:240],
                    }
                )
                if len(findings) >= MAX_FINDINGS:
                    break
            if len(findings) >= MAX_FINDINGS:
                break

    return {"secrets": findings, "truncated": len(findings) >= MAX_FINDINGS}


def _run(cmd: list[str], cwd: Path, timeout: int = 180) -> dict[str, Any]:
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "PIP_DISABLE_PIP_VERSION_CHECK": "1"},
        )
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "command": cmd,
        }
    except FileNotFoundError as exc:
        return {"returncode": 127, "stdout": "", "stderr": str(exc), "command": cmd}
    except subprocess.TimeoutExpired as exc:
        return {
            "returncode": 124,
            "stdout": exc.stdout or "",
            "stderr": f"Timed out after {timeout}s",
            "command": cmd,
        }


def audit_deps(repo_dir: Path) -> dict[str, Any]:
    requirements = repo_dir / "requirements.txt"
    if not requirements.exists():
        return {"pip_audit": {"info": "No requirements.txt found"}}

    result = _run(
        ["pip-audit", "-r", "requirements.txt", "-f", "json", "--progress-spinner", "off"],
        repo_dir,
    )
    parsed: Any
    try:
        parsed = json.loads(result["stdout"].strip())
        if isinstance(parsed, list):
            parsed = {"dependencies": parsed}
        if not isinstance(parsed, dict):
            parsed = {"raw": parsed}
    except Exception:
        parsed = {
            "error": "pip-audit output could not be parsed",
            "returncode": result["returncode"],
            "stderr": result["stderr"][-2000:],
        }
    return {"pip_audit": parsed}


def _generate_sbom(repo_dir: Path, requirements: Path, sbom_path: Path) -> dict[str, Any]:
    # cyclonedx-bom changed its CLI over time. Prefer the modern command and
    # retain a compatibility fallback for older installations.
    commands = [
        [
            "cyclonedx-py",
            "requirements",
            str(requirements.name),
            "--output-format",
            "JSON",
            "--output-file",
            str(sbom_path),
        ],
        [
            "cyclonedx-py",
            "-r",
            "-i",
            str(requirements.name),
            "--format",
            "json",
            "-o",
            str(sbom_path),
        ],
    ]
    last: dict[str, Any] = {}
    for cmd in commands:
        last = _run(cmd, repo_dir)
        if last["returncode"] == 0 and sbom_path.exists():
            return {"ok": True, "command": cmd}
    return {
        "ok": False,
        "returncode": last.get("returncode"),
        "stderr": str(last.get("stderr", ""))[-2000:],
    }


def sbom_and_licenses(repo_dir: Path) -> dict[str, Any]:
    sbom_path = repo_dir / "_repo_doctor" / "sbom.json"
    sbom_path.parent.mkdir(exist_ok=True, parents=True)
    requirements = repo_dir / "requirements.txt"
    if requirements.exists():
        sbom_result = _generate_sbom(repo_dir, requirements, sbom_path)
    else:
        sbom_result = {"ok": False, "info": "No requirements.txt found"}

    licenses: list[dict[str, str]] = []
    for candidate in ["LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING", "COPYING.txt"]:
        path = repo_dir / candidate
        if path.exists() and path.is_file():
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")[:4_000]
            except Exception:
                content = ""
            licenses.append({"file": candidate, "preview": content})

    return {
        "sbom_path": str(sbom_path) if sbom_path.exists() else None,
        "sbom_result": sbom_result,
        "licenses": licenses,
    }


def generate_patch(repo_dir: Path, secrets: dict, deps: dict, licenses: dict) -> str:
    """Return conservative unified-diff suggestions.

    Repo Doctor never auto-applies LLM output. Secret rotation and dependency
    upgrades require human review, so the patch is limited to safe baseline
    hygiene plus comments for review.
    """
    patch_lines: list[str] = []
    if not (repo_dir / ".gitignore").exists():
        patch_lines += [
            "diff --git a/.gitignore b/.gitignore",
            "new file mode 100644",
            "index 0000000..1111111",
            "--- /dev/null",
            "+++ b/.gitignore",
            "@@ -0,0 +1,10 @@",
            "+.env",
            "+.env.*",
            "+*.pem",
            "+*.p12",
            "+*.key",
            "+__pycache__/",
            "+.pytest_cache/",
            "+.mypy_cache/",
            "+*.pyc",
            "+_repo_doctor/",
            "",
        ]

    pip_audit = deps.get("pip_audit", {})
    if isinstance(pip_audit, dict):
        for dep in pip_audit.get("dependencies", []):
            if not isinstance(dep, dict):
                continue
            name = dep.get("name")
            vulns = dep.get("vulns", []) or []
            if name and vulns:
                fix_versions = sorted(
                    {
                        version
                        for vuln in vulns
                        if isinstance(vuln, dict)
                        for version in (vuln.get("fix_versions") or [])
                    }
                )
                suffix = f"; candidate fixes: {', '.join(fix_versions)}" if fix_versions else ""
                patch_lines.append(
                    f"# REVIEW: upgrade {name}; {len(vulns)} vulnerability record(s){suffix}"
                )

    if secrets.get("secrets"):
        patch_lines.append(
            "# REVIEW: rotate/revoke every detected credential and remove it from Git history; raw secret values are intentionally omitted."
        )

    if not patch_lines:
        patch_lines = ["# No conservative patch suggestions were generated."]
    return "\n".join(patch_lines)
