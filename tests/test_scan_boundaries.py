import json
from pathlib import Path

import pytest

from agent import report, tools


@pytest.mark.parametrize(
    "requirement",
    [
        "./local-package",
        "-e ./local-package",
        "demo @ https://example.invalid/package.tar.gz",
        "git+https://example.invalid/repo.git",
        "-r /etc/passwd",
        "--extra-index-url https://example.invalid/simple",
        "demo>=1.0",
        "demo==1.*",
    ],
)
def test_unsafe_requirements_never_reach_external_tools(
    tmp_path: Path, monkeypatch, requirement: str
) -> None:
    (tmp_path / "requirements.txt").write_text(requirement + "\n")

    def forbidden_run(*args, **kwargs):
        pytest.fail("Untrusted requirement reached an external tool")

    monkeypatch.setattr(tools, "_run", forbidden_run)
    audit = tools.audit_deps(tmp_path)["pip_audit"]
    assert audit["status"] == "skipped"
    assert audit["dependencies"] == []
    sbom = tools.sbom_and_licenses(tmp_path)
    assert sbom["sbom_path"] is None
    assert sbom["sbom_result"]["status"] == "skipped"


def test_pinned_audit_uses_private_input_without_pip_resolution(
    tmp_path: Path, monkeypatch
) -> None:
    (tmp_path / "requirements.txt").write_text("demo==1.2.3  # reviewed pin\n")

    def fake_run(cmd, cwd, timeout=180):
        assert cwd.resolve() != tmp_path.resolve()
        assert "--no-deps" in cmd
        assert "--disable-pip" in cmd
        sanitized = Path(cmd[cmd.index("-r") + 1])
        assert sanitized.read_text() == "demo==1.2.3\n"
        return {
            "returncode": 1,
            "stdout": json.dumps({"dependencies": [
                {"name": "demo", "version": "1.2.3", "vulns": [{"id": "TEST-1"}]}
            ]}),
            "stderr": "",
        }

    monkeypatch.setattr(tools, "_run", fake_run)
    audit = tools.audit_deps(tmp_path)["pip_audit"]
    assert audit["status"] == "complete"
    assert audit["dependencies"][0]["vulns"][0]["id"] == "TEST-1"


def test_symlinked_inputs_are_not_read(tmp_path: Path, monkeypatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    private = tmp_path / "private.txt"
    private.write_text("OUTSIDE_PRIVATE_CONTENT\n")
    (repo / "requirements.txt").symlink_to(private)
    (repo / "LICENSE").symlink_to(private)

    def forbidden_run(*args, **kwargs):
        pytest.fail("Symlinked input reached an external tool")

    monkeypatch.setattr(tools, "_run", forbidden_run)
    assert tools.audit_deps(repo)["pip_audit"]["status"] == "skipped"
    licenses = tools.sbom_and_licenses(repo)
    assert licenses["licenses"] == []
    assert "OUTSIDE_PRIVATE_CONTENT" not in json.dumps(licenses)


def test_repository_symlink_cannot_redirect_report_writes(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "report.sarif"
    sentinel.write_text("keep this file")
    (repo / "_repo_doctor").symlink_to(outside, target_is_directory=True)

    sarif, pdf, _ = report.summarize(repo, {"secrets": []}, {}, {})

    assert sentinel.read_text() == "keep this file"
    assert Path(sarif).is_file()
    assert Path(pdf).is_file()
    assert not Path(sarif).resolve().is_relative_to(repo)
    assert not Path(sarif).resolve().is_relative_to(outside)


def test_repository_cannot_supply_a_stale_sbom(tmp_path: Path) -> None:
    output = tmp_path / "_repo_doctor"
    output.mkdir()
    (output / "sbom.json").write_text('{"not": "a generated SBOM"}')
    result = tools.sbom_and_licenses(tmp_path)
    assert result["sbom_path"] is None


def test_sbom_uses_private_input_and_output(tmp_path: Path, monkeypatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("demo==1.2.3\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sbom.json"
    sentinel.write_text("keep this file")
    (repo / "_repo_doctor").symlink_to(outside, target_is_directory=True)

    def fake_run(cmd, cwd, timeout=180):
        assert not cwd.resolve().is_relative_to(repo)
        assert (cwd / "requirements.txt").read_text() == "demo==1.2.3\n"
        output = Path(cmd[cmd.index("--output-file") + 1])
        output.write_text('{"bomFormat": "CycloneDX"}')
        return {"returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(tools, "_run", fake_run)
    result = tools.sbom_and_licenses(repo)
    assert result["sbom_result"]["status"] == "complete"
    assert Path(result["sbom_path"]).read_text() == '{"bomFormat": "CycloneDX"}'
    assert sentinel.read_text() == "keep this file"


@pytest.mark.parametrize(
    ("returncode", "stdout"),
    [(127, ""), (124, ""), (2, '{"dependencies": []}'), (0, "invalid JSON"), (0, '{}')],
)
def test_audit_failures_are_explicit(tmp_path: Path, monkeypatch, returncode, stdout) -> None:
    (tmp_path / "requirements.txt").write_text("demo==1.2.3\n")
    monkeypatch.setattr(tools, "_run", lambda *args: {
        "returncode": returncode, "stdout": stdout, "stderr": ""
    })
    audit = tools.audit_deps(tmp_path)["pip_audit"]
    assert audit["status"] == "failed"
    _, _, summary = report.summarize(tmp_path, {}, {"pip_audit": audit}, {})
    assert "dependency audit: failed" in summary


def test_only_active_pins_reach_tools(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        '# a comment\nDemo_Package[extra]==1.2.3; python_version >= "3"\n'
        'other==2.0; python_version < "2"\n'
    )
    assert tools._pinned_requirements(tmp_path) == "demo-package==1.2.3\n"


def test_skipped_packages_are_not_counted_as_audited() -> None:
    assert report._count_vulnerabilities({"pip_audit": {"dependencies": [
        {"name": "audited", "vulns": []},
        {"name": "skipped", "skip_reason": "No advisory data"},
    ]}}) == (1, 0)
