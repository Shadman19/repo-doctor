from pathlib import Path
from zipfile import ZipFile

import pytest

from agent import tools


def test_secret_scanner_redacts_and_locates(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    raw = "ghp_" + "A" * 36
    (repo / "keys.txt").write_text(f"api: {raw}\n", encoding="utf-8")

    out = tools.scan_secrets(repo)
    assert len(out["secrets"]) == 1
    finding = out["secrets"][0]
    assert finding["label"] == "GitHub PAT"
    assert finding["line"] == 1
    assert finding["column"] == 6
    assert raw not in str(out)
    assert "match" not in finding
    assert finding["redacted_match"].startswith("ghp_")
    assert finding["fingerprint"]


def test_secret_scanner_avoids_env_reference_false_positive(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "settings.py").write_text(
        "secret_key = os.environ['SECRET_KEY']\n", encoding="utf-8"
    )
    assert tools.scan_secrets(repo)["secrets"] == []


def test_zip_slip_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "unsafe.zip"
    with ZipFile(archive, "w") as zf:
        zf.writestr("../escape.txt", "nope")

    with pytest.raises(ValueError, match="Unsafe zip member"):
        tools.fetch_repo_or_zip(None, archive.read_bytes())


def test_public_git_url_validation() -> None:
    with pytest.raises(ValueError):
        tools.fetch_repo_or_zip("file:///etc/passwd", None)
    with pytest.raises(ValueError):
        tools.fetch_repo_or_zip("https://127.0.0.1/repo.git", None)


def test_scanner_does_not_return_unrecognized_secret_on_same_line(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    unknown_secret = "PRIVATE_NOT_IN_REGEX_123456789"
    (repo / "settings.py").write_text(
        'secret_key="synthetic-credential"; unknown_token="' + unknown_secret + '"'
    )
    output = tools.scan_secrets(repo)
    assert output["secrets"]
    assert unknown_secret not in str(output)
    assert "synthetic-credential" not in str(output)


def test_zip_bomb_uncompressed_size_limit(tmp_path: Path, monkeypatch) -> None:
    import io
    import zipfile
    monkeypatch.setattr(tools, "MAX_UNCOMPRESSED_ZIP_BYTES", 16)
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("large.txt", "A" * 100)
    with pytest.raises(ValueError, match="uncompressed-size"):
        tools.fetch_repo_or_zip(None, data.getvalue())
