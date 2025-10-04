from agent import tools
from pathlib import Path

def test_secret_scanner_tmp(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    f = repo / "keys.txt"
    f.write_text("api: ghp_1234567890abcdefghijklmnopqrstuv")
    out = tools.scan_secrets(repo)
    assert out["secrets"], "should detect a dummy token"
