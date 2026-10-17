from agent.evaluation import run_benchmark


def test_synthetic_benchmark_regression() -> None:
    result = run_benchmark()
    assert result["precision"] >= 0.99
    assert result["recall"] >= 0.99
    assert result["f1"] >= 0.99
    assert result["redaction_pass"] is True
    assert result["remediation_coverage"] == 1.0
