# Benchmark Methodology

The bundled benchmark is a deterministic regression test for secret-pattern detection and remediation-plan coverage.

## Dataset

`benchmarks/secret_cases.json` contains 14 synthetic cases:

- 8 positive cases representing the supported credential-pattern families;
- 6 negative cases designed to resemble secrets without matching the intended pattern.

All credential-like strings are synthetic examples. They must not be used as real credentials.

## Metrics

- **Precision:** detected `(file, label)` pairs that were expected.
- **Recall:** expected `(file, label)` pairs that were detected.
- **F1:** harmonic mean of precision and recall.
- **Redaction pass:** verifies that raw values and a `match` field are absent from serialized scanner output.
- **Remediation coverage:** fraction of normalized findings with at least one remediation record.

## Current result

- Precision: 1.000
- Recall: 1.000
- F1: 1.000
- Redaction: pass
- Remediation coverage: 1.000

## Interpretation

This result protects against regression on the bundled cases. It does not estimate production precision or recall, coverage of novel secret formats, live vulnerability-database quality, exploitability, or real-world remediation success.
