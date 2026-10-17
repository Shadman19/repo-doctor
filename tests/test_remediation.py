import json

from agent import remediation


def _finding() -> dict:
    return {
        "id": "SEC-001",
        "category": "secret",
        "severity": "critical",
        "rule_id": "github-pat",
        "title": "GitHub PAT possibly exposed",
        "file": "settings.py",
        "line": 3,
        "column": 8,
        "evidence": "ghp_...AAAA",
        "fingerprint": "0123456789abcdef",
        "source": "deterministic-secret-scanner",
    }


def test_deterministic_plan_covers_every_finding() -> None:
    findings = [
        _finding(),
        {
            "id": "DEP-001",
            "category": "dependency",
            "severity": "high",
            "rule_id": "PYSEC-EXAMPLE",
            "title": "Vulnerable dependency: demo",
            "package": "demo",
            "installed_version": "1.0",
            "fix_versions": ["1.1"],
        },
    ]
    plan = remediation.deterministic_remediation_plan(findings)
    assert plan["provider"] == "deterministic"
    assert {item["finding_id"] for item in plan["remediations"]} == {
        "SEC-001",
        "DEP-001",
    }
    assert all(item["auto_apply"] is False for item in plan["remediations"])


def test_bedrock_payload_is_redacted_and_minimized() -> None:
    payload = remediation._bedrock_payload([_finding()])
    serialized = json.dumps(payload)
    assert "ghp_...AAAA" not in serialized
    assert "0123456789abcdef" not in serialized
    assert "raw source code" not in serialized
    assert "snippet" not in payload["findings"][0]


class FakeBedrockClient:
    def converse(self, **kwargs):
        assert kwargs["modelId"] == "test-model"
        return {
            "output": {
                "message": {
                    "content": [
                        {
                            "text": json.dumps(
                                {
                                    "remediations": [
                                        {
                                            "finding_id": "SEC-001",
                                            "priority": "critical",
                                            "title": "Rotate credential",
                                            "actions": [
                                                "Revoke the credential at its provider.",
                                                "Replace it with a managed secret reference.",
                                            ],
                                            "verification": [
                                                "Confirm the old credential is rejected.",
                                                "Re-run Repo Doctor.",
                                            ],
                                            "rationale": "The credential may be exposed.",
                                            "auto_apply": False,
                                        }
                                    ]
                                }
                            )
                        }
                    ]
                }
            }
        }


def test_bedrock_plan_is_validated_without_network() -> None:
    plan = remediation.generate_remediation_plan(
        [_finding()],
        use_bedrock=True,
        model_id="test-model",
        region_name="us-east-1",
        client=FakeBedrockClient(),
    )
    assert plan["provider"] == "amazon-bedrock"
    assert plan["remediations"][0]["finding_id"] == "SEC-001"
    assert plan["remediations"][0]["auto_apply"] is False


def test_invalid_bedrock_output_falls_back() -> None:
    class InvalidClient:
        def converse(self, **kwargs):
            return {"output": {"message": {"content": [{"text": "not-json"}]}}}

    plan = remediation.generate_remediation_plan(
        [_finding()],
        use_bedrock=True,
        model_id="test-model",
        client=InvalidClient(),
    )
    assert plan["provider"] == "deterministic-fallback"
    assert plan["bedrock_error"]
    assert plan["remediations"]


def test_invalid_item_for_known_id_gets_deterministic_fallback() -> None:
    candidate = {
        "remediations": [
            {
                "finding_id": "SEC-001",
                "actions": [],
                "verification": ["Re-run scan"],
            }
        ]
    }
    result = remediation._validate_model_plan(candidate, [_finding()])
    assert len(result) == 1
    assert result[0]["finding_id"] == "SEC-001"
    assert result[0]["auto_apply"] is False
    assert result[0]["actions"]
