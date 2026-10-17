# AWS Security Architecture Note

## Goal

Turn deterministic repository-security findings into a concise remediation plan without exposing source code or credentials to a foundation model and without allowing model output to make changes automatically.

## Data flow

1. **Acquire** a public HTTPS Git repository or uploaded zip.
2. **Scan locally** for likely secrets, Python dependency vulnerabilities, SBOM information, and license-policy flags.
3. **Normalize and redact** every finding. A credential is represented only by type, file location, a redacted display value and a short SHA-256 fingerprint, both omitted from the Bedrock request.
4. **Optionally call Amazon Bedrock Runtime** through the Converse API with the normalized JSON payload.
5. **Validate the response** against a fixed schema and the set of known finding IDs.
6. **Merge deterministic fallback guidance** for any finding omitted by the model.
7. **Require human review** before any action.

## Trust boundaries

- Repository contents are untrusted.
- Scanner findings are untrusted data, not prompt instructions.
- Model output is untrusted advice.
- AWS credentials are supplied only through the standard SDK credential chain and are not stored by Repo Doctor.
- The scanner and output validators, not the model, define the accepted data structures.

## Bedrock request

Repo Doctor uses `bedrock-runtime.converse` with:

- a configured model ID or inference-profile ARN;
- a fixed system instruction that treats finding fields as untrusted data;
- temperature 0 for more reproducible formatting;
- optional Bedrock Guardrail ID/version;
- normalized findings only.

The AWS documentation states that Converse requires `bedrock:InvokeModel`. The project therefore recommends a least-privilege role scoped to the approved model or inference profile.

## Prompt-injection resistance

The model never receives repository files or arbitrary code comments. It receives a whitelist of finding fields. The system prompt explicitly says that all values are data. Output is accepted only if it:

- parses as JSON;
- contains a remediation list;
- references an existing finding ID;
- includes concrete actions and objective verification steps;
- does not contain selected destructive commands;
- leaves `auto_apply` false.

These controls reduce risk but do not eliminate model error. AWS also notes that guardrail components have distinct scopes; guardrails do not replace input minimization, least privilege, deterministic validation, or human review.

## Recommended deployment controls

- Run the service in a private workload identity with no long-lived AWS keys.
- Grant only `bedrock:InvokeModel` to the approved model/inference profile.
- Keep network egress restricted to required Git hosts and AWS endpoints.
- Encrypt logs and avoid recording request payloads containing repository metadata.
- Set CloudWatch alarms for unusual invocation volume, errors, and latency.
- Add authentication and rate limiting before exposing the Streamlit app beyond a trusted environment.
- Use AWS Secrets Manager or Parameter Store for deployment secrets.
- Retain SARIF and benchmark artifacts for auditability.

## Bedrock vs. SageMaker framing

Use Bedrock when the need is managed access to supported foundation models through a standardized inference API. Use SageMaker when the team must train, fine-tune, host, or operate a custom model endpoint with deeper control over the model artifact and serving stack. Repo Doctor uses Bedrock because the model is an optional reasoning layer; the core scanners remain local and deterministic.
