# Threat Model

## Assets

- repository source code;
- credentials and sensitive configuration;
- dependency and license metadata;
- AWS credentials used to call Bedrock;
- scan and remediation artifacts.

## Adversaries and failure modes

- malicious zip paths attempting directory traversal;
- Git URLs targeting internal or credentialed endpoints;
- secrets embedded in text or generated artifacts;
- prompt-injection strings in repository content or finding metadata;
- hallucinated vulnerabilities or fixes;
- destructive remediation commands;
- dependency-scanner or SBOM-tool failure;
- users treating a synthetic benchmark score as production evidence.

## Controls

- safe zip extraction and symlink rejection;
- HTTPS Git host allow-list and no embedded credentials;
- file-size, file-type, and directory exclusions;
- raw-match redaction and non-reversible fingerprints;
- deterministic scanner as source of truth;
- Bedrock input field allow-list;
- JSON schema-style output validation and existing-ID checks;
- deterministic fallback for missing/invalid model output;
- no automatic application of model suggestions;
- tests and a versioned synthetic regression benchmark.

## Out of scope

- full static application security testing;
- malware execution or sandboxing;
- complete Git-history scanning;
- binary reverse engineering;
- legal conclusions about license obligations;
- incident response or credential rotation on the user's behalf;
- proof that a generated patch is correct without project-specific tests.
