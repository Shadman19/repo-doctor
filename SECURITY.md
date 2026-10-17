# Security Policy

## Reporting a vulnerability

Please do not open a public issue containing a credential, private repository content, or exploit details that would put users at risk. Contact the repository owner privately through the email listed on the GitHub profile and include a minimal reproduction with synthetic data.

## Handling findings

- Treat every detected credential as potentially compromised until verified.
- Revoke or rotate credentials before removing them from code.
- Do not paste raw secrets into issues, model prompts, logs, or reports.
- Review every remediation manually; Repo Doctor does not apply fixes.

## Scope

Repo Doctor is a research/engineering prototype. It is not an enterprise SAST/SCA platform and does not guarantee detection of every vulnerability or secret.
