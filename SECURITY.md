# Security policy

## Project status

This is an educational prototype. No production-support commitment or maintained release matrix has been established. Review the current source and deployment configuration before use with anything beyond synthetic demonstration data.

## Reporting a vulnerability

Do not disclose exploitable vulnerabilities, credentials, or sensitive records in a public issue or pull request.

If the repository's **Security** tab offers **Report a vulnerability**, use that private reporting route. Its availability has not been confirmed. If it is unavailable, ask the maintainer for a private contact channel without posting vulnerability details. A dedicated security contact and response-time commitment have not yet been published.

A useful private report includes the affected commit, prerequisites, minimal reproduction with synthetic data, impact, and suggested mitigation. Never include a real password, token, PEM key, or customer database.

## Current controls and boundaries

- Password verification occurs within MCP using bcrypt; password hashes are not returned through MCP.
- Web authentication uses JWT; CLI authentication does not use Web JWTs.
- Authentication tools are excluded from the LLM-visible tool list.
- The trusted agent core supplies the authenticated identity; protected MCP queries/actions enforce scope.
- MCP itself trusts the calling application and must remain local. It is not safe to expose its operational tools directly to untrusted clients.
- Web sessions are isolated and bounded. Login rate limiting and session limits are in memory and per process.

## Known limitations

- All seeded demo accounts intentionally share a known sample password. Do not deploy them as real accounts or expose them to untrusted users.
- IP allowlists do not encrypt HTTP. Use HTTPS or an SSH tunnel for remote login and chat.
- The application does not automatically establish TLS, a reverse proxy, or a secure public deployment.
- The browser stores its Web token in sessionStorage. This does not protect it from malicious script executing in the page's origin.
- Application/agent traces may contain operational data and email addresses. Review log access and retention. Do not assume switching off the UI trace disables server logging.
- Retrieved content can be untrusted, and model output can be inaccurate. Do not rely on prompts as an authorization boundary.
- Selected policy, operational, and conversation content can be sent to Anthropic.
- A successful authentication test does not prove all authorization paths or prompt-injection cases are secure.

## Repository hygiene

Exclude populated `.env` files, keys, live databases, caches, and sensitive logs from Git and container build contexts. Inspect seed data and history before publication. If a real secret was committed, revoke or rotate it and remediate repository history; deleting it from the latest file alone is insufficient.

Review the impact of changes to authentication, user scoping, tool dispatch, logs, and write operations. Validate cross-user read and write denial after such changes.
