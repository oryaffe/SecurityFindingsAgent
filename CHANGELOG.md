# Changelog

Significant project milestones. No version number or release date is assigned until a release is created.

## Unreleased

### Application

- Local Chroma policy retrieval with `all-MiniLM-L6-v2` embeddings, whole documents, top five.
- Shared agent core with Anthropic integration and MCP tool use.
- SQLite schema for assets, findings, scans, scan results, patch history, risk acceptances, and remediation tickets, mapped one-to-one from the original store schema.
- User-scoped operational access and ticket creation; user id injected from the session, never chosen by the model.
- Email + password authentication with bcrypt verification inside MCP.
- FastAPI browser UI, JWT sessions, and WebSocket chat.
- CLI interface sharing the same agent core.
- Isolated sessions, bounded history, login rate limiting, and bounded reconnect.
- Optional structured execution trace in the browser.

### Deployment

- Deployed to AWS EC2 and validated from the operator's PC.
- Web and MCP services bound to loopback, with browser access validated through SSH port forwarding.

### Documentation

- Installation, user, architecture, deployment, troubleshooting, and validation guides.
- Course requirement mapping, including the adaptation from the original store assignment.
- Security and contribution policies, and an environment template.

### Not implemented (optional course stretch goals)

- Docker packaging.
- Separate Web client and agent server.
- LiteLLM fallback model.
