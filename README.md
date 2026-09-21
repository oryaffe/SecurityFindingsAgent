# Security Findings Agent

Ask security-hardening questions, retrieve findings on **your** assets, and open remediation tickets from a browser chat or CLI.

The system combines **policy RAG**, an **LLM tool-use loop**, and **MCP-backed SQLite access**. Answers are grounded in retrieved security policies and the authenticated user's own operational records.

> Educational project, not a production security platform. It queries stored scan results. It does not run vulnerability scans, install patches, or create tickets in Jira or ServiceNow.

## What it does

- Answers hardening and remediation questions using local RAG over 21 security policy and remediation documents.
- Retrieves the authenticated user's assets, findings, scans, patch history, risk acceptances, and remediation tickets.
- Creates remediation tickets for the authenticated user's own assets.
- Supports findings beyond CVEs, including misconfigurations, exposed services, exposed data, and end-of-life software.

## Example questions

```text
What vulnerabilities were found on server-prod-01?

Has this finding already been patched?

Is there an approved risk acceptance for this exposure?

What does our Linux hardening policy require?

How should I remediate this finding?

Open a remediation ticket for this issue.
```

## How it works

```text
User -> Browser / CLI
         -> Agentic LLM loop
              ├─ RAG -> ChromaDB + all-MiniLM-L6-v2 + security policies
              └─ MCP -> SQLite scoped reads + ticket creation
         -> Grounded response
```

The LLM decides when it needs policy knowledge, operational data, or both.

Authorization is enforced by application and database logic, not by asking the model to stay in scope. The trusted application layer injects the authenticated user identity, so the model cannot choose which user's data to access.

The MCP server trusts the application calling it and must remain private and inaccessible to untrusted clients.

For implementation details, see [Architecture](docs/architecture.md) and [Security](SECURITY.md).

## Quick start

For complete setup, including dependencies, the demo database, model download, and RAG indexing, see the [Installation guide](docs/installation.md).

Start the MCP server:

```bash
python mcp_server.py
```

Start the Web application in another terminal:

```bash
python -m uvicorn app:app --host 127.0.0.1 --port 8080 --workers 1 --log-level info
```

Open:

```text
http://127.0.0.1:8080
```

To use the CLI:

```bash
python main.py
```

Demo credentials and additional example prompts are available in the [User guide](docs/user-guide.md).

## Stack

Python 3.12 · Anthropic API · RAG · MCP · FastAPI · WebSocket · SQLite · ChromaDB · Sentence Transformers · bcrypt · JWT · AWS EC2

The application has been validated locally on Windows and on AWS EC2 with Ubuntu 24.04.

Docker packaging, a separate Web client/server architecture, and LiteLLM fallback are out of scope in this version.

## Documentation

| Document | Purpose |
|---|---|
| [Installation](docs/installation.md) | Environment, dependencies, demo data, and indexing |
| [User guide](docs/user-guide.md) | Sign-in, questions, tickets, and sessions |
| [Architecture](docs/architecture.md) | Components, data flow, and authorization boundaries |
| [EC2 deployment](docs/deployment.md) | AWS deployment and SSH forwarding |
| [Troubleshooting](docs/troubleshooting.md) | Common problems and recovery |
| [Validation](docs/validation.md) | Validation checklist and recorded results |
| [Course project specification](docs/project-requirements.md) | Course requirements, domain adaptation, and implementation mapping |
| [Security](SECURITY.md) | Security boundaries, limitations, and reporting |
| [Contributing](CONTRIBUTING.md) | Contribution workflow |
| [Changelog](CHANGELOG.md) | Project milestones |
| [Environment template](.env.example) | Configuration names and safe defaults |
| [License](LICENSE) | Project usage terms |

## Data handling and limitations

All seeded project data is synthetic.

Selected policy text, operational tool results, and conversation context can be sent to Anthropic to generate responses. Local SQLite and ChromaDB storage does not mean that all AI processing remains local.

Current limitations:

- Up to five authenticated Web sessions per process.
- Up to 20 conversation messages retained per session.
- Sessions are in memory; a restart drops them.
- Demo accounts intentionally share a known sample password. Do not expose the demo instance to untrusted users.
- AI-generated answers may be incomplete or incorrect and should be validated against source records and policies.

Never commit API keys, JWT secrets, `.env`, private keys, live databases, model caches, or sensitive logs.

## Project origin

The system was built from the same core architecture as the course's customer-support agent exercise, while the business domain was redesigned around vulnerability and exposure management.

| Original domain | Security domain |
|---|---|
| Customers | Users |
| Products | Findings |
| Orders | Assets |
| Order items | Scans |
| Shipments | Scan results |
| Returns | Risk acceptances |
| Payments | Patch history |
| Support tickets | Remediation tickets |

The agent loop, RAG, MCP-based database access, memory, Web and CLI interfaces, and ticket-write workflow remain the architectural foundation.

The security adaptation adds domain-specific policies and operational records, asset ownership, stronger authentication, authorization boundaries, and remediation workflows.

See the [Course project specification](docs/project-requirements.md) for the original requirements, domain adaptation, and implementation mapping.

## License

Copyright (c) 2026 Ory Yaffe Mordechai.

All rights reserved. Source is published for review; reuse requires permission.
