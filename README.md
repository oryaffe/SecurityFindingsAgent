# Security Findings Agent

**AI-powered Vulnerability & Exposure Support Agent**

An AI agent that helps security teams and developers answer security-hardening questions, retrieve asset-specific vulnerability and exposure records, and open remediation tickets. It combines policy RAG, LLM tool use, MCP-backed database access, and conversation memory, through both a CLI and a browser chat interface.

## Origin: adapting a customer-support agent into a cybersecurity agent

This project was adapted from the course's original online-store customer-support exercise into a Vulnerability & Exposure Support Agent, while preserving the core architecture and project requirements.

The course's starter template was built around a familiar support domain: customers, products, orders, order items, shipments, returns, payments, support tickets, and store policies. Its architecture combined an agentic LLM loop, RAG over policy documents, MCP-based access to SQLite, conversation memory, CLI and Web interfaces, WebSocket updates, user-scoped access, and the ability to create a support ticket.

For the final project, that architecture was kept intact and the entire business domain was replaced with vulnerability and exposure management. The goal was not simply to rename entities - the store workflow had to be translated into cybersecurity concepts that preserved the same relationships, authorization boundaries, read/write patterns, and level of complexity.

### Domain mapping

| Original customer-support domain | Cybersecurity adaptation | Purpose |
| --- | --- | --- |
| Customers | Users | Authenticated identity |
| Products | Findings | Shared catalog of vulnerabilities and exposures |
| Orders | Assets | Main user-owned entities |
| Order items | Scans | Security assessment activity tied to an asset |
| Shipments | Scan results | Individual detected findings and their status |
| Returns | Risk acceptances | Formal exception process when remediation is deferred |
| Payments | Patch history | Record of remediation actions already performed |
| Support tickets | Remediation tickets | The agent's write target |

The mapping preserves a property of the original design: user-owned data can always be traced back to the authenticated user through a clear ownership path - here, through the asset a record belongs to.

### From store policies to a security knowledge base

The RAG component was converted the same way. Instead of delivery, returns, and refund procedures, it indexes 21 security policy and remediation documents: OS and server hardening, vulnerability remediation, web-application security, OWASP Top 10, OWASP for LLM applications, CIS-aligned hardening, remote access, logging and monitoring, credential and secret exposure, and end-of-life systems. The retrieval mechanics are unchanged - complete documents embedded with `all-MiniLM-L6-v2`, stored in local ChromaDB, top five retrieved per question.

### From customer records to security operations

Instead of "Where is my order?", the agent answers "What was found on this asset?", "Has this finding been patched?", "Is there an approved risk acceptance?", or "How should this be remediated?" - and can open a remediation ticket the same way the original opens a support ticket.

The finding model goes beyond CVEs: a finding can be a vulnerability, a misconfiguration, an exposed service, exposed data, or end-of-life software, because each needs a different fix.

### Stronger identity and authorization

The original identifies a user by email alone. This system exposes which assets are vulnerable, which exposures were accepted rather than fixed, and what remediation was attempted - data that needs a real authentication boundary. So the adaptation adds email + password authentication, bcrypt verification inside MCP, signed JWT sessions, login rate limiting, and identity injected by the trusted application layer rather than chosen by the model. Authorization is enforced by application and database logic, not by asking the LLM to follow a prompt.

### What stayed the same

**User → CLI/Web → agentic LLM loop → RAG and/or MCP tools → authoritative data → final answer.**

The result is a full domain adaptation of the original exercise - not a cosmetic rebranding - applying the same agent architecture to a substantially different and more security-sensitive problem.

## What it does

- Uses an agentic loop: the LLM selects policy retrieval or operational tools, examines results, and continues until it can answer.
- Answers policy and hardening questions using local RAG over complete policy documents, without chunking.
- Retrieves the authenticated user's assets, findings, scans, patch history, risk acceptances, and remediation tickets.
- Creates remediation tickets for the user's own assets through MCP.
- Provides a browser chat interface and a CLI using the same agent core.
- Maintains bounded conversation context and supports simultaneous users.
- Offers an optional structured execution trace in the browser.

The application queries stored scan results. It does not run vulnerability scans, install patches, or remediate systems. A ticket is a record in the project's SQLite database, not an external ticketing platform.

## Project status

| Area | Status |
| --- | --- |
| Local RAG and CLI | Implemented and validated |
| MCP tools, SQLite, user-scoped access | Implemented and validated |
| Web login, JWT, WebSocket chat, concurrent sessions | Implemented and validated |
| AWS EC2 deployment, access from own PC | Deployed and validated |
| Docker, separate Web client/server, LiteLLM fallback | Optional course stretch goals - not implemented |

Validated locally on Windows and on AWS EC2 (Ubuntu 24.04, Python 3.12.3). See [Validation](docs/validation.md) for recorded results. This is an educational project, not a production security platform.

## Technology

Python, FastAPI/Uvicorn, Anthropic API, MCP, SQLite, ChromaDB, Sentence Transformers (`all-MiniLM-L6-v2`), bcrypt, and JWT.

ChromaDB runs embedded in the application; no separate vector-database server or GPU is required. The language model is accessed through Anthropic; policy retrieval and embeddings run locally.

## Getting started

Follow [Installation](docs/installation.md) first. It covers dependencies, environment settings, model download, demo data, and indexing.

Then start each process in its own terminal, from the project root with the virtual environment activated:

```bash
python mcp_server.py
```

```bash
python -m uvicorn app:app --host 127.0.0.1 --port 8080 --workers 1 --log-level info
```

Open `http://127.0.0.1:8080`. For the CLI, in another terminal:

```bash
python main.py
```

Both services bind to loopback on purpose. On EC2 they stay on loopback, and the browser reaches them through SSH port forwarding - see [EC2 deployment](docs/deployment.md).

Demo credentials and example prompts are in the [User guide](docs/user-guide.md).

## Documentation

| Document | Purpose |
| --- | --- |
| [Installation](docs/installation.md) | Prepare a local environment and initialize demo data |
| [User guide](docs/user-guide.md) | Sign in, ask questions, create tickets, and manage sessions |
| [Architecture](docs/architecture.md) | Components, data flow, and authorization boundaries |
| [EC2 deployment](docs/deployment.md) | How the application runs on AWS and how to reach it |
| [Troubleshooting](docs/troubleshooting.md) | Diagnose common failures |
| [Validation](docs/validation.md) | Test checklist and recorded results |
| [Project requirements](docs/project-requirements.md) | Requirement mapping, domain adaptation, submission checklist |
| [Security](SECURITY.md) | Security limitations and vulnerability reporting |
| [Contributing](CONTRIBUTING.md) | Report bugs and propose changes |
| [Changelog](CHANGELOG.md) | Implementation milestones |
| [Environment template](.env.example) | Configuration names and safe defaults |
| [License](LICENSE) | License terms |

## Course delivery

The course requires a ZIP with the application code and related files, a requirements file, a README explaining how to run the project, and a short video of a Q&A session. This repository supplements that delivery; it does not replace the ZIP and video. See the [submission checklist](docs/project-requirements.md#submission-checklist).

## Data handling

All data is synthetic. Retrieved policy text, tool results, and conversation content are sent to Anthropic to generate answers, so local storage of SQLite and Chroma does not mean all processing stays local.

Never commit `.env`, API keys, JWT secrets, PEM files, live databases, model caches, or sensitive logs.

## Limitations

The Web service allows up to five authenticated sessions per process and keeps at most 20 conversation messages per session. Sessions live in memory and are not restored after a restart. All seeded demo users share one known password - never expose them to untrusted users. AI-generated answers can be incomplete or wrong; verify the underlying records and policies before acting.

See [Security](SECURITY.md) for the trusted MCP boundary.
