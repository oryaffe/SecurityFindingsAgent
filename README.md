# Security Findings Agent

**Agentic AI for vulnerability and exposure workflows.**

A Python application that combines **local policy RAG**, **MCP tool orchestration**, and **authenticated operational data** to investigate security findings and follow their remediation state. Available through a browser chat and CLI.

The security workflow brings together findings, scan records, patch history, risk acceptances, and remediation tickets. It demonstrates both cybersecurity reasoning and the implementation of an AI agent with tools, memory, authentication, and cloud deployment.

[Architecture](docs/architecture.md) · [Installation](docs/installation.md) · [Security](SECURITY.md) · [Validation](docs/validation.md)

## Demo

Ask about an asset, inspect its recorded findings, and follow up on remediation in the same conversation.

![Browser conversation showing asset findings and a remediation follow-up](docs/images/security-agent-demo.png)

## What it does

- **Investigates recorded exposures:** retrieves the signed-in user's assets, scan results, findings, and severity, including vulnerabilities, misconfigurations, exposed services, exposed data, and end-of-life software.
- **Brings remediation evidence together:** retrieves patch history, risk acceptances, and existing tickets to help assess the recorded state of a finding.
- **Retrieves policy guidance:** searches 21 local sample security-policy and remediation documents using ChromaDB and Sentence Transformers.
- **Creates local remediation tickets:** writes a ticket for an asset owned by the authenticated user through MCP.
- **Checks selected response claims:** applies deterministic validation rules to policy and operational statements, with a correction step when violations are detected.

A central security distinction in the project is that an `Applied` patch-history entry does not, by itself, demonstrate that remediation has been verified.

### Remediation workflow

The conversation can move from retrieving findings to creating a ticket and listing recorded tickets.

![Conversation moving from findings to local remediation-ticket creation](docs/images/security-agent-ticket-workflow.png)

Ticket creation writes to the project's SQLite database. The application queries stored scan results; it does not run scanners, install patches, or create Jira or ServiceNow tickets.

## What I designed

- **Security domain adaptation:** remodeled a course customer-support agent around assets, findings, scans, patch history, risk acceptances, and remediation tickets.
- **Remediation workflows:** adapted the prompts, sample policies, and scenarios to distinguish finding status, recorded treatment actions, accepted risks, and verification evidence.
- **Authentication and access boundaries:** added password authentication, signed Web sessions, and session-derived identity injection for ownership-scoped tool access.
- **Response checks:** developed and iterated deterministic rules for selected policy, ticket, patch-history, risk-acceptance, and remediation claims.

The agent loop, RAG, MCP, and Web/CLI architecture build on the course foundation. The [requirements mapping](docs/project-requirements.md) explains the adaptation and additions.

## How it works

![Conceptual overview of the user interface, agent core, model, policy retrieval, and MCP data access](docs/images/security-agent-question-to-answer.png)

1. **Authenticate:** users sign in through the browser or CLI. The application maintains the authenticated identity outside the model's tool arguments.
2. **Select tools:** the shared agent core sends the conversation and available tools to Anthropic. The model can request policy retrieval or operational data.
3. **Retrieve evidence:** `search_policies` runs locally against ChromaDB. Operational tools run through MCP and perform ownership-scoped SQLite reads or ticket writes.
4. **Continue the conversation:** the core returns tool results to the model, which can request additional tools. Conversation history supports follow-up questions.
5. **Check the response:** a deterministic validation layer checks selected claims and can request a corrected answer. It is a rule-based quality check, not a guarantee of factual accuracy.

RAG runs locally in `policy_retriever.py`; it is separate from the MCP data-access path. See [Architecture](docs/architecture.md) for the runtime flow and trust boundaries.

### Execution trace

The browser's **Show Thinking** option displays a structured execution trace of tool calls, retrieval, and validation events. It is an application trace, not raw model chain-of-thought.

This example brings together a finding, an existing ticket, patch-history records, and a retrieved policy, while distinguishing an applied patch from verified remediation.

![Execution trace and answer distinguishing patch history from verification evidence](docs/images/security-agent-rag-mcp-trace.png)

### Access control

The application injects the authenticated `user_id`, and MCP tools check asset ownership before protected reads or ticket creation. Authentication tools are excluded from the model's available tools.

The following conversation illustrates a refusal to switch identity based on a user message. The ownership checks themselves are implemented in code; this screenshot is a conversation example rather than a standalone test of those checks.

![Conversation refusing a request to impersonate another user](docs/images/security-agent-access-control.png)

The MCP server trusts the calling application and must remain private. See [Security](SECURITY.md) for authentication, authorization, and deployment boundaries.

## Try these questions

```text
What findings are recorded for server-prod-02?

Show the patch history and existing remediation tickets for this asset.

Is there an approved risk acceptance for this exposure?

What does the sample Linux hardening policy require?

Open a remediation ticket for this issue.
```

## Quick start

First follow the [Installation guide](docs/installation.md) to install dependencies, configure the [environment](.env.example), initialize a fresh demo database, and build the RAG index.

From the project root, with the environment activated, start MCP:

```bash
python mcp_server.py
```

Start the Web application in another terminal using the same environment:

```bash
python -m uvicorn app:app --host 127.0.0.1 --port 8080 --workers 1 --log-level info
```

Open `http://127.0.0.1:8080`. To use the CLI with MCP running:

```bash
python main.py
```

Demo sign-in details and usage instructions are in the [User guide](docs/user-guide.md).

## Stack and deployment

**Python 3.12 · Anthropic API · RAG · MCP · FastAPI · WebSocket · SQLite · ChromaDB · Sentence Transformers · bcrypt · JWT · AWS EC2**

The project has been run locally on Windows and on Ubuntu 24.04 in AWS EC2, with access through SSH forwarding. Deployment instructions are in the [EC2 guide](docs/deployment.md).

## Documentation

| Document | Purpose |
|---|---|
| [Installation](docs/installation.md) | Dependencies, configuration, demo data, and indexing |
| [User guide](docs/user-guide.md) | Sign-in, conversations, tickets, and sessions |
| [Architecture](docs/architecture.md) | Components, tool orchestration, data flow, and trust boundaries |
| [EC2 deployment](docs/deployment.md) | Linux deployment and SSH forwarding |
| [Security](SECURITY.md) | Authentication, authorization, limitations, and reporting |
| [Validation](docs/validation.md) | Validation checklist and recorded results |
| [Troubleshooting](docs/troubleshooting.md) | Common problems and recovery |
| [Contributing](CONTRIBUTING.md) | Contribution workflow |
| [Changelog](CHANGELOG.md) | Project milestones |

## Data scope and limitations

This is an educational portfolio project using synthetic operational records and sample policies. The demo content is designed to exercise the application's workflows and should not be treated as authoritative vulnerability intelligence or production remediation guidance.

Selected policy text, operational tool results, and conversation context can be sent to Anthropic. Local SQLite and ChromaDB storage does not make the entire inference workflow local.

- AI-generated answers and rule-based validation have coverage limits. Check conclusions against their source records and authoritative guidance.
- The Web application supports up to five authenticated sessions per process and retains up to 20 conversation messages per session.
- Sessions are stored in memory and are lost on restart.
- Demo accounts share a known sample password. Keep the demo instance restricted to trusted users.
- Docker packaging is not included in this version.

## Project origin

Developed as the final project for an AI Engineering program, adapting a customer-support agent architecture to vulnerability and exposure management. The course foundation includes agent orchestration, RAG, MCP, conversation memory, Web/CLI interfaces, ticket creation, and EC2 deployment.

See the [original specification](docs/project-specification.pdf) and [requirements mapping](docs/project-requirements.md) for the source requirements and security adaptation.

## Author

**Ory Yaffe Mordechai**  
Cybersecurity · Security Operations · Technical Investigations · AI Engineering  
[LinkedIn](https://www.linkedin.com/in/oryaffe) · [GitHub profile](https://github.com/oryaffe)

## License

Copyright (c) 2026 Ory Yaffe Mordechai.

All rights reserved. Source is published for review; reuse requires permission. See [License](LICENSE).
