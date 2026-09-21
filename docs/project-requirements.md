# Project requirements

[Back to README](../README.md)

This page separates three things: what the course's original starter template required, how it was adapted into the project-specific requirements for the Vulnerability & Exposure Support Agent, and what this implementation added beyond those requirements.

## The course's starter template

The course provides a generic starter assignment: an AI customer-support agent for an **online store**. The project-specific requirements document - *AI-powered Vulnerability & Exposure Support Agent* - was built by adapting that starter template into the vulnerability-management domain, while keeping the core architectural requirements. This page maps the adaptation.

The starter template's required architecture:

- an agentic loop combining an LLM, tools, and conversation memory;
- local RAG over policy documents (Chroma, `all-MiniLM-L6-v2`, whole documents, top five);
- database access exclusively through an MCP server;
- CLI and Web interfaces, with WebSocket updates and a debug view of intermediate steps;
- authentication, and answers scoped to the authenticated user;
- the ability to open a ticket on the user's behalf;
- deployment on AWS EC2, accessible from the student's own PC.

## The domain adaptation

This project keeps the core architectural requirements above and replaces the store domain with **vulnerability and exposure management**. The schema is mapped one-to-one, preserving the original's structure and complexity:

| Original (store) | This project | Role |
| --- | --- | --- |
| customers | users | the anchor - who is asking |
| orders | assets | owned directly by the user |
| order_items | scans | detail under the owned entity |
| shipments | scan_results | status and event tracking |
| returns | risk_acceptances | exception process |
| payments | patch_history | transaction log |
| support_tickets | remediation_tickets | the agent's write target |
| products | findings | shared catalog, owned by no one |

The rest of the system was adapted to match:

- **Knowledge base** - 21 store policies became 21 security policies: hardening by platform, remediation guides, OWASP Top 10, OWASP Top 10 for LLM applications, CIS benchmarks, remote access, logging, and end-of-life systems.
- **Findings** - a finding is not always a CVE. The catalog distinguishes vulnerabilities from misconfigurations, open ports, exposed data, and end-of-life software, because each has a different fix path.
- **Scoping** - every event table carries the asset it belongs to, so each read reaches the owning user in one step, exactly as the store's tables reach the customer through the order.
- **Example scenarios** - 23 support scenarios written for the new domain.

## Additions beyond the requirements

- **Password authentication.** The original identifies users by email alone. Here that would be too weak: the data reveals which assets are exposed and which risks were accepted rather than fixed. Users sign in with email and password; bcrypt verification happens inside the MCP server, which never returns hashes.
- **Signed Web sessions.** A JWT is issued at login and required as the first WebSocket message.
- **Login rate limiting.** Failed attempts are limited per IP/email and per IP within a sliding window.
- **Identity injection.** The user id is removed from every tool schema the model sees and supplied from the authenticated session, so the model cannot choose whose data to read.

## Requirement mapping

| Requirement | Implementation | Status |
| --- | --- | --- |
| Agentic loop with LLM, tools, memory | `security_agent_core.py` | Validated |
| Concurrent users; async calls | AsyncAnthropic, awaited MCP calls, per-connection sessions | Validated locally |
| Haiku 4.5 or comparable model | Default `claude-haiku-4-5-20251001` | Implemented |
| Up to 20 history messages | `ChatSession` keeps the last 20 user/assistant messages | Implemented |
| Database access through MCP | All runtime queries and writes in `mcp_server.py` | Implemented |
| Local Chroma, `all-MiniLM-L6-v2` | `rag_build.py`, `policy_retriever.py` | Validated |
| Whole documents, no chunking | One entry per policy document | Implemented |
| Top five documents, configurable | `TOP_K = 5`; `top_k` parameter | Implemented |
| CLI and Web interfaces | `main.py`, `app.py`, `web/index.html` | Validated |
| WebSocket and intermediate steps | `/ws`, Show thinking | Validated |
| Open a ticket for the user | `open_remediation_ticket` writes to `remediation_tickets` | Validated |
| Authenticate; answer only for that user | Email + password, session identity, owner-scoped tools | Validated locally |
| No other users' or table information | Scoped tools, hidden auth tools, prompt constraints | Implemented; see [Validation](validation.md) |
| Deploy on EC2, reach it from own PC | Ubuntu 24.04 on EC2, accessed via SSH forwarding | Validated |

## Differences from the starter template's details

- **MCP transport** - the assignment's diagram shows SSE; this project uses Streamable HTTP at `/mcp`. The MCP boundary is the same.
- **Server filename** - the diagram names `security_mcp_server.py`; this project uses `mcp_server.py`.
- **Knowledge-base path** - starter files are listed under `dataset_design/`; the builder reads `data/01_knowledge_base_documents.md`.
- **Requirements filename** - the delivery list spells it `Requirement.txt`; this project uses the conventional `requirements.txt`.

## Optional stretch goals

1. Docker container - not implemented.
2. Separate Web client and agent server over WebSocket - not implemented.
3. LiteLLM fallback model - not implemented.

## Submission checklist

- [ ] ZIP with the application code and related files
- [x] Requirements file
- [x] README explaining configuration, initialization, startup, and use
- [ ] Short video of a Q&A session
- [x] Application deployed on EC2 and reached from own PC
- [ ] Repository, ZIP, and recording reviewed for secrets

Submit according to the delivery instructions in the course document. The GitHub repository does not replace the ZIP and video.
