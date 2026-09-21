# Installation

[Back to README](../README.md)

## Prerequisites

The project is validated on **Python 3.12.3** (Ubuntu 24.04 on EC2) with the dependencies in `requirements.txt`; `pip check` reports no broken requirements. Most dependencies are not pinned to exact versions, so a future install may resolve newer releases.

You need Git, Python with virtual-environment support, an Anthropic API key, and network access for dependency installation and the initial embedding-model download.

## Obtain the source

Clone the repository:

```bash
git clone https://github.com/oryaffe/SecurityFindingsAgent.git
cd SecurityFindingsAgent
```

Do not put a GitHub token into the URL or commit it.

Expected application paths include `app.py`, `main.py`, `mcp_server.py`, `mcp_client.py`, `auth.py`, `security_agent_core.py`, `session_manager.py`, `policy_retriever.py`, `rag_build.py`, `mcp_servers.yaml`, `requirements.txt`, `web/index.html`, `database/init_db.py`, and `data/01_knowledge_base_documents.md`. Use these exact runtime filenames. The assignment supplies design documents under `dataset_design/`, but the current RAG builder expects the policy file under `data/`. Preserve the design documents for reference and place the approved policy content at the path the builder reads.

## Create an isolated environment

Windows PowerShell, from the project root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Linux, with a compatible Python interpreter and its venv support already installed:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

If PowerShell activation is blocked, you can invoke `.\.venv\Scripts\python.exe` directly instead of changing system-wide execution policy. Create a new Linux virtual environment; never copy the Windows `.venv` to EC2.

## Configure the application

Copy `.env.example` to `.env` in the project root and edit it locally. Supply `ANTHROPIC_API_KEY` and a unique `JWT_SECRET`. Generate a JWT secret with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Keep the generated value private. Keep it stable across ordinary service restarts; changing it invalidates existing tokens. Optional settings are explained in [.env.example](../.env.example). Load process-level settings before launching Python, particularly Hugging Face cache/offline settings.

## Initialize a fresh demo database

**Destructive operation:** `database/init_db.py` deletes an existing `database/security.db` and creates a new seeded database. Existing users, records, and newly created tickets will be lost. It is not a migration or a routine startup command.

Only for a fresh demo installation, after checking that no database needs to be preserved:

```bash
python database/init_db.py
```

For an existing database, skip initialization and preserve it. Stop writers before copying a SQLite backup, or use SQLite's supported backup mechanism; do not casually copy a live database without its transactional state.

## Prepare the model and RAG index

For the initial download, ensure `HF_HUB_OFFLINE` and `TRANSFORMERS_OFFLINE` are unset or `0` in the shell. Run the builder under the same OS user/cache configuration that will run the agent:

```bash
python rag_build.py
```

The builder reads `data/01_knowledge_base_documents.md`, embeds document sections with `all-MiniLM-L6-v2`, and adds them to `security_policies` under `chroma_db/`. The supplied knowledge base contains 21 document sections.

The builder uses `collection.add`; rerunning it is not a reliable replacement/update of existing document IDs. For policy updates, plan an explicit backup and rebuild rather than treating this command as an automatic sync.

Runtime retrieval defaults to offline model loading. A copied `chroma_db/` does not include the Hugging Face model cache. Pre-download the model for the runtime user if indexing was performed elsewhere.

## Start and check

Start MCP, then the Web interface, the CLI interface, or both using the commands in [README](../README.md). Both interfaces are required project deliverables, even though users need not run both at once. Use one Web worker so session limits and rate-limit state remain coherent with the current design.

Confirm the login page loads, then follow [Validation](validation.md). Dependencies installing successfully does not prove authentication, authorization, retrieval, or ticket persistence works.
