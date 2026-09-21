# EC2 deployment

[Back to README](../README.md)

## Status: completed

The application is deployed on AWS EC2 and reached from the operator's own PC, which completes course Phase 4. Both services run on the instance and bind to loopback; the browser connects through SSH port forwarding.

| Item | Value |
| --- | --- |
| OS | Ubuntu 24.04 LTS, x86_64 |
| Python | 3.12.3, dedicated virtual environment |
| Runtime user | `ubuntu` (non-root) |
| Project path | `/home/ubuntu/security-agent` |

## How it runs on the instance

The validated access path was from the operator's PC browser to the Web service at `127.0.0.1:8080` through an SSH tunnel. The Web service calls MCP at `127.0.0.1:8000/mcp`, and MCP accesses SQLite locally on EC2.

Binding both services to loopback prevents direct network access to those listeners. SSH encrypts the remote login and chat traffic, so this tunnel-based setup does not require a TLS certificate or reverse proxy.

## Network configuration

| Port | Purpose | Security group requirement for this design |
| --- | --- | --- |
| 22 | SSH and port forwarding | Inbound from the administrator's IP only |
| 8080 | Web | No inbound rule is required for the SSH-tunnel deployment |
| 8000 | MCP | No inbound rule required - keep MCP on loopback only |

For the SSH-tunnel design, no inbound rule is required for ports 8080 or 8000. This table describes the intended configuration, not an audit of the current AWS security group. Any unused inbound rules should be removed when reviewing the deployment configuration.

## Reaching the application

**From a terminal** (Windows PowerShell, macOS, or Linux):

```bash
ssh -i <path-to-key>.pem -L 8080:127.0.0.1:8080 ubuntu@<instance-public-ip-or-dns>
```

Keep that session open, then browse to `http://localhost:8080` on the PC.

**From Cursor or VS Code Remote-SSH:** open the **Ports** panel and forward port 8080; the editor creates the same tunnel.

## Reproducing the deployment

1. Launch Ubuntu 24.04 with the settings in the table above. Restrict SSH to your IP.
2. Connect over SSH and update the OS:
   ```bash
   sudo apt update && sudo apt upgrade -y
   sudo apt install -y python3-pip python3-venv git
   ```
3. Place the project in `~/security-agent`. Keep `web/index.html` and `data/01_knowledge_base_documents.md` at those paths - the code reads them there.
4. Create a fresh virtual environment. Never copy a Windows environment to Linux.
   ```bash
   cd ~/security-agent
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   pip check
   ```
5. Create `.env` on the instance and restrict it:
   ```bash
   cp .env.example .env
   nano .env          # set ANTHROPIC_API_KEY and a fresh JWT_SECRET
   chmod 600 .env
   ```
6. Build the demo database and the policy index. **`init_db.py` deletes any existing database** - run it only on a fresh install.
   ```bash
   python database/init_db.py
   python rag_build.py
   ```
7. Start both services, each in its own terminal with the environment activated:
   ```bash
   python mcp_server.py
   ```
   ```bash
   python -m uvicorn app:app --host 127.0.0.1 --port 8080 --workers 1
   ```
8. Open the tunnel from the PC and browse to `http://localhost:8080`.

Keep one Web worker: sessions, the five-session cap, and rate-limit counters are held per process.

## Resource usage (measured while running)

MCP and Web were active, and browser login/Q&A was exercised from the operator's PC. No CLI process was running alongside them during this measurement. These figures describe that demo run, not a load-test capacity guarantee.

| Resource | Observed |
| --- | --- |
| Memory | 1.4 GiB used of 1.9 GiB; about 490 MiB available |
| Swap | None configured |
| Disk | 13 GB used of 29 GB (45%) |

The tested demo workload runs successfully, but memory headroom is limited: a CLI process started alongside the Web service loads a second copy of the embedding model. See swap under future hardening.

## Operations

- **Stop the instance when not in use**, as the course requires. Review resource usage and charges in the AWS billing console. Confirm the current connection address before reconnecting.
- **Never run `init_db.py` during routine startup.** It recreates the database and discards tickets created since.
- Service output can contain asset names, policy excerpts, and email addresses. Review it before sharing.

## Future operational hardening

Not required for the course. These would matter for longer-running or shared use:

| Item | Why |
| --- | --- |
| Swap file (2 GB) | No swap and ~490 MiB available leave limited headroom; memory pressure may cause the OS to terminate a process |
| Process supervision (systemd) | Services are started manually and stop when their terminals close or the instance restarts |
| Pinned dependency versions | Most dependencies in `requirements.txt` are unpinned, so a future install may resolve differently |
| Automated backup with a tested restore | Only needed once the database holds data worth keeping |
| TLS reverse proxy | Only if direct browser access without an SSH tunnel is wanted |
| Docker | Optional course stretch goal; would require changing how Web reaches MCP |
