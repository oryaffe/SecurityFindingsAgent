# Vulnerability & Exposure Support Agent

Educational cybersecurity agent with an MCP tool server, email + password login, JWT-backed Web UI, and a CLI.

## Demo password

All 20 seeded users share the same demo password:

```
SecurePass1!
```

Examples: `alice@cyber.com`, `bob@cyber.com`.

This identical password is intentional and exists for educational purposes only. Authentication is intentionally simplified for this project (shared demo password, in-memory rate limiting). Do not use this pattern in a production system.

## Login flow

1. The client sends email and password to `POST /auth/login`.
2. The server normalizes the email (trim + lowercase) and applies in-memory rate limits.
3. Credentials are verified only inside the MCP server (`verify_user_credentials` + bcrypt). The web app never sees password hashes.
4. On success the server issues a JWT (`sub`, `email`, `iat`, `exp`). Downstream WebSocket auth is unchanged.
5. The CLI prompts for email, then a hidden password (`getpass`). It does not issue or store JWTs.

Unknown email, wrong password, and empty password all return the same HTTP 401 detail.

## Rate limiting (educational)

Failed logins only, sliding 60-second window, in-memory:

- 5 failures per client IP + normalized email
- 20 failures per client IP
- A successful login clears that request's buckets
- 429 responses are not counted as extra failures
- MCP outages and other 5xx errors do not increment counters

## Run

```text
python database/init_db.py
python mcp_server.py
uvicorn app:app --port 8080
python main.py
```

MCP listens on port 8000. Use a different port for the web app.
