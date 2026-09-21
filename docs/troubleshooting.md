# Troubleshooting

[Back to README](../README.md)

Diagnose the failing layer before changing configuration. Capture the exact command, error, environment, and recent change. Sanitize logs before sharing.

| Symptom | Likely checks | Small next step |
| --- | --- | --- |
| SSH times out | Instance health, current public IP, IP allowlist, route/Internet Gateway, local connectivity | Check those values before changing SSH keys |
| SSH rejects the key | Correct Ubuntu username, selected key pair, PEM path, file permissions | Compare with launch configuration; never post the PEM |
| Browser cannot connect | Web process, bind address, port, security group or tunnel | Test local access on the server before changing external rules |
| Login returns 401 | Incorrect credentials, wrong seed database, or empty password | Verify the intended account; do not rebuild an existing database |
| Login returns 429 | Too many failed attempts in the rolling 60-second window | Wait for the failure window to clear, then retry correct credentials |
| Login returns 503 | MCP unavailable or credential-verification transport failed | Check MCP startup and the configured loopback endpoint |
| JWT creation fails | Missing/empty `JWT_SECRET` or related configuration | Verify secret presence without printing its value |
| WebSocket authentication fails | Expired token or changed signing secret | Return to login and obtain a new token |
| Session limit reached | Five authenticated Web sessions already active in the process | Disconnect an unused tab/session |
| Reconnect limit reached | Network interruption or service restart | Restore connectivity and sign in again; prior context may be lost |
| Model cannot load offline | Missing cache or wrong runtime user/`HF_HOME` | Download the model under the runtime user's cache before retrying |
| Chroma collection missing | Index not built or incorrect directory | Confirm source paths and initialize only the intended new index |
| Policies appear outdated | Builder uses `add`, not an update/replacement workflow | Plan a controlled index rebuild with a backup |
| Anthropic call fails | Key, model access, network, API quota, or service error | Inspect sanitized error classification and account access |
| Process disappears or prints `Killed` | Possible memory pressure | Check OS logs and memory before increasing concurrency |
| Database is locked/read-only | Concurrent writers, filesystem ownership, or directory permissions | Inspect permissions and active processes; do not delete the DB |
| A ticket may have been created before disconnect | Write completed but response was lost | List tickets before repeating the creation request |

## Read-only diagnostics

From the project environment:

```bash
python --version
python -m pip check
```

On Linux:

```bash
free -h
df -h
ss -lnt
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/
```

The application has no dedicated documented health endpoint. The GET request above checks whether the login page is served (expected HTTP 200). It does not verify MCP, login, or Anthropic availability.

An MCP request made without its protocol handshake may return a protocol/method error even when the server is running. Use the configured MCP client and logs to diagnose it rather than treating every non-200 response as an outage.

Never resolve connectivity by opening all ports, disabling authorization, or exposing MCP to the Internet.
