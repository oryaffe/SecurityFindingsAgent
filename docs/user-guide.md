# User guide

[Back to README](../README.md)

## Sign in

For local use, start MCP and Web and open `http://127.0.0.1:8080`. Enter your account email and password. Accounts come from the database; the application does not provide self-service registration.

The supplied seed dataset contains 20 demonstration users. Example accounts are `alice@cyber.com` and `bob@cyber.com`, both with the intentionally shared demonstration password `SecurePass1!`. This is public sample data, not a secret or a recommended account-management design. Use it only in a controlled demo with synthetic records.

For EC2, use the access method configured by the operator. Do not submit credentials over an unencrypted Internet HTTP connection.

## Ask questions

Start with these prompts:

- "Which assets can I access?"
- "What is the hardening policy for Linux servers?"
- "What is our policy for patching critical vulnerabilities?"
- "Show the latest scan results for <asset-name>."
- "Show patch history and risk acceptances for <asset-name>."
- "List my remediation tickets."
- "How should I remediate <CVE-ID> on <asset-name> according to the available records and policies?"

Replace `<asset-name>` with an exact asset name returned for your account and `<CVE-ID>` with a finding present in the demo records. Avoid inventing asset identifiers or assuming another user's records are accessible.

For policy questions, the assistant retrieves relevant documents. For asset questions, it uses operational tools and may combine those results with policy guidance. Review the evidence and distinguish recorded facts from proposed actions.

## Create a remediation ticket

Example:

> Create a remediation ticket for <asset-name> titled "Review exposed management service".

This writes to the project database. It does not patch the asset or create a ticket in Jira, ServiceNow, or another external platform. Check the returned ticket information and then ask to list tickets. Do not assume a separate confirmation step is always required by the application. If a connection drops after a write, check existing tickets before repeating the request.

## Show Thinking

The browser's **Show thinking** toggle implements the course's intermediate-step debug view: it displays steps, tool calls, result summaries, and generated decision/execution summaries when enabled. It is an execution trace, not a guarantee of correctness or access to the model's private internal reasoning. Turning the toggle off does not necessarily stop server-side trace logging.

## Sessions and reconnects

Each WebSocket connection has an independent conversation session. The Web service limits authenticated sessions to five per process and keeps at most 20 conversation messages per session.

Use **Disconnect** to end a Web session. Returning to the login view clears the displayed conversation and the stored Web token. Tickets remain in SQLite.

Reconnect attempts are bounded and use exponential backoff. A newly established authenticated connection creates a new server-side session; previous conversation context is not guaranteed to survive. Sign in again when prompted. Session state is not persisted across service restarts.

## CLI

Run `python main.py` from an activated environment. Enter your email at the prompt, then your password at the hidden password prompt. The CLI verifies credentials through MCP without using a Web JWT.

Use `exit`, `quit`, or `q` to leave. Separate CLI processes can operate alongside Web sessions; the five-session Web limit does not count CLI processes.

## Handling failures

Wrong credentials produce a generic authentication failure. Repeated failed Web logins are temporarily rate limited. A service-unavailable message can indicate an MCP or Anthropic problem rather than incorrect credentials. See [Troubleshooting](troubleshooting.md).
