# Part 3 — SQL Schema Definition (Conceptual)

Conceptual relational schema for the security support agent. No SQL code—only table names, field names, types (conceptual), and relationships. This schema replaces the online-store database (`database/store.db`) with `database/security.db`.

---

## Core Tables

### users

| Field | Conceptual type | Description |
|-------|-----------------|-------------|
| id | unique identifier | Primary key. |
| user_id | string | Unique employee identifier (e.g., "U-0001"); used in tickets and audit. |
| email | string | Unique; used for (mock) authentication to the agent. |
| role | string | Job function, e.g. security_analyst, systems_engineer, soc_analyst, ciso. **Descriptive only** — it is not an access level. |
| department | string | One of: IT Systems, IT Security, Cyber Team. |
| last_login | datetime (optional) | Last authentication to the support agent. |
| password_hash | string | bcrypt hash; verified only inside the MCP server via verify_user_credentials; never returned by any tool |

---

### assets

| Field | Conceptual type | Description |
|-------|-----------------|-------------|
| id | unique identifier | Primary key. |
| asset_tag | string | Unique inventory tag (e.g., "A-0001"). |
| name | string | Hostname / device name (e.g., "server-prod-01"). |
| type | string | e.g., linux_server, windows_server, web_app, database, laptop, network_device. |
| ip_address | string | Primary IP. |
| mac_address | string (optional) | Hardware address. |
| os | string | OS and version (e.g., "Ubuntu 22.04", "CentOS 7 (EOL)"). |
| location | string | Site / DC / cloud region (e.g., "TLV-DC1", "aws-eu-west-1", "Office-3F"). |
| owner_user_id | foreign key → users.id | The engineer responsible for this asset. **Authorization anchor**: every read/write is scoped to assets whose owner is the requesting user. |

---

### findings

The catalog of things a scan can detect. **Not every finding is a vulnerability**: scans also surface security misconfigurations, open ports, exposed sensitive data, and end-of-life software. A CVE-backed vulnerability is therefore one *type* of finding, not the whole table.

| Field | Conceptual type | Description |
|-------|-----------------|-------------|
| id | unique identifier | Primary key. |
| finding_type | string | One of: vulnerability, misconfiguration, open_port, exposed_data, eol_software. |
| cve_id | string (optional, unique) | e.g., "CVE-2025-1974". Populated only when finding_type = vulnerability; null otherwise. |
| title | string | Short name of the finding. |
| severity | string | One of: Critical, High, Medium, Low. Drives SLA (Doc 1). |
| description | string | What the finding is and its impact. |
| remediation_guide_ref | string | Link into the RAG knowledge base (e.g., "Document 8: Remediation Guide — OpenSSH Vulnerabilities"). |

**Note:** `remediation_guide_ref` is critical for policy alignment: the agent retrieves the referenced guide to answer "how do I fix this?".

**Note:** `finding_type` lets the agent reason correctly about the fix path — a `vulnerability` is remediated by patching, a `misconfiguration` by changing a setting, an `eol_software` finding by migration (Doc 13). Asking "which CVEs affect me?" filters on `finding_type = 'vulnerability'`; asking "what did the scan find?" does not filter at all.

---

## Junction / Detail Tables

### scans

One row per scan execution against an asset.

| Field | Conceptual type | Description |
|-------|-----------------|-------------|
| id | unique identifier | Primary key. |
| scan_time | datetime | When the scan ran. |
| scanner_tool | string | e.g., Nessus, Qualys, SAST, DAST, Pentest. |
| asset_id | foreign key → assets.id | The scanned asset. |
| status | string | e.g., Completed, In Progress, Failed. |

---

### scan_results

Links scans to the findings detected in them — one row per *detected instance*. This is the junction: `findings` is the catalog (what a thing is), `scan_results` is the occurrence (this scan, on this asset, found this thing).

| Field | Conceptual type | Description |
|-------|-----------------|-------------|
| id | unique identifier | Primary key. |
| scan_id | foreign key → scans.id | The scan that detected it. |
| finding_id | foreign key → findings.id | What was detected. |
| asset_id | foreign key → assets.id | **Authorization anchor** (direct, one hop — matches every other event table in this schema). Set together with the owning `scans.asset_id` at insert time; never chosen independently, so it cannot contradict it. |
| status | string | Unremediated / Remediated. Closure only after verifying rescan (Doc 20). |
| comments | string (optional) | Tool-specific evidence (port, file/line, request, PT reference). |

---

### risk_acceptances

Parallel to `returns` in the original: a documented exception instead of remediating. Recorded at the **asset** level, exactly as a return in the original attaches to an order rather than to an individual line item.

| Field | Conceptual type | Description |
|-------|-----------------|-------------|
| id | unique identifier | Primary key. |
| asset_id | foreign key → assets.id | **Authorization anchor** (direct, one hop). |
| requested_at | datetime | When the exception was requested. |
| justification | string | Why remediation is not happening now, and which exposure it covers. |
| status | string | Pending / Approved / Rejected. |
| review_date | date (optional) | Mandatory re-review date (90 days per Doc 1); null unless approved. |

---

### patch_history

Parallel to `payments` in the original: one transaction per remediation action attempted on an asset, including failures, independent of whether a ticket exists.

| Field | Conceptual type | Description |
|-------|-----------------|-------------|
| id | unique identifier | Primary key. |
| asset_id | foreign key → assets.id | **Authorization anchor** (direct, one hop). |
| action_taken | string | What was done (e.g., "Applied KB5040430 cumulative update"). |
| status | string | Applied / Failed / Rolled_back. |
| performed_at | datetime | When the action was carried out. |

---

### remediation_tickets

Tracks remediation work; the agent's write target. Mirrors `support_tickets` in the original field for field: attributed to a user, related to one of their assets.

| Field | Conceptual type | Description |
|-------|-----------------|-------------|
| id | unique identifier | Primary key; displayed as ticket number. |
| reporting_user_id | foreign key → users.id | The user the ticket is attributed to. The **agent** opens the ticket on their behalf (Doc 21); resolved from the email the user gives in conversation. |
| asset_id | foreign key → assets.id | The asset the ticket concerns — the direct parallel of `support_tickets.order_id`. |
| title | string | Short subject (= `subject` in the original). |
| status | string | e.g., Open, In Progress, Done. New tickets start Open. |
| created_at | datetime | When the ticket was opened. |
| updated_at | datetime (optional) | Last update; null until the ticket changes. |

---

## Access Model (Guardrails — requirements §3.10)

Mirroring the original project exactly ("the agent authenticates the user and answers questions only for the relevant user"):

- **Authentication:** email + password verified via the verify_user_credentials MCP tool.
- **Reads:** every event table carries a **direct, one-hop** authorization column back to `assets.owner_user_id` — uniformly, with no table more than one JOIN from its anchor:
  - `assets` → `owner_user_id` (direct)
  - `scans` → `asset_id` (one hop)
  - `scan_results` → `asset_id` (one hop)
  - `risk_acceptances` → `asset_id` (one hop)
  - `patch_history` → `asset_id` (one hop)
  - `remediation_tickets` → `reporting_user_id` (direct) and `asset_id` (one hop)

  **No data leakage between users** — just as a store customer sees only their own orders. There are no privileged tiers: `role` is a job function, not an access level, exactly as customers had no tiers.
- **`findings` is the one exception, by design** — it is a shared catalog (parallel to `products` in the original), not a user-owned event. A single finding (e.g. one CVE) can be detected on assets belonging to several different owners, so it cannot carry a single owner column without being duplicated per owner — which would turn it into another `scan_results`. It may be read directly as a catalog (what a CVE is, its severity, its remediation guide), but such a read must never reveal which assets are affected — asset linkage is only ever reached through the already-scoped `scan_results`.
- **Writes:** the **agent** decides when a remediation ticket is required and creates it on the user's behalf (Document 21) — only for assets the user owns. It cannot attribute a ticket to a user who does not exist.
- The agent must also never expose **table/schema information** or other users' details in its answers.
- *Note:* in a real internal deployment, SOC analysts would receive org-wide read. This project deliberately mirrors the original's strict per-user scoping to keep the two systems identical.

---

## Entity Relationship Summary

- **users** 1 — N **assets** (via owner_user_id) — remediation responsibility **and** the authorization anchor
- **assets** 1 — N **scans**
- **assets** 1 — N **scan_results**, **risk_acceptances**, **patch_history**, **remediation_tickets** — each carries `asset_id` directly, so every event table is exactly one hop from its owner
- **scans** N — N **findings** via **scan_results** (a scan detects many findings; a finding appears in many scans)
- **assets** N — N **findings** — realized through `scan_results`, never a direct column on `findings` itself (see Access Model)
- **assets** 1 — N **risk_acceptances** (an exception process, parallel to `returns` → `orders`)
- **assets** 1 — N **patch_history** (a remediation transaction log, parallel to `payments` → `orders`)
- **users** 1 — N **remediation_tickets** (as reporter via reporting_user_id), parallel to `customers` 1 — N `support_tickets`

**Note on subtyping:** vulnerabilities are not a separate table. A vulnerability is a **findings** row with `finding_type = 'vulnerability'` and a populated `cve_id`. This keeps "every vulnerability is a finding, but not every finding is a vulnerability" true in the data model without SQL inheritance.

**Eight tables, mirroring the original's seven + catalog exactly:**

| Original | This schema | Role |
|---|---|---|
| customers | users | anchor |
| orders | assets | direct-owned entity |
| order_items | scans | detail under the entity |
| shipments | scan_results | status/event tracking |
| returns | risk_acceptances | exception process |
| payments | patch_history | transaction log |
| support_tickets | remediation_tickets | agent-initiated ticket |
| *products* (catalog, no owner column) | *findings* (catalog, no owner column) | shared reference data |

---

## Indexing Hints (for later implementation)

- `assets.owner_user_id`, `assets.asset_tag`, `assets.name`
- `scans.asset_id`, `scans.scanner_tool`
- `scan_results.scan_id`, `scan_results.finding_id`, `scan_results.asset_id`, `scan_results.status`
- `risk_acceptances.asset_id`, `risk_acceptances.status`
- `patch_history.asset_id`
- `findings.cve_id`, `findings.severity`, `findings.finding_type`
- `remediation_tickets.asset_id`, `remediation_tickets.reporting_user_id`

This schema supports answering: finding lookups per asset (assets + scan_results + findings, one hop), CVE-specific questions (filter `finding_type = 'vulnerability'`), non-CVE exposure questions such as open ports, misconfigurations, and exposed secrets (the other finding_type values), remediation guidance (findings.remediation_guide_ref → RAG), SLA/severity prioritization (severity + scan_time), risk-acceptance tracking (risk_acceptances.status + review_date), remediation transaction history (patch_history), uniform per-user authorization (every event table scoped one hop from assets.owner_user_id), and agent-initiated ticket creation (remediation_tickets.asset_id).
