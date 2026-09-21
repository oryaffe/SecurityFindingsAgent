# Part 4 — Generated Dataset Samples

**Reference date for "today":** 2026-07-12 (used for SLA-day calculations).

Generated to align with policies:
- **SLA (Doc 1):** Critical findings first seen ~8+ days ago (SLA breached) vs ~1-3 days ago (within SLA).
- **Verification (Doc 20):** mix of Unremediated and Remediated results — Remediated only where a verifying rescan is documented.
- **Guardrails (§3.10):** every query is scoped to the requesting user's own assets (`owner_user_id`) — e.g., bob (webapp-store/portal) asking about server-prod-01 is denied. No data leakage between users.
- **EOL (Doc 13):** one CentOS 7 (EOL) host with legacy findings that cannot be "patched".
- **Guide linkage:** every finding's `remediation_guide_ref` points to a knowledge-base document.
- **Finding types:** the dataset deliberately mixes CVE-backed vulnerabilities with misconfigurations, open ports, exposed data, and EOL software — so the agent must distinguish "which CVEs affect me?" from "what did the scan find?".

---

## 1. Users (20 rows)

| id | user_id | email | role | department | last_login |
|----|---------|-------|------|------------|------------|
| 1 | U-0001 | alice@cyber.com | security_analyst | IT Security | 2026-07-11 08:45:00 |
| 2 | U-0002 | bob@cyber.com | systems_engineer | IT Systems | 2026-07-10 17:20:00 |
| 3 | U-0003 | carol@cyber.com | database_administrator | IT Systems | 2026-07-11 09:10:00 |
| 4 | U-0004 | dave@cyber.com | systems_administrator | IT Systems | 2026-07-12 07:30:00 |
| 5 | U-0005 | erez.levi@cyber.com | soc_analyst | Cyber Team | 2026-07-09 14:00:00 |
| 6 | U-0006 | fatima.h@cyber.com | network_engineer | IT Systems | 2026-07-11 11:05:00 |
| 7 | U-0007 | gil.shapira@cyber.com | ciso | IT Security | 2026-07-08 10:15:00 |
| 8 | U-0008 | hana.katz@cyber.com | security_analyst | IT Security | 2026-07-12 06:50:00 |
| 9 | U-0009 | itai.mor@cyber.com | devops_engineer | IT Systems | 2026-07-10 13:40:00 |
| 10 | U-0010 | julia.k@cyber.com | threat_hunter | Cyber Team | 2026-07-07 09:00:00 |
| 11 | U-0011 | kobi.d@cyber.com | systems_engineer | IT Systems | 2026-07-11 16:25:00 |
| 12 | U-0012 | lior.ben@cyber.com | devops_engineer | IT Systems | 2026-07-11 12:00:00 |
| 13 | U-0013 | maya.r@cyber.com | database_administrator | IT Systems | 2026-07-09 15:30:00 |
| 14 | U-0014 | nadav.o@cyber.com | incident_responder | Cyber Team | 2026-07-10 08:20:00 |
| 15 | U-0015 | orly.s@cyber.com | grc_specialist | IT Security | 2026-07-06 11:45:00 |
| 16 | U-0016 | pavel.g@cyber.com | application_security_engineer | IT Security | 2026-07-11 18:10:00 |
| 17 | U-0017 | rina.t@cyber.com | soc_analyst | Cyber Team | 2026-07-08 09:35:00 |
| 18 | U-0018 | sami.a@cyber.com | network_engineer | IT Systems | 2026-07-12 05:55:00 |
| 19 | U-0019 | tal.w@cyber.com | penetration_tester | Cyber Team | 2026-07-05 14:50:00 |
| 20 | U-0020 | uri.z@cyber.com | security_engineer | IT Security | 2026-07-11 20:05:00 |

users also carry a password_hash column (bcrypt, seeded by init_db.py; all demo users share the documented demo password). Hashes are not shown here.

*(All 20 users are IT Systems, IT Security, or Cyber Team staff — this is an internal tool. Departments: IT Systems 9, IT Security 6, Cyber Team 5.)*

**Per-user scoping (§3.10).** The agent answers questions only for the identified user: a user sees the **assets they own**, and the `scans`, `scan_results`, `risk_acceptances` and `patch_history` belonging to those assets, plus the `remediation_tickets` they reported. `findings` is a shared catalog (like `products` in the original) and is not user-owned — it is readable as reference data, but which assets a finding affects is only ever reached through the scoped tables. `role` is a job function, not an access level — there are no privileged tiers, exactly as store customers had none. The agent opens tickets on the user's behalf (Doc 21), and only for their own assets. See the Access Model section of document 02.

---

## 2. Assets (20 rows)

| id | asset_tag | name | type | ip_address | os | location | owner_user_id |
|----|-----------|------|------|------------|----|-----------|---------------|
| 1 | A-0001 | server-prod-01 | linux_server | 10.0.1.11 | Ubuntu 22.04 | TLV-DC1 | 1 |
| 2 | A-0002 | server-prod-02 | linux_server | 10.0.1.12 | Ubuntu 20.04 | TLV-DC1 | 1 |
| 3 | A-0003 | win-dc-01 | windows_server | 10.0.2.10 | Windows Server 2019 | TLV-DC1 | 4 |
| 4 | A-0004 | win-app-02 | windows_server | 10.0.2.21 | Windows Server 2022 | TLV-DC2 | 4 |
| 5 | A-0005 | webapp-store | web_app | 10.0.3.30 | Ubuntu 22.04 | aws-eu-west-1 | 2 |
| 6 | A-0006 | webapp-portal | web_app | 10.0.3.31 | Ubuntu 22.04 | aws-eu-west-1 | 2 |
| 7 | A-0007 | db-postgres-01 | database | 10.0.4.40 | Debian 12 | TLV-DC1 | 3 |
| 8 | A-0008 | db-mysql-02 | database | 10.0.4.41 | Ubuntu 22.04 | TLV-DC2 | 3 |
| 9 | A-0009 | k8s-node-01 | linux_server | 10.0.5.50 | Amazon Linux 2023 | aws-eu-west-1 | 1 |
| 10 | A-0010 | legacy-ftp-01 | linux_server | 10.0.9.90 | CentOS 7 (EOL) | TLV-DC1 | 4 |
| 11 | A-0011 | fw-edge-01 | network_device | 10.0.0.1 | FortiOS 7.4 | TLV-DC1 | 6 |
| 12 | A-0012 | sw-core-01 | network_device | 10.0.0.2 | Cisco IOS-XE 17.9 | TLV-DC1 | 6 |
| 13 | A-0013 | lt-eng-erez | laptop | 10.10.1.15 | Windows 11 23H2 | Office-3F | 5 |
| 14 | A-0014 | lt-fin-gil | laptop | 10.10.2.22 | Windows 11 22H2 | Office-2F | 7 |
| 15 | A-0015 | lt-eng-itai | laptop | 10.10.1.31 | macOS 14 | Office-3F | 9 |
| 16 | A-0016 | jenkins-ci-01 | linux_server | 10.0.6.60 | Ubuntu 22.04 | aws-eu-west-1 | 12 |
| 17 | A-0017 | db-analytics-01 | database | 10.0.4.45 | PostgreSQL on RDS | aws-eu-west-1 | 13 |
| 18 | A-0018 | vpn-gw-01 | network_device | 10.0.0.5 | OpenVPN AS 2.13 | TLV-DC1 | 18 |
| 19 | A-0019 | mail-relay-01 | linux_server | 10.0.7.70 | Debian 12 | TLV-DC2 | 11 |
| 20 | A-0020 | webapp-api | web_app | 10.0.3.32 | Ubuntu 24.04 | aws-eu-west-1 | 16 |

*(mac_address filled with plausible values in init_db.py; asset types cover servers, web apps, databases, laptops, and network devices.)*

---

## 3. Findings (21 rows)

The catalog of what a scan can detect. **Not every finding is a vulnerability** — 9 of the 21 rows are misconfigurations, open ports, exposed data, or EOL software, and carry no CVE.

| id | finding_type | cve_id | title | severity | remediation_guide_ref |
|----|--------------|--------|-------|----------|------------------------|
| 1 | vulnerability | CVE-2025-1974 | OpenSSH pre-auth remote code execution | Critical | Document 8 |
| 2 | vulnerability | CVE-2024-6387 | regreSSHion: OpenSSH RCE (glibc) | Critical | Document 8 |
| 3 | vulnerability | CVE-2025-2419 | Apache HTTP Server path traversal | High | Document 5 |
| 4 | vulnerability | CVE-2025-0432 | nginx HTTP/3 QUIC memory disclosure | Medium | Document 5 |
| 5 | vulnerability | CVE-2023-44487 | HTTP/2 Rapid Reset denial of service | High | Document 5 |
| 6 | vulnerability | CVE-2025-5211 | Windows SMB signing bypass | High | Document 9 |
| 7 | vulnerability | CVE-2021-44228 | Log4Shell — Log4j JNDI RCE | Critical | Document 14 |
| 8 | vulnerability | CVE-2024-3094 | XZ Utils backdoor (liblzma) | Critical | Document 3 |
| 9 | vulnerability | CVE-2025-3100 | MySQL privilege escalation via stored routine | High | Document 6 |
| 10 | vulnerability | CVE-2026-0101 | Jenkins unauthenticated script console | Critical | Document 17 |
| 11 | vulnerability | — | SQL injection in /api/orders endpoint | Critical | Document 10 |
| 12 | vulnerability | — | Stored XSS in user profile page | High | Document 10 |
| 13 | misconfiguration | — | Missing HTTP security headers | Medium | Document 5 |
| 14 | misconfiguration | — | TLS 1.0/1.1 enabled | Medium | Document 11 |
| 15 | misconfiguration | — | Default credentials on network device | High | Document 16 |
| 16 | misconfiguration | — | SMBv1 protocol enabled | Medium | Document 9 |
| 17 | misconfiguration | — | LLM app passes model output directly into SQL | High | Document 18 |
| 18 | open_port | — | RDP exposed to the internet (3389/tcp) | Critical | Document 17 |
| 19 | open_port | — | Anonymous FTP enabled (21/tcp) | High | Document 13 |
| 20 | exposed_data | — | Hardcoded AWS credentials in repository | Critical | Document 12 |
| 21 | eol_software | — | CentOS 7 past end-of-life | High | Document 13 |

**Type breakdown:** vulnerability 12 · misconfiguration 5 · open_port 2 · exposed_data 1 · eol_software 1.

*Note on rows 11–12:* SQL injection and stored XSS are genuine **vulnerabilities** (code-level weaknesses) even though no vendor CVE exists — `finding_type` captures the nature of the finding, while `cve_id` merely records whether a public identifier was issued.

*(A CVE id is only permitted where finding_type = 'vulnerability' — enforced by a CHECK constraint. Full descriptions and guide titles in init_db.py.)*

---

## 4. Scans (20 rows)

| id | scan_time | scanner_tool | asset_id | status |
|----|-----------|--------------|----------|--------|
| 1 | 2026-07-11 02:00:00 | Nessus | 1 | Completed |
| 2 | 2026-07-11 02:10:00 | Nessus | 2 | Completed |
| 3 | 2026-07-10 03:00:00 | Qualys | 1 | Completed |
| 4 | 2026-07-11 02:20:00 | Nessus | 3 | Completed |
| 5 | 2026-07-11 02:30:00 | Nessus | 4 | Completed |
| 6 | 2026-07-09 14:00:00 | DAST | 5 | Completed |
| 7 | 2026-07-08 11:00:00 | SAST | 6 | Completed |
| 8 | 2026-07-05 09:00:00 | Pentest | 6 | Completed |
| 9 | 2026-07-11 02:40:00 | Nessus | 7 | Completed |
| 10 | 2026-07-11 02:50:00 | Nessus | 8 | Completed |
| 11 | 2026-07-10 03:10:00 | Qualys | 9 | Completed |
| 12 | 2026-06-25 10:00:00 | Pentest | 10 | Completed |
| 13 | 2026-07-11 03:00:00 | Nessus | 10 | Completed |
| 14 | 2026-07-10 03:20:00 | Qualys | 11 | Completed |
| 15 | 2026-07-11 03:10:00 | Nessus | 12 | Completed |
| 16 | 2026-07-11 03:20:00 | Nessus | 13 | Completed |
| 17 | 2026-07-10 03:30:00 | Qualys | 18 | Completed |
| 18 | 2026-07-08 12:00:00 | SAST | 16 | Completed |
| 19 | 2026-07-11 03:30:00 | Nessus | 19 | Completed |
| 20 | 2026-07-12 02:00:00 | Nessus | 20 | In Progress |

*(Cadence follows Document 20: Nessus weekly per server, Qualys external, SAST per merge, DAST pre-release, annual pentest. Scan 20 is In Progress — no results yet.)*

---

## 5. Scan results (17 rows — the detected instances)

One row per detected instance. `asset_id` is the direct authorization anchor — set together with the owning `scans.asset_id`, never independently, so the two can never contradict each other.

| id | scan_id | finding_id | asset_id | status | comments |
|----|---------|------------|----------|--------|----------|
| 1 | 1 | 1 | 1 | Unremediated | Port 22/tcp — OpenSSH 9.3p1 detected |
| 2 | 3 | 2 | 1 | Unremediated | Port 22/tcp — glibc host, sshd 9.3 |
| 3 | 1 | 14 | 1 | Unremediated | Port 443/tcp — TLSv1.0 handshake accepted |
| 4 | 2 | 2 | 2 | Unremediated | Port 22/tcp — sshd 8.9p1; ticket in progress |
| 5 | 6 | 11 | 5 | Unremediated | POST /api/orders 'sort' — blind SQLi confirmed |
| 6 | 6 | 13 | 5 | Unremediated | CSP and HSTS absent on all responses |
| 7 | 8 | 12 | 6 | Unremediated | PT-2026-014: payload persists in 'about' field |
| 8 | 7 | 20 | 6 | Unremediated | AKIA... key in src/config/aws.js line 14 |
| 9 | 4 | 6 | 3 | Unremediated | SMB signing not enforced (port 445) |
| 10 | 5 | 6 | 4 | Remediated | Patched via KB5040430; verified 2026-06-20 |
| 11 | 4 | 16 | 3 | Unremediated | SMBv1 enabled on domain controller |
| 12 | 12 | 19 | 10 | Unremediated | PT-2026-009: anonymous FTP, /pub readable |
| 13 | 13 | 14 | 10 | Unremediated | vsftpd accepts TLS 1.0 |
| 14 | 13 | 21 | 10 | Unremediated | CentOS 7 — EOL since 2024-06-30; migration required |
| 15 | 14 | 15 | 11 | Unremediated | admin/admin accepted on management interface |
| 16 | 17 | 18 | 18 | Unremediated | 3389/tcp reachable from internet scan point |
| 17 | 18 | 10 | 16 | Remediated | Script console locked down; verified 2026-07-10 |

*Note:* result 10 (asset 4, win-app-02) and result 9 (asset 3, win-dc-01) are the **same finding** (id 6, SMB signing) detected on two different assets — one already remediated, one not. This is exactly why findings are a catalog and scan_results are the instances: `finding_id` repeats across owners, but each row's own `asset_id` is single and unambiguous.

---

## 6. Risk acceptances (7 rows)

Parallel to `returns` in the original: a documented exception process instead of remediating. Recorded at the **asset** level, exactly as a return attaches to an order rather than to a line item.

| id | asset_id | requested_at | justification | status | review_date |
|----|----------|---------------|----------------|--------|-------------|
| 1 | 10 (legacy-ftp-01) | 2026-07-11 09:00:00 | Legacy TLS on vsftpd cannot be disabled without breaking a third-party integration; host is already isolated to the restricted VLAN pending CentOS 7 migration. | Approved | 2026-10-09 |
| 2 | 11 (fw-edge-01) | 2026-07-12 10:30:00 | Default credential change requires a vendor-supervised maintenance window; scheduled next month. | Pending | — |
| 3 | 3 (win-dc-01) | 2026-07-05 08:00:00 | SMB signing rollout on the domain controller requires downtime approval from IT Operations. | Rejected | — |
| 4 | 1 (server-prod-01) | 2026-07-08 11:00:00 | TLS 1.0 is required for a legacy monitoring client until it is upgraded next quarter; endpoint is not internet-facing. | Approved | 2026-10-06 |
| 5 | 5 (webapp-store) | 2026-07-09 14:20:00 | Adding CSP/HSTS headers requires a front-end release; scheduled for the next sprint. | Pending | — |
| 6 | 18 (vpn-gw-01) | 2026-07-06 09:45:00 | Requested temporary acceptance for internet-facing RDP during a vendor migration window. | Rejected | — |
| 7 | 6 (webapp-portal) | 2026-07-10 13:00:00 | Stored XSS fix requires a framework upgrade scheduled for the next release; the affected profile field is restricted to authenticated internal users. | Pending | — |

*Note:* rows 3 and 6 show requests being **Rejected** — the exposure stays Unremediated and the ticket/patch path remains the expected route, illustrating that acceptance is a gated exception, not a default off-ramp. Row 6 is a **Critical** internet-facing RDP exposure, which Document 17 gives a 24-hour SLA — hence the rejection. Approved rows always carry a 90-day `review_date` (Doc 1); the `justification` names the specific exposure being accepted.

---

## 7. Patch history (7 rows)

Parallel to `payments` in the original: one transaction per remediation action attempted on an asset, including failures — independent of whether a ticket exists.

| id | asset_id | action_taken | status | performed_at |
|----|----------|--------------|--------|---------------|
| 1 | 4 (win-app-02) | Applied KB5040430 cumulative update | Applied | 2026-06-20 22:00:00 |
| 2 | 16 (jenkins-ci-01) | Disabled Jenkins script console anonymous access | Applied | 2026-07-10 11:00:00 |
| 3 | 2 (server-prod-02) | Attempted openssh-server upgrade via apt | Failed | 2026-07-09 23:00:00 |
| 4 | 1 (server-prod-01) | Scheduled openssh-server upgrade for next maintenance window | Applied | 2026-07-12 09:00:00 |
| 5 | 2 (server-prod-02) | Retried openssh-server upgrade after dependency fix | Applied | 2026-07-11 20:00:00 |
| 6 | 5 (webapp-store) | Deployed parameterized queries to /api/orders | Applied | 2026-07-10 16:30:00 |
| 7 | 11 (fw-edge-01) | Attempted firmware-managed credential rotation on fw-edge-01 | Failed | 2026-07-11 08:15:00 |

*Note:* row 3 (Failed) explains why ticket 1 on server-prod-02 is still "In Progress"; row 5 shows the **retry succeeding** after the dependency issue was fixed. The same asset can appear more than once, since each row is one attempted action, not the current state.

---

## 8. Remediation tickets (7 rows)

Mirrors `support_tickets` in the original: attributed to a user, related to one of their assets.

| id | reporting_user_id | asset_id | title | status | created_at | updated_at |
|----|-------------------|----------|-------|--------|------------|------------|
| 1 | 1 (alice) | 2 (server-prod-02) | Patch OpenSSH on server-prod-02 (regreSSHion) | In Progress | 2026-07-04 09:00:00 | 2026-07-11 20:05:00 |
| 2 | 12 (lior.ben) | 16 (jenkins-ci-01) | Lock down Jenkins script console | Done | 2026-07-06 15:30:00 | 2026-07-10 11:05:00 |
| 3 | 1 (alice) | 1 (server-prod-01) | Patch OpenSSH pre-auth RCE on server-prod-01 | Open | 2026-07-05 10:15:00 | — |
| 4 | 4 (dave) | 10 (legacy-ftp-01) | Disable anonymous FTP access on legacy-ftp-01 | In Progress | 2026-07-08 13:40:00 | 2026-07-10 16:35:00 |
| 5 | 2 (bob) | 6 (webapp-portal) | Rotate hardcoded AWS credentials in webapp-portal repo | Open | 2026-07-09 09:00:00 | — |
| 6 | 4 (dave) | 3 (win-dc-01) | Enforce SMB signing on win-dc-01 | Open | 2026-07-07 11:20:00 | — |
| 7 | 18 (sami.a) | 18 (vpn-gw-01) | Remove internet exposure on vpn-gw-01 RDP | In Progress | 2026-07-11 08:30:00 | 2026-07-11 14:00:00 |

*Note:* every `reporting_user_id` is the owner of the `asset_id` on the same row — the write-side guardrail (§3.10). Newly opened tickets have `updated_at` null until something changes. **No ticket exists for the SQL injection on webapp-store** — that is deliberate, so scenarios 5 and 6 genuinely exercise the WRITE operation rather than hitting the "a ticket already covers this" rule in Doc 21.

---

## Policy + database alignment summary

| Policy rule | Data that triggers it |
|-------------|------------------------|
| Critical SLA 7 days (Doc 1) | Result 4 (regreSSHion, server-prod-02): ticket opened 2026-07-04 — in progress near SLA. Result 16 (exposed RDP, open_port): detected 2026-07-10 → 24-hour rule (Doc 17). |
| Ticket per Critical/High (Doc 1, 21) | Existing tickets cover several Critical/High findings; uncovered Unremediated Critical/High findings, such as the SQL injection on webapp-store, are cases where the agent should open a ticket. |
| Verification before closure (Doc 20) | Results 10, 17 are Remediated **with** verification comments; everything else Unremediated. |
| Agent-initiated tickets (Doc 21) | The agent decides a ticket is needed for an unremediated Critical/High finding and opens it, attributed to the user it resolved from the conversation. Only for the user's own assets; it cannot attribute a ticket to a user not in the table. |
| Guardrails / no leakage (§3.10) | bob (owns webapp-store/portal) asking about server-prod-01 → **Access denied**. alice asking "which of my assets have CVE-2024-6387?" → only server-prod-01/02, never anyone else's. |
| EOL systems (Doc 13) | legacy-ftp-01 on CentOS 7: results 12 (open_port), 13 (misconfiguration), 14 (eol_software) — remediation is migration, not patching. |
| Guide linkage | Every findings row carries remediation_guide_ref → the agent retrieves that document to answer "how do I fix it?". |
| Not every finding is a vulnerability | Findings 13–21 (misconfigurations, open ports, exposed data, EOL) have no CVE. "Which CVEs affect me?" must filter finding_type='vulnerability'; "what did the scan find?" must not. |
| Fix path depends on type (Doc 13) | Finding 21 (CentOS 7 EOL) cannot be patched — remediation is migration. Finding 20 (exposed keys) is fixed by rotation, not patching. |
| Default credentials (Doc 16) | Result 15 on fw-edge-01 (finding 15, misconfiguration): change immediately, High severity. |
| Risk acceptance requires CISO approval + 90-day review (Doc 1) | Acceptance 1 (legacy TLS on legacy-ftp-01): Approved with review_date 2026-10-09. Acceptances 3 and 6: **Rejected** — remediation stays mandatory. |
| Remediation transaction log | Patch history 3 shows a **Failed** openssh-server upgrade attempt on server-prod-02, explaining why ticket 1 on that asset is still "In Progress" rather than resolved. |
| Uniform one-hop authorization (§3.10) | Every event table (scans, scan_results, risk_acceptances, patch_history, remediation_tickets) carries `asset_id` directly — no table requires more than a single JOIN to `assets.owner_user_id`. |

This gives the agent concrete rows to query and cite when answering the example support scenarios.
