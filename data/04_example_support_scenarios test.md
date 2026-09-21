# Part 5 — Example Support Scenarios

Twenty-three example user questions, with **which policies (RAG)** and **which database data** the agent would need to answer each. The agent combines: (1) retrieval from the security-policy knowledge base, (2) queries to the SQL database (after resolving user identity and asset context via the MCP tools).

---

## Scenario 1

**User question:** "What vulnerabilities were found on my server server-prod-01?"

**Policies needed (RAG):** none strictly (data question); optionally **Doc 1** for SLA framing.

**Database needed:** `get_asset_scan_results("server-prod-01")` — it resolves the asset by name, verifies the requester **owns** it (guardrail 3.10), and returns `scan_results` joined to `findings`, ordered by severity. Returns **all** finding types, not just CVEs. Use `get_asset_details` if the user also wants the host's OS/IP/location.

**Example:** alice (owner of server-prod-01) → results 1 (CVE-2025-1974, vulnerability, Critical), 2 (CVE-2024-6387, vulnerability, Critical), 3 (TLS 1.0/1.1, misconfiguration, Medium).

---

## Scenario 2

**User question:** "How do I fix CVE-2025-1974?"

**Policies needed (RAG):** **Document 8 — Remediation Guide: OpenSSH Vulnerabilities** (located via `findings.remediation_guide_ref`).

**Database needed:** `get_finding_details(cve_id="CVE-2025-1974")` for the description and `remediation_guide_ref` (catalog data, no asset linkage); then `get_user_assets` + `get_asset_scan_results` per asset to see which of **their** assets carry it.

**Example:** alice → guide steps (upgrade to 9.7p1, interim LoginGraceTime 0) + **her** affected assets: server-prod-01/02. bob asking about the same CVE sees none of his assets affected — and nothing of alice's.

---

## Scenario 3

**User question:** "Show me the findings on server-prod-01." (asked by bob, who does not own it)

**Policies needed (RAG):** none.

**Database needed:** ownership check — bob (U-0002) owns webapp-store/portal only; server-prod-01 belongs to alice.

**Example:** the MCP server returns **Access denied**; the agent explains that users can only view findings for assets they own, without revealing anything about the asset or its findings. This is the "no data leakage between users" guardrail (requirements 3.10) — the direct parallel of a store customer being unable to read another customer's orders.

---

## Scenario 4

**User question:** "What is the hardening policy for Linux servers?"

**Policies needed (RAG):** **Document 3 — Linux Server Hardening Policy**.

**Database needed:** none (policy-only question).

**Example:** SSH baseline, firewall default-deny, TLS 1.2+, auditd → cited from Document 3.

---

## Scenario 5

**User question:** "Open a remediation ticket for the SQL injection on webapp-store."

**Policies needed (RAG):** **Doc 21** (when a ticket is warranted and what it must contain), **Doc 1** (Critical SLA 7 days).

**Database needed:** resolve the user via `lookup_user_by_email` from the email given in conversation (if they have not identified yet, ask); `get_asset_scan_results("webapp-store")` both confirms ownership and surfaces the SQLi; then `open_remediation_ticket(asset_name, title)`. Per Doc 21 the **agent** decides the ticket is warranted (Critical, unremediated) and opens it.

**Example:** bob → ticket created, status Open, asset_id 5 (webapp-store), title naming the SQL injection so the next engineer knows what to fix.

---

## Scenario 6

**User question:** "What's open on webapp-store?" then "Open a ticket for the first one."

**Policies needed (RAG):** Doc 21 for the ticket step.

**Database needed:** first turn lists results (5 — SQLi, Critical; 6 — missing headers, Medium); second turn resolves "the first one" from **conversation memory** → the SQLi, and opens a ticket on webapp-store naming it in the title.

**Example:** demonstrates multi-turn memory (up to 20 messages) within a session.

---

## Scenario 7

**User question:** "Show all my open Critical findings from any scanner." (asked by alice)

**Policies needed (RAG):** **Doc 1** for prioritization framing.

**Database needed:** `get_user_assets` to get the user's asset list, then `get_asset_scan_results` for each one (at most three assets for any user in this dataset), filtering to severity Critical + status Unremediated. There is deliberately **no** cross-asset search tool: every read stays anchored to one owned asset, which is what keeps the guardrail simple. No finding_type filter — an exposed RDP port is Critical too.

**Example:** alice → 3 results: CVE-2025-1974 once and CVE-2024-6387 twice across server-prod-01/02. bob asking the same question gets **his** criticals (SQLi, hardcoded keys) — different users, different answers, no leakage.

---

## Scenario 8

**User question:** "Which of my Critical findings are past SLA?"

**Policies needed (RAG):** **Doc 1** — Critical = 7 days.

**Database needed:** `get_asset_scan_results` per owned asset for the Unremediated Critical findings, then `get_asset_scans` on the same asset; match the two on `scan_id` to get each finding's `scan_time`, and compare it to today (2026-07-12). The `scan_id` returned by both tools is what makes this join possible.

**Example:** alice → regreSSHion on server-prod-02 first seen ≥8 days ago (ticket 1 already In Progress); agent flags SLA breach risk.

---

## Scenario 9

**User question:** "Why can't I just mark the finding as fixed myself?"

**Policies needed (RAG):** **Doc 20** — closure only after a verifying rescan; **Doc 1** — no self-attestation.

**Database needed:** optionally show result status values (Unremediated/Remediated with verification comments, e.g. results 10, 17).

**Example:** agent explains verification requirement and offers to check latest scan status.

---

## Scenario 10

**User question:** "The FTP server is EOL CentOS 7 — do I still have to patch it?"

**Policies needed (RAG):** **Doc 13 — End-of-Life Systems Policy**.

**Database needed:** asset legacy-ftp-01 + its results: 12 (anonymous FTP, open_port), 13 (legacy TLS, misconfiguration), 14 (**eol_software** — CentOS 7 past EOL).

**Example:** the `eol_software` finding has no patch — the agent must say so explicitly: remediation is migration/decommission, plus immediate disable of anonymous FTP, with isolation until then. This is the clearest case where finding_type changes the answer.

---

## Scenario 11

**User question:** "We found default credentials on fw-edge-01. How urgent is this?"

**Policies needed (RAG):** **Doc 16** — default credentials are High, change immediately.

**Database needed:** result 15 on asset A-0011 (finding 15, misconfiguration; owner fatima.h); severity High.

**Example:** fatima → immediate change required, 14-day SLA at most, ticket recommended.

---

## Scenario 12

**User question:** "Is RDP allowed from the internet if it's only temporary?"

**Policies needed (RAG):** **Doc 17 — Remote Access and VPN Policy** (never; Critical, remove within 24 hours).

**Database needed:** result 16 (finding 18 — RDP exposed, **open_port**) on vpn-gw-01. Not a software flaw: no patch to apply, the fix is closing the exposure.

**Example:** sami (owner) → policy says no exceptions; agent offers a ticket for immediate remediation.

---

## Scenario 13

**User question:** "What are the required HTTP security headers for our apps?"

**Policies needed (RAG):** **Doc 5 — Web Server and Application Hardening Policy**.

**Database needed:** optionally the user's web assets with result 6 (finding 13 — missing headers, misconfiguration, on webapp-store).

**Example:** bob → header list + note that webapp-store currently fails this (Medium, 30-day SLA).

---

## Scenario 14

**User question:** "A developer committed AWS keys to the repo. What now?"

**Policies needed (RAG):** **Doc 12 — Exposed Secrets** (rotate within 24h, purge history, scanning); **Doc 7** (Critical).

**Database needed:** result 8 on webapp-portal (finding 20 — **exposed_data**, owner bob). Fix path is rotation, not patching.

**Example:** step-by-step rotation-first procedure + offer to open a Critical ticket.

---

## Scenario 15

**User question:** "The finding on win-app-02 shows Remediated — how and when was it verified?"

**Policies needed (RAG):** **Doc 20** — verification requirement.

**Database needed:** result 10: status Remediated, comments "Patched via KB5040430; verified 2026-06-20". Note the same finding (6) is still Unremediated on win-dc-01 as result 9.

**Example:** dave → agent cites the verification note ("verified 2026-06-20") and the originating Nessus scan. The schema records *that* it was verified and when, not which person signed off — the agent should answer with what is recorded rather than inventing an approver.

---

## Scenario 16

**User question:** "What's our password and MFA policy for admins?"

**Policies needed (RAG):** **Doc 16 — Password and MFA Policy**.

**Database needed:** none.

**Example:** 14+ chars, breached-list screening, FIDO2 for admins, MFA on VPN/consoles.

---

## Scenario 17

**User question:** "Which scanner found the XSS on webapp-portal, and when?"

**Policies needed (RAG):** none; optionally **Doc 10** for the fix.

**Database needed:** `get_asset_scan_results("webapp-portal")` for the finding and its comments (PT-2026-014), then `get_asset_scans("webapp-portal")`; match on the `scan_id` both tools return → scan 8 (Pentest, 2026-07-05). This asset has two scans — the AWS-credentials finding came from scan 7 (SAST) — so the `scan_id` match is what disambiguates them.

**Example:** bob → annual pentest detection; agent offers the remediation guide and a ticket.

---

## Scenario 18

**User question:** "List my assets." (asked by carol)

**Policies needed (RAG):** none.

**Database needed:** `get_user_assets` scoped by owner_user_id → assets 7, 8 (db-postgres-01, db-mysql-02).

**Example:** carol sees exactly her two databases — nothing else, per the guardrail.

---

## Scenario 19

**User question:** "Show my tickets." / "What's the status of the OpenSSH ticket?"

**Policies needed (RAG):** none; **Doc 1** if discussing SLA.

**Database needed:** `get_user_remediation_tickets` — scoped to the requester's own tickets. alice → ticket 1 (server-prod-02, In Progress, last updated 2026-07-11) and ticket 3 (server-prod-01, Open, never updated).

**Example:** demonstrates ticket read-back and status tracking.

---

## Scenario 20

**User question:** "Which CVEs affect my servers?" — followed by: "OK, but what else did the scans find?"

**Policies needed (RAG):** none; **Doc 20** if discussing scan coverage.

**Database needed:** the first question filters `finding_type = 'vulnerability'` **and** `cve_id IS NOT NULL`; the second must **drop the filter entirely** and return misconfigurations, open ports, exposed data, and EOL findings as well.

**Example:** this pair is the sharpest test of the data model. For alice: the first answer returns CVE-2025-1974 and CVE-2024-6387; the second additionally surfaces the TLS 1.0/1.1 misconfiguration on server-prod-01 — a real exposure with no CVE. An agent that treats "finding" and "vulnerability" as synonyms silently drops it.

---

## Scenario 21

**User question:** "How often do we scan, and with which tools?"

**Policies needed (RAG):** **Doc 20 — Vulnerability Scanning Program**.

**Database needed:** optionally `get_asset_scans` per owned asset for recent scan times as evidence.

**Example:** Nessus weekly, Qualys daily external, SAST per merge, DAST pre-release, annual pentest — with the user's latest scan times.

---

## Scenario 22

**User question:** "I can't fix the legacy TLS on legacy-ftp-01 right now — can we accept the risk?"

**Policies needed (RAG):** **Doc 1** — risk acceptance requires CISO approval, a compensating control, and a 90-day review date.

**Database needed:** `get_asset_risk_acceptances("legacy-ftp-01")` — it verifies dave owns the asset and returns any existing acceptance before anything is created. The agent explains this requires CISO sign-off; there is deliberately no write tool for risk acceptances, so the agent can read and report them but never approve one.

**Example:** dave → the agent finds acceptance 1 on that asset already **Approved**, with review_date 2026-10-09 and a justification naming the legacy TLS exposure, and reports it instead of duplicating the request. Contrast: acceptance 3 (win-dc-01) and 6 (vpn-gw-01) were **Rejected** — the agent must say remediation is still required, not offer acceptance as a settled exception.

---

## Scenario 23

**User question:** "What's been tried already to fix the regreSSHion finding on server-prod-02?"

**Policies needed (RAG):** none — this is a transaction-history question, not a policy question.

**Database needed:** `get_asset_patch_history("server-prod-02")` — it verifies alice owns the asset and returns the remediation actions attempted on it.

**Example:** alice → patch_history row 3 shows a **Failed** attempt ("Attempted openssh-server upgrade via apt", 2026-07-09), followed by row 5, a successful retry after a dependency fix. The agent should surface both attempts in order, including the failure — a remediation log is only useful if it shows what did not work, not just the final state.

---

## Summary

| # | Scenario | RAG documents | Database tables | Write? |
|---|----------|---------------|-----------------|--------|
| 1 | Findings on a specific asset | (Doc 1 for SLA framing) | assets, scans, scan_results, findings | — |
| 2 | How to fix a CVE | Doc 8 (via remediation_guide_ref) | findings, scan_results, scans, assets | — |
| 3 | Access denied on another user's asset | — | users, assets | — |
| 4 | Linux hardening policy | Doc 3 | — | — |
| 5 | Open a ticket for the SQL injection | Doc 21, Doc 1 | users, assets, scan_results, remediation_tickets | ✔ |
| 6 | Multi-turn: "open a ticket for the first one" | Doc 21 | assets, scan_results, remediation_tickets | ✔ |
| 7 | All open Critical findings | Doc 1 | scan_results, scans, assets, findings | — |
| 8 | Which Criticals are past SLA | Doc 1 | scans, scan_results, findings | — |
| 9 | Why can't I self-attest a fix | Doc 20, Doc 1 | scan_results | — |
| 10 | EOL CentOS 7 — must I patch? | Doc 13 | assets, scan_results, findings | — |
| 11 | Default credentials urgency | Doc 16 | assets, scan_results, findings | — |
| 12 | Is temporary internet RDP allowed? | Doc 17 | assets, scan_results, findings | — |
| 13 | Required HTTP security headers | Doc 5 | (optional) scan_results, findings | — |
| 14 | AWS keys committed to the repo | Doc 12, Doc 7 | scan_results, findings | — |
| 15 | How and when was this finding verified? | Doc 20 | scan_results, scans | — |
| 16 | Password and MFA policy | Doc 16 | — | — |
| 17 | Which scanner found the XSS, and when? | (Doc 10) | scans, scan_results, findings | — |
| 18 | Which assets am I responsible for? | — | users, assets | — |
| 19 | Show my tickets / ticket status | (Doc 1) | remediation_tickets, assets | — |
| 20 | "Which CVEs affect me?" vs "what else did the scans find?" | (Doc 20) | findings (finding_type filter), scan_results | — |
| 21 | Scan cadence and tools | Doc 20 | (optional) scans | — |
| 22 | Accept the risk on legacy TLS | Doc 1 | assets, risk_acceptances | — |
| 23 | What's been tried on this asset already | — | assets, patch_history | — |

**Coverage:** 23 scenarios — 4 policy-only (RAG, no DB), 17 read-only (RAG + DB), 1 guardrail denial scenario, and 2 involving a **write** (agent opens a remediation ticket on the user's behalf, for their own assets only). Reading `risk_acceptances` and `patch_history` (scenarios 22–23) does not involve a write — the agent surfaces existing records; approving a risk acceptance is a CISO action outside the agent's tools.

**Knowledge-base documents exercised:** 1, 3, 5, 7, 8, 10, 11, 12, 13, 16, 17, 20, 21.

**Every finding_type appears:** vulnerability (2, 5, 8), misconfiguration (11, 13), open_port (10, 12), exposed_data (14), eol_software (10).

**Every table is exercised:** users (2, 3, 22 via asset ownership), assets (1, 3, 18, 22, 23), findings (throughout), scans (17, 21), scan_results (throughout), risk_acceptances (22), patch_history (23), remediation_tickets (5, 6, 19).
