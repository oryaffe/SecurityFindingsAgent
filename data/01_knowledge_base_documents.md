# Part 1 — Knowledge Base Dataset (RAG)

Security policy and remediation documents for the vulnerability support simulation. Each document has a **title**, **short description**, and **policy content** in natural security-team language.

---

## Document 1: Vulnerability Management Policy

**Short description:**
How findings are prioritized and the remediation SLAs per severity.

**Policy content:**

All findings from authorized scanners (Nessus, Qualys, SAST, DAST, penetration tests) are recorded centrally and assigned a severity: **Critical, High, Medium, or Low**.

**Remediation SLAs (from first detection):**
- Critical: **7 days**
- High: **14 days**
- Medium: **30 days**
- Low: **90 days**

**Requirements:**
- Every open Critical or High finding must be covered by either a remediation ticket or a documented risk acceptance.
- Findings are closed only after a verifying rescan; self-attestation is not sufficient.
- Risk acceptance requires CISO approval, documented compensating controls, and a 90-day review date. Recorded in the **risk_acceptances** table: `status` starts Pending and moves to Approved or Rejected only by CISO decision; Approved records must carry a `review_date`, and the `justification` must name the specific exposure being accepted.

**Prioritization:** internet-facing assets first, then production, then staging/dev. Exploited-in-the-wild vulnerabilities are treated as Critical regardless of base severity.

---

## Document 2: Patch Management Policy

**Short description:**
Timelines and process for applying security patches to servers and endpoints.

**Policy content:**

Security patches must be applied within the vulnerability SLAs. Vendor-critical out-of-band patches are applied within **48 hours** on production systems after smoke testing in staging.

- Linux servers: enable unattended security upgrades where supported; full patch cycle monthly.
- Windows servers: monthly cumulative updates within 7 days of Patch Tuesday.
- Emergency patching may bypass change windows with Security Operations approval; rollback plan required.
- Systems that cannot be patched (vendor constraint) must be isolated and documented as risk-accepted.

---

## Document 3: Linux Server Hardening Policy

**Short description:**
Mandatory baseline for all Linux servers (Ubuntu, Debian, RHEL family).

**Policy content:**

- **SSH:** OpenSSH 9.7p1+ (mitigates CVE-2025-1974 and CVE-2024-6387). `PermitRootLogin no`, key-based auth only, `PasswordAuthentication no`, access restricted to management networks, fail2ban enabled. Interim mitigation on unpatched hosts: `LoginGraceTime 0`.
- **Network:** default-deny firewall (ufw/nftables); disable telnet, rsh, and anonymous FTP — use SFTP.
- **Crypto:** TLS 1.2 minimum on all listening services; disable TLS 1.0/1.1 and SSLv3.
- **Accounts:** per-user sudo, no shared root; lock unused accounts quarterly.
- **Audit:** auditd enabled; logs forwarded to the SIEM within 5 minutes; NTP synchronized.
- **Kernel/FS:** ASLR enabled; /tmp mounted noexec,nosuid,nodev; xz-utils at distro-approved versions (CVE-2024-3094).

---

## Document 4: Windows Server Hardening Policy

**Short description:**
Mandatory baseline for Windows Server 2019/2022.

**Policy content:**

- **SMB:** signing enforced via GPO ("Digitally sign communications (always)") — mitigates relay attacks incl. CVE-2025-5211. SMBv1 disabled. LLMNR and NetBIOS-NS disabled.
- **Patching:** latest cumulative update within 7 days of release.
- **Authentication:** NTLMv1 disabled, Kerberos with AES preferred, LAPS on all member servers, tiered administration for domain controllers.
- **Defender:** real-time + cloud protection on; ASR rules: block LSASS credential theft, block Office child processes.
- **RDP:** only via gateway/VPN, NLA required, lockout after 5 failed attempts.
- **Logging:** process creation with command line, logon events, and sensitive object access forwarded to the SIEM.

---

## Document 5: Web Server and Application Hardening Policy

**Short description:**
Required configuration for nginx/Apache and the security headers every application must return.

**Policy content:**

- **Versions:** Apache 2.4.59+ (path traversal CVE-2025-2419); nginx 1.27.1+ if HTTP/3 is enabled (CVE-2025-0432), otherwise disable QUIC. HTTP/2 Rapid Reset (CVE-2023-44487): patched builds + stream rate limiting.
- **TLS:** 1.2 minimum, 1.3 preferred; AEAD cipher suites only; HSTS with max-age 31536000.
- **Required headers on all responses:** Content-Security-Policy, X-Content-Type-Options: nosniff, X-Frame-Options: DENY (or frame-ancestors), Strict-Transport-Security, Referrer-Policy. Missing headers = Medium finding, 30-day SLA.
- **Exposure:** version banners hidden, default vhosts and sample apps removed, workers run as non-root.
- **WAF:** internet-facing apps behind the organizational WAF with OWASP CRS; per-IP rate limiting on auth and API endpoints.

---

## Document 6: Database Hardening Policy

**Short description:**
Baseline for PostgreSQL and MySQL instances.

**Policy content:**

- Databases are never internet-exposed; access only from application subnets.
- TLS 1.2+ for client connections; legacy TLS is a Medium finding.
- MySQL 8.0.40+ required (privilege escalation CVE-2025-3100); audit accounts with CREATE ROUTINE.
- Application accounts follow least privilege: no superuser, schema-scoped grants, separate migration vs runtime accounts.
- Credentials come from the secrets manager and rotate automatically — never hardcoded.
- Audit logging of DDL, privilege changes, and failed logins ships to the SIEM. Daily encrypted backups with quarterly restore tests.

---

## Document 7: Secure Coding Standard

**Short description:**
Rules developers must follow; the basis for SAST/DAST findings.

**Policy content:**

- **Input validation:** server-side, allow-list based.
- **SQL safety:** parameterized statements or ORM binding for every query. Confirmed SQL injection = **Critical, 7-day SLA, ticket required**.
- **XSS prevention:** context-aware output encoding, framework auto-escaping, allow-list sanitizer for rich text, CSP as defense in depth. Stored XSS = **High, 14-day SLA**.
- **Secrets:** never in code, config, or CI variables. Committed secret → revoke and rotate **within 24 hours**, purge history, enable secret scanning. Hardcoded credentials = **Critical**.
- **Sessions:** argon2id/bcrypt password hashing, Secure+HttpOnly+SameSite cookies, session id regenerated on login.
- **Dependencies:** lockfiles committed; SCA in CI; builds with critical vulnerable dependencies are blocked.

---

## Document 8: Remediation Guide — OpenSSH Vulnerabilities

**Short description:**
Step-by-step fix for CVE-2025-1974 and CVE-2024-6387 (regreSSHion).

**Policy content:**

1. Verify version: `ssh -V` / `dpkg -l openssh-server`.
2. Ubuntu/Debian: `sudo apt update && sudo apt install --only-upgrade openssh-server`; confirm 9.7p1+ or the distro backport that fixes the CVE.
3. If patching is delayed: set `LoginGraceTime 0` in sshd_config and restart sshd (interim only — enables connection-exhaustion DoS; patch remains mandatory).
4. Restrict port 22 to the management network.
5. Run a verifying rescan and close the finding; keep evidence in the ticket.

---

## Document 9: Remediation Guide — SMB Signing and Windows Protocols

**Short description:**
Fixing SMB signing bypass (CVE-2025-5211) and related relay exposure.

**Policy content:**

1. Apply the latest cumulative update to affected Windows Server 2019 hosts.
2. Enforce via GPO: Security Options → "Microsoft network server: Digitally sign communications (always)" = Enabled.
3. `gpupdate /force`, then validate: `Get-SmbServerConfiguration | Select RequireSecuritySignature`.
4. Disable SMBv1, LLMNR, and NetBIOS-NS while in the same change window.
5. Rescan to verify; document in the ticket.

---

## Document 10: Remediation Guide — Web Vulnerabilities (SQL Injection and XSS)

**Short description:**
Fix procedure for injection findings from SAST/DAST/pentest.

**Policy content:**

**SQL injection (Critical, 7 days):** locate the query (file/line from SAST or request from DAST); replace string-built SQL with parameterized statements; add input validation and least-privilege DB grants; add a regression test with injection payloads; request DAST revalidation.

**Stored XSS (High, 14 days):** apply context-correct output encoding in the template; sanitize stored rich text with an allow-list sanitizer and re-sanitize existing data; deploy CSP; request pentest revalidation.

Both require a remediation ticket referencing the finding.

---

## Document 11: Remediation Guide — Legacy TLS and Weak Cryptography

**Short description:**
Disabling TLS 1.0/1.1 and weak cipher suites across platforms.

**Policy content:**

- nginx: `ssl_protocols TLSv1.2 TLSv1.3;`
- Apache: `SSLProtocol -all +TLSv1.2 +TLSv1.3`
- Windows/IIS: disable legacy protocols via SChannel registry keys or IISCrypto.
- PostgreSQL: `ssl_min_protocol_version = 'TLSv1.2'`; MySQL: `tls_version=TLSv1.2,TLSv1.3`.
- vsftpd/other daemons: set the equivalent minimum-TLS directive or place behind a terminating proxy.

Verify with a rescan before closing. Legacy TLS is Medium severity (30-day SLA), but escalate to High on internet-facing services.

---

## Document 12: Remediation Guide — Exposed Secrets and Credentials

**Short description:**
What to do when keys or passwords are found in code or repositories.

**Policy content:**

1. **Rotate first, clean later:** revoke and reissue the exposed credential within **24 hours**. Assume it is compromised.
2. Move the secret to the secrets manager and load it at runtime.
3. Purge from git history (git filter-repo) and coordinate force-push.
4. Review access logs of the exposed credential for abuse; open an incident if suspicious.
5. Enable pre-commit and CI secret scanning to prevent recurrence.

---

## Document 13: End-of-Life Systems Policy

**Short description:**
Handling operating systems and software past vendor support, including which Windows Server and Linux versions are already EOL.

**Policy content:**

EOL software no longer receives security fixes and fails our patching SLAs by definition. An EOL finding **cannot be remediated by patching** — the remediation is migration or decommissioning.

**Windows Server — end-of-support dates:**

| Version | Extended support ended | Status |
|---|---|---|
| Windows Server 2008 / 2008 R2 | January 2020 | **EOL — must be decommissioned** |
| Windows Server 2012 / 2012 R2 | October 2023 | **EOL — must be decommissioned** |
| Windows Server 2016 | January 2027 | Approaching EOL — plan migration |
| Windows Server 2019 | January 2029 | Supported |
| Windows Server 2022 | October 2031 | Supported |

Windows 10 reached end of support in **October 2025**; remaining endpoints must be on Windows 11.

**Linux — end-of-life:**

| Version | EOL | Status |
|---|---|---|
| CentOS 7 | June 2024 | **EOL — migrate to RHEL 9 / Ubuntu 22.04 LTS** |
| CentOS 8 | December 2021 | **EOL** |
| Ubuntu 18.04 LTS | May 2023 (standard support) | **EOL without ESM** |
| Ubuntu 20.04 LTS | May 2025 (standard support) | EOL without ESM — plan migration |
| Ubuntu 22.04 LTS | April 2027 | Supported |

**Requirements:**

- EOL systems must have a **migration plan with a target date** approved by the asset owner.
- Until migrated: isolate in a restricted VLAN, remove internet exposure, apply strict host firewall rules, and increase monitoring.
- Legacy services on EOL hosts (e.g., anonymous FTP, SMBv1) must be **disabled immediately**, regardless of the migration timeline.
- Purchasing Extended Security Updates (ESU/ESM) is a temporary compensating control, not a remediation, and requires documented approval.

---

## Document 14: OWASP Top 10 (2025) Summary

**Short description:**
The ten most critical web application security risks (OWASP Top 10:2025 — announced November 2025, final release January 2026) and our organizational requirement for each.

**Policy content:**

The 2025 edition introduced two new categories — **A03 Software Supply Chain Failures** and **A10 Mishandling of Exceptional Conditions** — and consolidated SSRF into A01. Security Misconfiguration rose from #5 to #2.

**A01 — Broken Access Control**
Users act outside their intended permissions: IDOR, missing function-level checks, privilege escalation, and the API authorization failures BOLA and BFLA. **Server-Side Request Forgery (SSRF) was consolidated into this category in 2025** (it was a standalone A10 in 2021). *Requirement:* enforce authorization server-side on every request, deny by default, test every object reference; for SSRF, allow-list outbound destinations and block link-local/metadata addresses (169.254.169.254).

**A02 — Security Misconfiguration**
Default credentials, unnecessary features enabled, missing hardening, verbose errors. *Requirement:* hardened baselines per Documents 3–6, no defaults, required security headers, no stack traces in production.

**A03 — Software Supply Chain Failures**
Vulnerable, outdated, or maliciously modified components and build pipelines. *Requirement:* SCA scanning in CI, lockfiles committed, SBOM maintained, signed artifacts. Critical library CVEs (e.g., Log4Shell CVE-2021-44228) patched within 48 hours. Reference incident: the XZ Utils backdoor (CVE-2024-3094).

**A04 — Cryptographic Failures**
Sensitive data exposed through weak or missing encryption. *Requirement:* TLS 1.2+ in transit, AES-256-GCM at rest, no custom cryptography, no legacy protocols (Document 11).

**A05 — Injection**
Untrusted input interpreted as a command or query (SQL, NoSQL, OS, LDAP), including cross-site scripting. *Requirement:* parameterized queries and context-aware output encoding. Confirmed SQL injection is **Critical** (7-day SLA); stored XSS is **High** (14-day SLA).

**A06 — Insecure Design**
Missing or ineffective security controls at the design level — a flaw that cannot be fixed by better implementation. *Requirement:* threat modeling for services handling sensitive data; abuse-case review before build.

**A07 — Authentication Failures**
Weak credentials, broken session management, missing MFA. *Requirement:* MFA on all administrative interfaces, breached-password screening, session id regenerated on login (Document 16).

**A08 — Software and Data Integrity Failures**
Code or data modified without verification: unsigned updates, untrusted CI plugins, insecure deserialization. *Requirement:* verify integrity of artifacts and dependencies; review third-party pipeline plugins.

**A09 — Logging and Alerting Failures**
Breaches undetected because security events are not logged or not alerted on. *Requirement:* log authentication, access-control, and input-validation failures to the SIEM; alert within 15 minutes (Document 19).

**A10 — Mishandling of Exceptional Conditions**
Improper error handling, fail-open logic, and unexpected states that leave the system in an insecure condition. *Requirement:* fail closed by default; handle errors explicitly; never expose internal detail to the client.

---

## Document 15: CIS Benchmarks Adoption

**Short description:**
Which CIS controls are mandatory and how compliance is measured.

**Policy content:**

CIS **Level 1** is the mandatory baseline for all servers; selected **Level 2** controls apply to internet-facing and Tier 0 systems.

- Ubuntu 22.04: filesystem options (noexec /tmp), network sysctls, auditd + rsyslog, SSH and PAM per policy.
- Windows Server: account lockout 5, password 14+, SMB signing, NTLMv2-only, Defender + ASR.
- nginx: non-privileged worker user, server_tokens off, TLS per policy, request limits.

Automated benchmark scans run **monthly**; production assets must score **85%+**. Failures create findings in the vulnerability database with normal SLAs.

---

## Document 16: Password and MFA Policy

**Short description:**
Authentication requirements for users and administrators.

**Policy content:**

- Passwords: minimum 14 characters, screened against breached-password lists, no forced periodic rotation (rotate on suspicion of compromise).
- **MFA is mandatory** for: VPN, email, administrative interfaces, cloud consoles, and the SIEM. Phishing-resistant methods (FIDO2) required for admins.
- Service accounts use managed identities or vaulted credentials with automatic rotation — never interactive passwords.
- Default credentials on any device (network gear, appliances, cameras) are a **High** finding: change immediately upon detection.

---

## Document 17: Remote Access Policy (SASE and VPN)

**Short description:**
How remote and administrative access must be provided. SASE is the target architecture; legacy VPN is a transitional state.

**Policy content:**

**Target architecture — SASE (Secure Access Service Edge).**
New remote-access capability is delivered through SASE, which converges networking and security at the edge and replaces the flat, implicitly-trusted network that a traditional VPN creates. Required SASE components:

- **ZTNA (Zero Trust Network Access)** — per-application access, not per-network. A user authorized for one application gains no lateral reach to anything else. This is the core reason SASE is preferred over VPN.
- **Continuous verification** — identity, device posture (patch level, disk encryption, EDR present), and context are re-evaluated per session, not once at connect time.
- **Integrated SWG and CASB** — outbound web and SaaS traffic inspected at the edge.
- **Least-privilege by default** — access is granted to named applications; everything else is denied.

**Legacy VPN — transitional.**
Existing VPN concentrators remain in service until their applications are migrated to ZTNA. While a VPN is still in use, it must have: MFA enforced, split tunneling disabled for privileged sessions, device posture checks at connect time, and network segmentation so that VPN clients cannot reach management VLANs directly. **A VPN grants network-level access, which is precisely the risk SASE removes** — so every VPN in the estate must carry a documented migration plan.

**Absolute rules (apply under either architecture):**

- **RDP and SSH must never be exposed directly to the internet.** Detection of internet-exposed RDP (3389), SSH (22), or database ports is a **Critical** finding: the exposure must be removed within **24 hours**. This is not a software vulnerability — no patch exists for it; the remediation is closing the exposure.
- Administrative access to servers only from the management VLAN or a hardened jump host with session recording.
- Third-party and vendor access: time-boxed accounts, MFA, activity logging, and disabled when not in use.
- Management interfaces of infrastructure (firewalls, switches, hypervisors, CI systems) are never internet-reachable.

---

## Document 18: AI and LLM Security Guidelines (OWASP Top 10 for LLM Applications)

**Short description:**
Security requirements for applications that use large language models or AI agents, based on the OWASP Top 10 for LLM Applications.

**Policy content:**

Any application that sends organizational data to an LLM, or that lets an LLM take actions, is in scope. The following risks must be addressed before such a system reaches production.

**LLM01 — Prompt Injection**
Untrusted input (user text, a retrieved document, a web page, a scan report) manipulates the model into ignoring its instructions. *Requirement:* treat **all** retrieved and tool-returned content as untrusted data, never as instructions. Never let model output alone authorize a privileged action.

**LLM02 — Sensitive Information Disclosure**
The model reveals secrets, credentials, or another user's data through its output. *Requirement:* never place secrets in prompts or system messages; scope every data-access tool so it can only return data the requesting session is entitled to.

**LLM03 — Supply Chain**
Compromised models, plugins, or dependencies. *Requirement:* use vetted model providers and pinned SDK versions; the requirements in Document 14 (A03) apply in full.

**LLM04 — Data and Model Poisoning**
Malicious content in training data or in a retrieval corpus. *Requirement:* control write access to the knowledge base; treat the RAG corpus as a security boundary — anyone who can edit an indexed document can influence every answer.

**LLM05 — Improper Output Handling**
Model output is passed unsanitized into a downstream system (SQL, shell, HTML, an API call). *Requirement:* **never** interpolate model output into a query or command. Parameterize, validate against an allow-list, and encode for the destination context — the rules in Document 7 apply unchanged.

**LLM06 — Excessive Agency**
The agent can take actions beyond what the task requires. *Requirement:* expose the **minimum** set of tools; prefer read-only tools; any write operation must be explicit, logged, and attributable to the requesting user.

**LLM07 — System Prompt Leakage**
Instructions and configuration exposed through the model's output. *Requirement:* assume the system prompt is public. It must never contain credentials, connection strings, or security logic whose secrecy is load-bearing.

**LLM08 — Vector and Embedding Weaknesses**
Retrieval returns content the requester should not see, or is manipulated to skew answers. *Requirement:* the embedding store is a data store — apply the same access controls and integrity checks as any database.

**LLM09 — Misinformation**
Confident, fabricated output. *Requirement:* ground answers in retrieved sources and cite them; the model must state when the knowledge base does not contain an answer rather than inventing one.

**LLM10 — Unbounded Consumption**
Uncontrolled cost or resource use through unlimited queries or loops. *Requirement:* cap agent iterations, cap token usage per request, and rate-limit per user.

---

## Document 19: Security Logging and Monitoring Policy

**Short description:**
What must be logged, where it goes, and alerting expectations.

**Policy content:**

- Mandatory sources: authentication events, privilege changes, process creation on servers, security-tool alerts, WAF/IDS events, and cloud audit logs.
- Logs ship to the SIEM within **5 minutes**; retention 12 months (hot 90 days).
- Time synchronized via organizational NTP.
- Missing/silent log source for 24 hours triggers an operational alert.
- High-fidelity detections page the on-call analyst within 15 minutes. Secrets and full card numbers must never be logged.

---

## Document 20: Vulnerability Scanning Program

**Short description:**
Which tools scan what, how often, and how results are recorded.

**Policy content:**

- **Nessus** — authenticated network/OS scans of all servers: **weekly**.
- **Qualys** — external perimeter scans: **daily**; internal complement: weekly.
- **SAST** — every merge to main for all repositories.
- **DAST** — pre-release and weekly against staging of internet-facing apps.
- **Penetration test** — annually per critical application, plus after major changes.

All results are normalized into the central findings database with the source tool recorded. A finding is **Remediated** only after the originating tool (or an equivalent authenticated scan) verifies the fix; otherwise it remains **Unremediated**.

---

## Document 21: Opening a remediation ticket (system)

**Short description:**
When and how the support agent creates a row in the **remediation_tickets** table on behalf of the user.

**Policy content:**

The agent can perform operations on behalf of the user. Concretely: **the agent decides when a remediation ticket is required and opens it**, based on the user's request and on policy. The user does not open tickets directly — they describe a problem, and the agent determines whether a ticket is warranted and creates it.

**When a ticket is required:**

- Any **Critical** or **High** finding that is still Unremediated and is not already covered by a documented risk acceptance (per Document 1).
- The user explicitly asks for one.
- Remediation requires another team, or work that will not complete within the conversation.

A ticket is **not** required when the user is only asking a policy question, when the finding is already Remediated, or when an open ticket already covers the same work on that asset.

**Information to collect from the user (before creating the ticket):**

- **User:** Confirm who you are helping so the ticket is attributed correctly. Resolve **reporting_user_id** from the email the user gives you — do not guess, and do not invent a user.
- **Asset:** Every ticket relates to one asset. Resolve the asset the user is talking about and record it as **asset_id**. If the user is vague ("the SSH one"), list their open findings and confirm which asset before writing.
- **Title:** A short, clear **title** stating what is vulnerable on that asset and what must be done — specific enough that the next engineer can act without re-investigating. Since the ticket records the asset rather than an individual finding, the title is what identifies the work.

**What the system stores automatically:**

- **id** is assigned at creation.
- **created_at** is set at creation time.
- **status** is set to **Open**.
- **updated_at** is left empty until the ticket changes.

**Rules:**

- Only create a ticket once you have the minimum fields: **reporting_user_id**, **asset_id**, and **title**.
- Only create a ticket for an asset the user **owns** — users cannot open tickets for other users' assets, and you must not reveal other users' assets or findings to them.
- Do not open a second ticket for work an existing open ticket on that asset already covers; reference the existing one instead.
- Confirm to the user that a ticket was opened, and recap the **title**, **asset**, and the SLA target date from Document 1, so they know exactly what was recorded.

---

**Total: 21 policy documents.**
Categories covered: vulnerability management, patch management, Linux hardening, Windows hardening, web server and application hardening, database hardening, secure coding, OpenSSH remediation, SMB and Windows protocol remediation, web vulnerability remediation (SQLi and XSS), legacy TLS remediation, exposed secrets remediation, end-of-life systems, OWASP Top 10, CIS benchmarks, passwords and MFA, remote access (SASE and VPN), AI and LLM security, logging and monitoring, the vulnerability scanning program, and opening remediation tickets in **remediation_tickets**.
