"""
Create SQLite database from dataset_design schema and sample data.
Idempotent: overwrites security.db on each run.
Run from project root with: python database/init_db.py
"""
import sqlite3
from pathlib import Path

import bcrypt

DB_PATH = Path(__file__).resolve().parent / "security.db"

# ---------------------------------------------------------------------------
# Schema (from dataset_design/02_sql_schema_definition.md)
# ---------------------------------------------------------------------------

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    user_id TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL,
    department TEXT NOT NULL,
    last_login TEXT,
    password_hash TEXT NOT NULL
);

CREATE TABLE assets (
    id INTEGER PRIMARY KEY,
    asset_tag TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    mac_address TEXT,
    os TEXT NOT NULL,
    location TEXT NOT NULL,
    owner_user_id INTEGER NOT NULL,
    FOREIGN KEY (owner_user_id) REFERENCES users(id)
);

CREATE TABLE findings (
    id INTEGER PRIMARY KEY,
    finding_type TEXT NOT NULL
        CHECK (finding_type IN ('vulnerability', 'misconfiguration', 'open_port', 'exposed_data', 'eol_software')),
    cve_id TEXT UNIQUE,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('Critical', 'High', 'Medium', 'Low')),
    description TEXT NOT NULL,
    remediation_guide_ref TEXT NOT NULL,
    -- A CVE id is meaningful only for actual vulnerabilities.
    CHECK (cve_id IS NULL OR finding_type = 'vulnerability')
);

CREATE TABLE scans (
    id INTEGER PRIMARY KEY,
    scan_time TEXT NOT NULL,
    scanner_tool TEXT NOT NULL,
    asset_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    FOREIGN KEY (asset_id) REFERENCES assets(id)
);

CREATE TABLE scan_results (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL,
    finding_id INTEGER NOT NULL,
    asset_id INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('Unremediated', 'Remediated')),
    comments TEXT,
    -- asset_id is the direct authorization anchor (one hop, like every other
    -- event table here). It is set alongside scans.asset_id at insert time,
    -- not an independently-chosen fact.
    FOREIGN KEY (scan_id) REFERENCES scans(id),
    FOREIGN KEY (finding_id) REFERENCES findings(id),
    FOREIGN KEY (asset_id) REFERENCES assets(id)
);

CREATE TABLE risk_acceptances (
    id INTEGER PRIMARY KEY,
    asset_id INTEGER NOT NULL,
    requested_at TEXT NOT NULL,
    justification TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('Pending', 'Approved', 'Rejected')),
    review_date TEXT,
    FOREIGN KEY (asset_id) REFERENCES assets(id)
);

CREATE TABLE patch_history (
    id INTEGER PRIMARY KEY,
    asset_id INTEGER NOT NULL,
    action_taken TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('Applied', 'Failed', 'Rolled_back')),
    performed_at TEXT NOT NULL,
    FOREIGN KEY (asset_id) REFERENCES assets(id)
);

CREATE TABLE remediation_tickets (
    id INTEGER PRIMARY KEY,
    reporting_user_id INTEGER NOT NULL,
    asset_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT,
    FOREIGN KEY (reporting_user_id) REFERENCES users(id),
    FOREIGN KEY (asset_id) REFERENCES assets(id)
);

-- Indexes (from schema doc)
CREATE INDEX idx_assets_owner_user_id ON assets(owner_user_id);
CREATE INDEX idx_assets_asset_tag ON assets(asset_tag);
CREATE INDEX idx_assets_name ON assets(name);
CREATE INDEX idx_scans_asset_id ON scans(asset_id);
CREATE INDEX idx_scans_scanner_tool ON scans(scanner_tool);
CREATE INDEX idx_scan_results_scan_id ON scan_results(scan_id);
CREATE INDEX idx_scan_results_finding_id ON scan_results(finding_id);
CREATE INDEX idx_scan_results_asset_id ON scan_results(asset_id);
CREATE INDEX idx_scan_results_status ON scan_results(status);
CREATE INDEX idx_findings_cve_id ON findings(cve_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_type ON findings(finding_type);
CREATE INDEX idx_risk_acceptances_asset_id ON risk_acceptances(asset_id);
CREATE INDEX idx_risk_acceptances_status ON risk_acceptances(status);
CREATE INDEX idx_patch_history_asset_id ON patch_history(asset_id);
CREATE INDEX idx_tickets_asset_id ON remediation_tickets(asset_id);
CREATE INDEX idx_tickets_reporting_user_id ON remediation_tickets(reporting_user_id);
"""

# ---------------------------------------------------------------------------
# Sample data (from dataset_design/03_generated_dataset_samples.md)
# Reference date for "today": 2026-07-12
# ---------------------------------------------------------------------------

# 20 users: id, user_id, email, role, department, last_login
# password_hash is NOT stored in this tuple list. One bcrypt hash of SecurePass1!
# is generated at seed time and reused for all 20 rows. That reuse is intentional:
# every demo user shares the same educational demo password (not 20 unique hashes).
# All users are IT Systems / IT Security / Cyber Team staff.
# Guardrails (requirements 3.10): the agent authenticates the user by email and
# password (via verify_user_credentials) and answers questions ONLY for that user.
# A user sees the assets they own (assets.owner_user_id), and the scans,
# scan_results, risk_acceptances and patch_history of those assets, plus the
# remediation_tickets they reported. `findings` is a shared catalog (like `products`
# in the original) and is not user-owned. No data leakage between users. `role` is
# descriptive (job function), NOT an access level: there are no privileged tiers,
# exactly as the original store had no privileged customers.
USERS = [
    (1, "U-0001", "alice@cyber.com", "security_analyst", "IT Security", "2026-07-11 08:45:00"),
    (2, "U-0002", "bob@cyber.com", "systems_engineer", "IT Systems", "2026-07-10 17:20:00"),
    (3, "U-0003", "carol@cyber.com", "database_administrator", "IT Systems", "2026-07-11 09:10:00"),
    (4, "U-0004", "dave@cyber.com", "systems_administrator", "IT Systems", "2026-07-12 07:30:00"),
    (5, "U-0005", "erez.levi@cyber.com", "soc_analyst", "Cyber Team", "2026-07-09 14:00:00"),
    (6, "U-0006", "fatima.h@cyber.com", "network_engineer", "IT Systems", "2026-07-11 11:05:00"),
    (7, "U-0007", "gil.shapira@cyber.com", "ciso", "IT Security", "2026-07-08 10:15:00"),
    (8, "U-0008", "hana.katz@cyber.com", "security_analyst", "IT Security", "2026-07-12 06:50:00"),
    (9, "U-0009", "itai.mor@cyber.com", "devops_engineer", "IT Systems", "2026-07-10 13:40:00"),
    (10, "U-0010", "julia.k@cyber.com", "threat_hunter", "Cyber Team", "2026-07-07 09:00:00"),
    (11, "U-0011", "kobi.d@cyber.com", "systems_engineer", "IT Systems", "2026-07-11 16:25:00"),
    (12, "U-0012", "lior.ben@cyber.com", "devops_engineer", "IT Systems", "2026-07-11 12:00:00"),
    (13, "U-0013", "maya.r@cyber.com", "database_administrator", "IT Systems", "2026-07-09 15:30:00"),
    (14, "U-0014", "nadav.o@cyber.com", "incident_responder", "Cyber Team", "2026-07-10 08:20:00"),
    (15, "U-0015", "orly.s@cyber.com", "grc_specialist", "IT Security", "2026-07-06 11:45:00"),
    (16, "U-0016", "pavel.g@cyber.com", "application_security_engineer", "IT Security", "2026-07-11 18:10:00"),
    (17, "U-0017", "rina.t@cyber.com", "soc_analyst", "Cyber Team", "2026-07-08 09:35:00"),
    (18, "U-0018", "sami.a@cyber.com", "network_engineer", "IT Systems", "2026-07-12 05:55:00"),
    (19, "U-0019", "tal.w@cyber.com", "penetration_tester", "Cyber Team", "2026-07-05 14:50:00"),
    (20, "U-0020", "uri.z@cyber.com", "security_engineer", "IT Security", "2026-07-11 20:05:00"),
]

# 20 assets: id, asset_tag, name, type, ip_address, mac_address, os, location, owner_user_id
ASSETS = [
    (1, "A-0001", "server-prod-01", "linux_server", "10.0.1.11", "00:1A:2B:3C:4D:01", "Ubuntu 22.04", "TLV-DC1", 1),
    (2, "A-0002", "server-prod-02", "linux_server", "10.0.1.12", "00:1A:2B:3C:4D:02", "Ubuntu 20.04", "TLV-DC1", 1),
    (3, "A-0003", "win-dc-01", "windows_server", "10.0.2.10", "00:1A:2B:3C:4D:03", "Windows Server 2019", "TLV-DC1", 4),
    (4, "A-0004", "win-app-02", "windows_server", "10.0.2.21", "00:1A:2B:3C:4D:04", "Windows Server 2022", "TLV-DC2", 4),
    (5, "A-0005", "webapp-store", "web_app", "10.0.3.30", None, "Ubuntu 22.04", "aws-eu-west-1", 2),
    (6, "A-0006", "webapp-portal", "web_app", "10.0.3.31", None, "Ubuntu 22.04", "aws-eu-west-1", 2),
    (7, "A-0007", "db-postgres-01", "database", "10.0.4.40", "00:1A:2B:3C:4D:07", "Debian 12", "TLV-DC1", 3),
    (8, "A-0008", "db-mysql-02", "database", "10.0.4.41", "00:1A:2B:3C:4D:08", "Ubuntu 22.04", "TLV-DC2", 3),
    (9, "A-0009", "k8s-node-01", "linux_server", "10.0.5.50", None, "Amazon Linux 2023", "aws-eu-west-1", 1),
    (10, "A-0010", "legacy-ftp-01", "linux_server", "10.0.9.90", "00:1A:2B:3C:4D:10", "CentOS 7 (EOL)", "TLV-DC1", 4),
    (11, "A-0011", "fw-edge-01", "network_device", "10.0.0.1", "00:1A:2B:3C:4D:11", "FortiOS 7.4", "TLV-DC1", 6),
    (12, "A-0012", "sw-core-01", "network_device", "10.0.0.2", "00:1A:2B:3C:4D:12", "Cisco IOS-XE 17.9", "TLV-DC1", 6),
    (13, "A-0013", "lt-eng-erez", "laptop", "10.10.1.15", "00:1A:2B:3C:4D:13", "Windows 11 23H2", "Office-3F", 5),
    (14, "A-0014", "lt-fin-gil", "laptop", "10.10.2.22", "00:1A:2B:3C:4D:14", "Windows 11 22H2", "Office-2F", 7),
    (15, "A-0015", "lt-eng-itai", "laptop", "10.10.1.31", "00:1A:2B:3C:4D:15", "macOS 14", "Office-3F", 9),
    (16, "A-0016", "jenkins-ci-01", "linux_server", "10.0.6.60", None, "Ubuntu 22.04", "aws-eu-west-1", 12),
    (17, "A-0017", "db-analytics-01", "database", "10.0.4.45", None, "PostgreSQL on RDS", "aws-eu-west-1", 13),
    (18, "A-0018", "vpn-gw-01", "network_device", "10.0.0.5", "00:1A:2B:3C:4D:18", "OpenVPN AS 2.13", "TLV-DC1", 18),
    (19, "A-0019", "mail-relay-01", "linux_server", "10.0.7.70", "00:1A:2B:3C:4D:19", "Debian 12", "TLV-DC2", 11),
    (20, "A-0020", "webapp-api", "web_app", "10.0.3.32", None, "Ubuntu 24.04", "aws-eu-west-1", 16),
]

# 20 findings: id, finding_type, cve_id, title, severity, description, remediation_guide_ref
# Not every finding is a vulnerability: scans also surface misconfigurations, open ports,
# exposed data, and EOL software. cve_id is populated only for finding_type='vulnerability'.
FINDINGS = [
    (1, "vulnerability", "CVE-2025-1974", "OpenSSH pre-auth remote code execution", "Critical",
     "Unauthenticated RCE in OpenSSH < 9.7 via a race condition in signal handling.",
     "Document 8: Remediation Guide — OpenSSH Vulnerabilities"),
    (2, "vulnerability", "CVE-2024-6387", "regreSSHion: OpenSSH RCE (glibc)", "Critical",
     "Signal handler race in OpenSSH on glibc systems allows remote code execution as root.",
     "Document 8: Remediation Guide — OpenSSH Vulnerabilities"),
    (3, "vulnerability", "CVE-2025-2419", "Apache HTTP Server path traversal", "High",
     "Improper path normalization in Apache < 2.4.59 allows reading files outside the document root.",
     "Document 5: Web Server and Application Hardening Policy"),
    (4, "vulnerability", "CVE-2025-0432", "nginx HTTP/3 QUIC memory disclosure", "Medium",
     "Crafted QUIC packets can leak worker memory in nginx < 1.27.1 with HTTP/3 enabled.",
     "Document 5: Web Server and Application Hardening Policy"),
    (5, "vulnerability", "CVE-2023-44487", "HTTP/2 Rapid Reset denial of service", "High",
     "HTTP/2 protocol flaw allowing DoS through rapid stream resets.",
     "Document 5: Web Server and Application Hardening Policy"),
    (6, "vulnerability", "CVE-2025-5211", "Windows SMB signing bypass", "High",
     "SMB signing can be bypassed on unpatched Windows Server 2019, enabling relay attacks.",
     "Document 9: Remediation Guide — SMB Signing and Windows Protocols"),
    (7, "vulnerability", "CVE-2021-44228", "Log4Shell — Log4j JNDI RCE", "Critical",
     "Remote code execution in Log4j 2.x via JNDI lookup in logged data.",
     "Document 14: OWASP Top 10 (2025) Summary"),
    (8, "vulnerability", "CVE-2024-3094", "XZ Utils backdoor (liblzma)", "Critical",
     "Malicious code in xz 5.6.0/5.6.1 allows SSH authentication bypass.",
     "Document 3: Linux Server Hardening Policy"),
    (9, "vulnerability", "CVE-2025-3100", "MySQL privilege escalation via stored routine", "High",
     "Authenticated users can escalate privileges via crafted stored routines in MySQL < 8.0.40.",
     "Document 6: Database Hardening Policy"),
    (10, "vulnerability", "CVE-2026-0101", "Jenkins unauthenticated script console", "Critical",
     "Misconfigured Jenkins exposes the Groovy script console without authentication.",
     "Document 17: Remote Access Policy (SASE and VPN)"),
    # --- non-CVE findings: code-level weaknesses detected by SAST/DAST/pentest ---
    (11, "vulnerability", None, "SQL injection in /api/orders endpoint", "Critical",
     "Unparameterized SQL built from user input in the orders API (confirmed by DAST). "
     "A code-level weakness with no vendor CVE, but a vulnerability nonetheless.",
     "Document 10: Remediation Guide — Web Vulnerabilities (SQL Injection and XSS)"),
    (12, "vulnerability", None, "Stored XSS in user profile page", "High",
     "User-supplied HTML rendered without output encoding in the profile 'about' field.",
     "Document 10: Remediation Guide — Web Vulnerabilities (SQL Injection and XSS)"),
    # --- misconfigurations: fixed by changing a setting, not by patching ---
    (13, "misconfiguration", None, "Missing HTTP security headers", "Medium",
     "Responses lack CSP, X-Content-Type-Options, and Strict-Transport-Security.",
     "Document 5: Web Server and Application Hardening Policy"),
    (14, "misconfiguration", None, "TLS 1.0/1.1 enabled", "Medium",
     "Legacy TLS protocol versions accepted; vulnerable to downgrade attacks.",
     "Document 11: Remediation Guide — Legacy TLS and Weak Cryptography"),
    (15, "misconfiguration", None, "Default credentials on network device", "High",
     "Management interface accepts the vendor default username and password.",
     "Document 16: Password and MFA Policy"),
    (16, "misconfiguration", None, "SMBv1 protocol enabled", "Medium",
     "Deprecated SMBv1 enabled, expanding attack surface (e.g., EternalBlue-class exploits).",
     "Document 9: Remediation Guide — SMB Signing and Windows Protocols"),
    (17, "misconfiguration", None, "LLM app passes model output directly into SQL", "High",
     "The internal AI assistant interpolates model output into a database query without "
     "parameterization (OWASP LLM05, Improper Output Handling). A prompt-injected response "
     "can execute arbitrary SQL.",
     "Document 18: AI and LLM Security Guidelines (OWASP Top 10 for LLM Applications)"),
    # --- open ports: exposure findings, fixed at the network/firewall layer ---
    (18, "open_port", None, "RDP exposed to the internet (3389/tcp)", "Critical",
     "TCP 3389 reachable from the internet. Not a software flaw — an exposure that must be removed within 24 hours.",
     "Document 17: Remote Access Policy (SASE and VPN)"),
    (19, "open_port", None, "Anonymous FTP enabled (21/tcp)", "High",
     "Anonymous FTP access on port 21 exposes internal documents (pentest confirmed).",
     "Document 13: End-of-Life Systems Policy"),
    # --- exposed data: sensitive material where it should not be ---
    (20, "exposed_data", None, "Hardcoded AWS credentials in repository", "Critical",
     "SAST detected AWS access keys committed to the application repository. "
     "Remediation is rotation first, then history purge — patching is irrelevant.",
     "Document 12: Remediation Guide — Exposed Secrets and Credentials"),
    # --- eol_software: remediated by migration, not by patching (Doc 13) ---
    (21, "eol_software", None, "CentOS 7 past end-of-life", "High",
     "Host runs CentOS 7, which no longer receives security fixes. No patch exists; "
     "remediation is migration or decommissioning.",
     "Document 13: End-of-Life Systems Policy"),
]

# 20 scans: id, scan_time, scanner_tool, asset_id, status
SCANS = [
    (1, "2026-07-11 02:00:00", "Nessus", 1, "Completed"),
    (2, "2026-07-11 02:10:00", "Nessus", 2, "Completed"),
    (3, "2026-07-10 03:00:00", "Qualys", 1, "Completed"),
    (4, "2026-07-11 02:20:00", "Nessus", 3, "Completed"),
    (5, "2026-07-11 02:30:00", "Nessus", 4, "Completed"),
    (6, "2026-07-09 14:00:00", "DAST", 5, "Completed"),
    (7, "2026-07-08 11:00:00", "SAST", 6, "Completed"),
    (8, "2026-07-05 09:00:00", "Pentest", 6, "Completed"),
    (9, "2026-07-11 02:40:00", "Nessus", 7, "Completed"),
    (10, "2026-07-11 02:50:00", "Nessus", 8, "Completed"),
    (11, "2026-07-10 03:10:00", "Qualys", 9, "Completed"),
    (12, "2026-06-25 10:00:00", "Pentest", 10, "Completed"),
    (13, "2026-07-11 03:00:00", "Nessus", 10, "Completed"),
    (14, "2026-07-10 03:20:00", "Qualys", 11, "Completed"),
    (15, "2026-07-11 03:10:00", "Nessus", 12, "Completed"),
    (16, "2026-07-11 03:20:00", "Nessus", 13, "Completed"),
    (17, "2026-07-10 03:30:00", "Qualys", 18, "Completed"),
    (18, "2026-07-08 12:00:00", "SAST", 16, "Completed"),
    (19, "2026-07-11 03:30:00", "Nessus", 19, "Completed"),
    (20, "2026-07-12 02:00:00", "Nessus", 20, "In Progress"),
]

# 17 scan_results: id, scan_id, finding_id, asset_id, status, comments
# One row per detected instance. asset_id is the direct authorization anchor
# (matches the owning scans.asset_id in every row -- set together, never independently).
SCAN_RESULTS = [
    (1, 1, 1, 1, "Unremediated", "Port 22/tcp — OpenSSH 9.3p1 detected"),
    (2, 3, 2, 1, "Unremediated", "Port 22/tcp — glibc host, sshd 9.3"),
    (3, 1, 14, 1, "Unremediated", "Port 443/tcp — TLSv1.0 handshake accepted"),
    (4, 2, 2, 2, "Unremediated", "Port 22/tcp — sshd 8.9p1; ticket in progress"),
    (5, 6, 11, 5, "Unremediated", "POST /api/orders 'sort' — blind SQLi confirmed"),
    (6, 6, 13, 5, "Unremediated", "CSP and HSTS absent on all responses"),
    (7, 8, 12, 6, "Unremediated", "PT-2026-014: payload persists in 'about' field"),
    (8, 7, 20, 6, "Unremediated", "AKIA... key in src/config/aws.js line 14"),
    (9, 4, 6, 3, "Unremediated", "SMB signing not enforced (port 445)"),
    (10, 5, 6, 4, "Remediated", "Patched via KB5040430; verified 2026-06-20"),
    (11, 4, 16, 3, "Unremediated", "SMBv1 enabled on domain controller"),
    (12, 12, 19, 10, "Unremediated", "PT-2026-009: anonymous FTP, /pub readable"),
    (13, 13, 14, 10, "Unremediated", "vsftpd accepts TLS 1.0"),
    (14, 13, 21, 10, "Unremediated", "CentOS 7 — EOL since 2024-06-30; migration required"),
    (15, 14, 15, 11, "Unremediated", "admin/admin accepted on management interface"),
    (16, 17, 18, 18, "Unremediated", "3389/tcp reachable from internet scan point"),
    (17, 18, 10, 16, "Remediated", "Script console locked down; verified 2026-07-10"),
]

# 7 risk_acceptances: id, asset_id, requested_at, justification, status, review_date
# Parallel to `returns`: an exception process instead of remediating, recorded at the
# asset level (exactly as a return in the original attaches to an order, not a line item).
RISK_ACCEPTANCES = [
    (1, 10, "2026-07-11 09:00:00",
     "Legacy TLS on vsftpd cannot be disabled without breaking a third-party integration; "
     "host is already isolated to the restricted VLAN pending CentOS 7 migration.",
     "Approved", "2026-10-09"),
    (2, 11, "2026-07-12 10:30:00",
     "Default credential change requires a vendor-supervised maintenance window; scheduled next month.",
     "Pending", None),
    (3, 3, "2026-07-05 08:00:00",
     "SMB signing rollout on the domain controller requires downtime approval from IT Operations.",
     "Rejected", None),
    (4, 1, "2026-07-08 11:00:00",
     "TLS 1.0 is required for a legacy monitoring client until it is upgraded next quarter; "
     "endpoint is not internet-facing.",
     "Approved", "2026-10-06"),
    (5, 5, "2026-07-09 14:20:00",
     "Adding CSP/HSTS headers requires a front-end release; scheduled for the next sprint.",
     "Pending", None),
    (6, 18, "2026-07-06 09:45:00",
     "Requested temporary acceptance for internet-facing RDP during a vendor migration window.",
     "Rejected", None),
    (7, 6, "2026-07-10 13:00:00",
     "Stored XSS fix requires a framework upgrade scheduled for the next release; the affected "
     "profile field is restricted to authenticated internal users.",
     "Pending", None),
]

# 7 patch_history: id, asset_id, action_taken, status, performed_at
# Parallel to `payments`: one transaction per remediation action attempted on an asset.
PATCH_HISTORY = [
    (1, 4, "Applied KB5040430 cumulative update", "Applied", "2026-06-20 22:00:00"),
    (2, 16, "Disabled Jenkins script console anonymous access", "Applied", "2026-07-10 11:00:00"),
    (3, 2, "Attempted openssh-server upgrade via apt", "Failed", "2026-07-09 23:00:00"),
    (4, 1, "Scheduled openssh-server upgrade for next maintenance window", "Applied",
     "2026-07-12 09:00:00"),
    (5, 2, "Retried openssh-server upgrade after dependency fix", "Applied",
     "2026-07-11 20:00:00"),
    (6, 5, "Deployed parameterized queries to /api/orders", "Applied", "2026-07-10 16:30:00"),
    (7, 11, "Attempted firmware-managed credential rotation on fw-edge-01", "Failed",
     "2026-07-11 08:15:00"),
]

# 7 remediation_tickets: id, reporting_user_id, asset_id, title, status, created_at, updated_at
# Parallel to `support_tickets`: attributed to a user and related to one of their assets
# (exactly as the original ticket relates to an order, not to a line item or shipment).
REMEDIATION_TICKETS = [
    (1, 1, 2, "Patch OpenSSH on server-prod-02 (regreSSHion)",
     "In Progress", "2026-07-04 09:00:00", "2026-07-11 20:05:00"),
    (2, 12, 16, "Lock down Jenkins script console",
     "Done", "2026-07-06 15:30:00", "2026-07-10 11:05:00"),
    (3, 1, 1, "Patch OpenSSH pre-auth RCE on server-prod-01",
     "Open", "2026-07-05 10:15:00", None),
    (4, 4, 10, "Disable anonymous FTP access on legacy-ftp-01",
     "In Progress", "2026-07-08 13:40:00", "2026-07-10 16:35:00"),
    (5, 2, 6, "Rotate hardcoded AWS credentials in webapp-portal repo",
     "Open", "2026-07-09 09:00:00", None),
    (6, 4, 3, "Enforce SMB signing on win-dc-01",
     "Open", "2026-07-07 11:20:00", None),
    (7, 18, 18, "Remove internet exposure on vpn-gw-01 RDP",
     "In Progress", "2026-07-11 08:30:00", "2026-07-11 14:00:00"),
]


def main() -> None:
    if DB_PATH.exists():
        DB_PATH.unlink()
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA_SQL)
    cur = conn.cursor()

    # One hash, reused for all 20 users. Intentional: identical demo passwords.
    demo_password_hash = bcrypt.hashpw(
        b"SecurePass1!",
        bcrypt.gensalt(),
    ).decode("utf-8")
    cur.executemany(
        "INSERT INTO users (id, user_id, email, role, department, last_login, password_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        [(*row, demo_password_hash) for row in USERS],
    )
    cur.executemany(
        "INSERT INTO assets (id, asset_tag, name, type, ip_address, mac_address, os, location, owner_user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ASSETS,
    )
    cur.executemany(
        "INSERT INTO findings (id, finding_type, cve_id, title, severity, description, remediation_guide_ref) VALUES (?, ?, ?, ?, ?, ?, ?)",
        FINDINGS,
    )
    cur.executemany(
        "INSERT INTO scans (id, scan_time, scanner_tool, asset_id, status) VALUES (?, ?, ?, ?, ?)",
        SCANS,
    )
    cur.executemany(
        "INSERT INTO scan_results (id, scan_id, finding_id, asset_id, status, comments) VALUES (?, ?, ?, ?, ?, ?)",
        SCAN_RESULTS,
    )
    cur.executemany(
        "INSERT INTO risk_acceptances (id, asset_id, requested_at, justification, status, review_date) VALUES (?, ?, ?, ?, ?, ?)",
        RISK_ACCEPTANCES,
    )
    cur.executemany(
        "INSERT INTO patch_history (id, asset_id, action_taken, status, performed_at) VALUES (?, ?, ?, ?, ?)",
        PATCH_HISTORY,
    )
    cur.executemany(
        "INSERT INTO remediation_tickets (id, reporting_user_id, asset_id, title, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        REMEDIATION_TICKETS,
    )

    conn.commit()
    conn.close()
    print(f"Created {DB_PATH}")


if __name__ == "__main__":
    main()
