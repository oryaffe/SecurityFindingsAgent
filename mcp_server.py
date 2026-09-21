"""
MCP server with streamable HTTP transport.

Exposes the 11 security tools defined in data/TOOLS_LIST.txt.
Connects to database/security.db. Stateless: user_id is passed on every user-scoped call.

Run with: python mcp_server.py
Connect at: http://127.0.0.1:8000/mcp
"""

import functools
import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import bcrypt
from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DB_PATH = Path(__file__).resolve().parent / "database" / "security.db"

mcp = FastMCP("security", host="127.0.0.1", port=8000)

AUTH_FAILURE = "authentication failure"
ACCESS_DENIED = "access denied"


def log_tool_call(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        print(fn.__name__)
        return fn(*args, **kwargs)

    return wrapper


@contextmanager
def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _as_json(value) -> str:
    return json.dumps(value, default=str)


def _row_dict(row: sqlite3.Row) -> dict:
    return dict(row)


def _owned_asset(conn: sqlite3.Connection, user_id: int, asset_name: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id, name FROM assets WHERE name = ? AND owner_user_id = ?",
        (asset_name, user_id),
    ).fetchone()


@mcp.tool()
@log_tool_call
def lookup_user_by_email(email: str) -> str:
    """Finds the user by the email provided at the beginning of the conversation and resolves the internal user identifier used throughout the session."""
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT
                id AS user_id,
                users.user_id AS employee_user_id,
                email,
                role,
                department,
                last_login
            FROM users
            WHERE email = ?
            """,
            (email,),
        ).fetchone()
    if row is None:
        return AUTH_FAILURE
    return _as_json(_row_dict(row))


@mcp.tool()
@log_tool_call
def verify_user_credentials(email: str, password: str) -> str:
    """Verifies an email + password pair for authentication. Returns the
    user identity on success; returns authentication failure otherwise."""
    normalized = email.strip().lower()
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT
                id AS user_id,
                users.user_id AS employee_user_id,
                email,
                role,
                department,
                last_login,
                password_hash
            FROM users
            WHERE lower(trim(email)) = ?
            """,
            (normalized,),
        ).fetchone()
    if row is None:
        return AUTH_FAILURE
    stored_hash = row["password_hash"]
    try:
        matched = bcrypt.checkpw(
            password.encode("utf-8"),
            stored_hash.encode("utf-8"),
        )
    except Exception:
        return AUTH_FAILURE
    if not matched:
        return AUTH_FAILURE
    return _as_json(
        {
            "user_id": row["user_id"],
            "employee_user_id": row["employee_user_id"],
            "email": row["email"],
            "role": row["role"],
            "department": row["department"],
            "last_login": row["last_login"],
        }
    )


@mcp.tool()
@log_tool_call
def get_user_assets(user_id: int) -> str:
    """Returns all assets assigned to the current user."""
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT asset_tag, name, type, ip_address, mac_address, os, location
            FROM assets
            WHERE owner_user_id = ?
            """,
            (user_id,),
        ).fetchall()
    return _as_json([_row_dict(r) for r in rows])


@mcp.tool()
@log_tool_call
def get_asset_details(user_id: int, asset_name: str) -> str:
    """Returns detailed information about one specific asset owned by the current user."""
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT asset_tag, name, type, ip_address, mac_address, os, location
            FROM assets
            WHERE name = ? AND owner_user_id = ?
            """,
            (asset_name, user_id),
        ).fetchone()
    if row is None:
        return ACCESS_DENIED
    return _as_json(_row_dict(row))


@mcp.tool()
@log_tool_call
def get_finding_details(
    cve_id: str | None = None,
    finding_type: str | None = None,
    severity: str | None = None,
) -> str:
    """Searches the shared Findings catalog and returns general information about security findings."""
    clauses: list[str] = []
    params: list[str] = []
    if cve_id:
        clauses.append("cve_id = ?")
        params.append(cve_id)
    if finding_type:
        clauses.append("finding_type = ?")
        params.append(finding_type)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)

    query = """
        SELECT finding_type, cve_id, title, severity, description, remediation_guide_ref
        FROM findings
    """
    if clauses:
        query += " WHERE " + " AND ".join(clauses)

    with _connect() as conn:
        rows = conn.execute(query, params).fetchall()
    return _as_json([_row_dict(r) for r in rows])


@mcp.tool()
@log_tool_call
def get_asset_scans(user_id: int, asset_name: str) -> str:
    """Returns scan executions performed against a specific asset owned by the current user."""
    with _connect() as conn:
        asset = _owned_asset(conn, user_id, asset_name)
        if asset is None:
            return ACCESS_DENIED
        rows = conn.execute(
            """
            SELECT id AS scan_id, scan_time, scanner_tool, status
            FROM scans
            WHERE asset_id = ?
            """,
            (asset["id"],),
        ).fetchall()
    return _as_json([_row_dict(r) for r in rows])


@mcp.tool()
@log_tool_call
def get_asset_scan_results(user_id: int, asset_name: str) -> str:
    """Returns the findings detected on a specific asset together with their remediation status and finding information."""
    with _connect() as conn:
        asset = _owned_asset(conn, user_id, asset_name)
        if asset is None:
            return ACCESS_DENIED
        rows = conn.execute(
            """
            SELECT
                sr.scan_id,
                sr.status,
                sr.comments,
                f.finding_type,
                f.cve_id,
                f.title,
                f.severity
            FROM scan_results sr
            JOIN findings f ON sr.finding_id = f.id
            WHERE sr.asset_id = ?
            """,
            (asset["id"],),
        ).fetchall()
    return _as_json([_row_dict(r) for r in rows])


@mcp.tool()
@log_tool_call
def get_asset_risk_acceptances(user_id: int, asset_name: str) -> str:
    """Returns existing risk-acceptance records associated with a specific asset owned by the current user."""
    with _connect() as conn:
        asset = _owned_asset(conn, user_id, asset_name)
        if asset is None:
            return ACCESS_DENIED
        rows = conn.execute(
            """
            SELECT requested_at, justification, status, review_date
            FROM risk_acceptances
            WHERE asset_id = ?
            """,
            (asset["id"],),
        ).fetchall()
    return _as_json([_row_dict(r) for r in rows])


@mcp.tool()
@log_tool_call
def get_asset_patch_history(user_id: int, asset_name: str) -> str:
    """Returns remediation actions that were previously performed or attempted on a specific asset."""
    with _connect() as conn:
        asset = _owned_asset(conn, user_id, asset_name)
        if asset is None:
            return ACCESS_DENIED
        rows = conn.execute(
            """
            SELECT action_taken, status, performed_at
            FROM patch_history
            WHERE asset_id = ?
            """,
            (asset["id"],),
        ).fetchall()
    return _as_json([_row_dict(r) for r in rows])


@mcp.tool()
@log_tool_call
def get_user_remediation_tickets(
    user_id: int,
    asset_name: str | None = None,
) -> str:
    """Returns remediation tickets attributed to the current user,
    optionally filtered to a specific owned asset."""

    with _connect() as conn:
        if asset_name:
            asset = _owned_asset(conn, user_id, asset_name)

            if asset is None:
                return ACCESS_DENIED

            rows = conn.execute(
                """
                SELECT
                    rt.id AS ticket_id,
                    a.name AS asset_name,
                    rt.title,
                    rt.status,
                    rt.created_at,
                    rt.updated_at
                FROM remediation_tickets rt
                JOIN assets a ON rt.asset_id = a.id
                WHERE rt.reporting_user_id = ?
                  AND rt.asset_id = ?
                """,
                (user_id, asset["id"]),
            ).fetchall()

        else:
            rows = conn.execute(
                """
                SELECT
                    rt.id AS ticket_id,
                    a.name AS asset_name,
                    rt.title,
                    rt.status,
                    rt.created_at,
                    rt.updated_at
                FROM remediation_tickets rt
                JOIN assets a ON rt.asset_id = a.id
                WHERE rt.reporting_user_id = ?
                """,
                (user_id,),
            ).fetchall()

    return _as_json([_row_dict(r) for r in rows])


@mcp.tool()
@log_tool_call
def open_remediation_ticket(user_id: int, asset_name: str, title: str) -> str:
    """Creates a new remediation ticket for an asset owned by the current user."""
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with _connect() as conn:
        asset = _owned_asset(conn, user_id, asset_name)
        if asset is None:
            return ACCESS_DENIED
        cursor = conn.execute(
            """
            INSERT INTO remediation_tickets (
                reporting_user_id, asset_id, title, status, created_at, updated_at
            )
            VALUES (?, ?, ?, 'Open', ?, NULL)
            """,
            (user_id, asset["id"], title, created_at),
        )
        conn.commit()
        ticket_id = cursor.lastrowid
    return _as_json(
        {
            "ticket_id": ticket_id,
            "asset_name": asset["name"],
            "title": title,
            "status": "Open",
            "created_at": created_at,
        }
    )


if __name__ == "__main__":
    logger.info("MCP server starting at http://127.0.0.1:8000/mcp")
    mcp.run(transport="streamable-http")
