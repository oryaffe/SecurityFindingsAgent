"""Email + password authentication via the MCP verify_user_credentials tool.

Web/API identity is issued as a signed JWT after a successful verification.
CLI authentication continues to use ``authenticate_user`` directly.
Password hashes are verified only inside the MCP server; this module never
sees or compares them.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from dotenv import load_dotenv
from mcp.client.session import ClientSession

from mcp_client import call_tool

LOOKUP_TOOL = "lookup_user_by_email"
VERIFY_TOOL = "verify_user_credentials"
JWT_ALGORITHM = "HS256"
DEFAULT_JWT_EXPIRE_MINUTES = 480
AUTH_FAILURE_MESSAGE = (
    "Authentication failed. No employee matches that email. "
    "Please check the email or try another one."
)
AUTH_SUCCESS_MESSAGE = (
    "Authentication succeeded. You are identified and can continue."
)
MISSING_EMAIL_MESSAGE = (
    "Please provide your organizational email address before continuing."
)


@dataclass
class AuthResult:
    success: bool
    user_id: Any = None
    message: str = ""
    email: str | None = None


@dataclass
class TokenClaims:
    user_id: Any
    email: str
    exp: datetime


class TokenError(Exception):
    """JWT is missing, malformed, expired, or has an invalid signature."""


def user_id_from_lookup_result(result_str: str) -> Any:
    """Return ``user_id`` from a successful ``lookup_user_by_email`` payload, else ``None``."""
    try:
        data = json.loads(result_str)
    except json.JSONDecodeError:
        return None
    if isinstance(data, dict) and "user_id" in data:
        return data["user_id"]
    return None


async def authenticate_user(
    mcp_session: ClientSession,
    user_input: str,
    password: str,
) -> AuthResult:
    """Identify the user by email and password through the MCP verify tool."""
    email = user_input.strip().lower()
    if "@" not in email:
        return AuthResult(success=False, message=MISSING_EMAIL_MESSAGE)
    if not password:
        return AuthResult(success=False, message=AUTH_FAILURE_MESSAGE)

    result_str = await call_tool(
        mcp_session,
        VERIFY_TOOL,
        {"email": email, "password": password},
    )
    user_id = user_id_from_lookup_result(result_str)
    if user_id is None:
        return AuthResult(success=False, message=AUTH_FAILURE_MESSAGE)

    return AuthResult(
        success=True,
        user_id=user_id,
        email=email,
        message=AUTH_SUCCESS_MESSAGE,
    )


def jwt_expire_minutes() -> int:
    raw = os.environ.get("JWT_EXPIRE_MINUTES", str(DEFAULT_JWT_EXPIRE_MINUTES))
    try:
        minutes = int(raw)
    except (TypeError, ValueError):
        minutes = DEFAULT_JWT_EXPIRE_MINUTES
    return minutes if minutes > 0 else DEFAULT_JWT_EXPIRE_MINUTES


def get_jwt_secret() -> str:
    secret = os.environ.get("JWT_SECRET", "").strip()
    if not secret:
        load_dotenv()
        secret = os.environ.get("JWT_SECRET", "").strip()
    if not secret:
        raise RuntimeError("JWT_SECRET is not set")
    return secret


def user_id_from_sub(sub: str) -> Any:
    """Restore a numeric MCP user_id when ``sub`` is an integer string."""
    if sub.isdigit():
        return int(sub)
    return sub


def create_access_token(user_id: Any, email: str) -> tuple[str, int]:
    """Return ``(jwt, expires_in_seconds)`` for an already authenticated user."""
    now = datetime.now(timezone.utc)
    expires_in = jwt_expire_minutes() * 60
    payload = {
        "sub": str(user_id),
        "email": email,
        "iat": now,
        "exp": now + timedelta(seconds=expires_in),
    }
    token = jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)
    if isinstance(token, bytes):
        token = token.decode("ascii")
    return token, expires_in


def decode_access_token(token: str) -> TokenClaims:
    """Validate HS256 signature and expiration; raise ``TokenError`` on failure."""
    if not token or not token.strip():
        raise TokenError("missing")
    try:
        payload = jwt.decode(
            token.strip(),
            get_jwt_secret(),
            algorithms=[JWT_ALGORITHM],
            options={"require": ["sub", "email", "exp", "iat"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("expired") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError("invalid") from exc

    sub = payload.get("sub")
    email = payload.get("email")
    exp = payload.get("exp")
    if not isinstance(sub, str) or not sub:
        raise TokenError("invalid")
    if not isinstance(email, str) or not email:
        raise TokenError("invalid")
    if not isinstance(exp, (int, float)):
        raise TokenError("invalid")

    return TokenClaims(
        user_id=user_id_from_sub(sub),
        email=email,
        exp=datetime.fromtimestamp(exp, tz=timezone.utc),
    )
