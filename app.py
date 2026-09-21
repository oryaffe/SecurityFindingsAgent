"""
FastAPI Web UI for the Vulnerability & Exposure Support Agent.

Serves a plain HTML chat page and a WebSocket endpoint. HTTP ``POST /auth/login``
issues a JWT after email + password verification via MCP. Each WebSocket
connection authenticates with that JWT as its first message, then gets its
own ChatSession. Intermediate agent events are streamed only when the client
has enabled Show Thinking.

The CLI in main.py authenticates with email + password and does not use JWTs.

Environment:
  ANTHROPIC_API_KEY         Required for the chat agent
  ANTHROPIC_MODEL           Optional (default: claude-haiku-4-5-20251001)
  JWT_SECRET                Required for Web JWT signing
  JWT_EXPIRE_MINUTES        Optional (default: 480)

Run (use a port other than the MCP server, which defaults to 8000):
  uvicorn app:app --reload --port 8080
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from collections import deque
from contextlib import AsyncExitStack, asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from mcp.client.session import ClientSession
from pydantic import BaseModel

from auth import (
    TokenError,
    authenticate_user,
    create_access_token,
    decode_access_token,
)
from mcp_client import CONFIG_PATH, load_server_config, open_transport
from security_agent_core import prepare_agent_tools, process_authenticated_message
from session_manager import (
    ChatSession,
    create_chat_session,
    destroy_chat_session,
    get_chat_session,
)

logger = logging.getLogger("security_agent_web")

WEB_DIR = Path(__file__).resolve().parent / "web"
MAX_ACTIVE_SESSIONS = 5
WAITING_FOR_AUTHENTICATION = "WAITING_FOR_AUTHENTICATION"
AUTHENTICATED = "AUTHENTICATED"

SESSION_LIMIT_MESSAGE = (
    "Maximum of 5 concurrent sessions reached. Please try again later."
)
GENERIC_ERROR_MESSAGE = "An unexpected error occurred. Please try again."
MCP_UNAVAILABLE_MESSAGE = (
    "The security tools service is unavailable. Please try again."
)
LLM_UNAVAILABLE_MESSAGE = (
    "The language model service is unavailable. Please try again."
)
AUTH_FAILED_MESSAGE = "Authentication failed or expired."
AUTH_TIMEOUT_MESSAGE = "Authentication timeout. Please try again."
HTTP_AUTH_FAILED_DETAIL = "Authentication failed"
RATE_LIMIT_DETAIL = "Too many login attempts. Try again later."
LOGIN_WINDOW_SECONDS = 60
MAX_FAILURES_PER_EMAIL = 5
MAX_FAILURES_PER_IP = 20
CLOSE_AUTH_FAILED = 4401
CLOSE_AUTH_TIMEOUT = 4408
CLOSE_SESSION_LIMIT = 1013
CLOSE_INTERNAL_ERROR = 1011
WS_AUTH_TIMEOUT_SECONDS = 5.0


class SessionSlots:
    """Asyncio-safe cap on authenticated Web sessions."""

    def __init__(self, limit: int = MAX_ACTIVE_SESSIONS) -> None:
        self._semaphore = asyncio.Semaphore(limit)
        self._lock = asyncio.Lock()

    async def try_acquire(self) -> bool:
        async with self._lock:
            if self._semaphore.locked():
                return False
            await self._semaphore.acquire()
            return True

    def release(self) -> None:
        self._semaphore.release()


class ConnectionState:
    """Per-WebSocket application state. Never shared across connections."""

    def __init__(self, websocket: WebSocket) -> None:
        self.websocket = websocket
        self.phase = WAITING_FOR_AUTHENTICATION
        self.chat: ChatSession | None = None
        self.session_id: str | None = None
        self.show_thinking = False
        self.request_lock = asyncio.Lock()
        self.slot_acquired = False
        self.token_exp: datetime | None = None


_session_slots = SessionSlots()
_active_sessions: dict[str, ConnectionState] = {}
_registry_lock = asyncio.Lock()
_login_failures: dict[str, deque[float]] = {}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    load_dotenv()
    if not os.environ.get("ANTHROPIC_API_KEY"):
        logger.warning("ANTHROPIC_API_KEY is not set; chat requests will fail.")
    if not os.environ.get("JWT_SECRET", "").strip():
        logger.warning("JWT_SECRET is not set; Web login will fail.")
    yield


app = FastAPI(title="Vulnerability & Exposure Support Agent", lifespan=lifespan)


class LoginRequest(BaseModel):
    """Login body. ``password`` has no min_length so an empty string yields 401."""

    email: str
    password: str


@asynccontextmanager
async def open_mcp_client():
    """Open a short-lived MCP session for login lookup only."""
    config = load_server_config(CONFIG_PATH)
    async with open_transport(config) as (read_stream, write_stream, _session_id):
        async with ClientSession(read_stream, write_stream) as mcp_session:
            await mcp_session.initialize()
            yield mcp_session


@asynccontextmanager
async def open_mcp_session():
    """Open an isolated MCP client session for one WebSocket connection."""
    config = load_server_config(CONFIG_PATH)
    async with open_transport(config) as (read_stream, write_stream, _session_id):
        async with ClientSession(read_stream, write_stream) as mcp_session:
            await mcp_session.initialize()
            tools_result = await mcp_session.list_tools()
            yield mcp_session, prepare_agent_tools(tools_result)


async def close_with_auth_error(
    websocket: WebSocket,
    code: int,
    message: str,
) -> None:
    try:
        await send_json(websocket, {"type": "auth_error", "message": message})
    except Exception:
        logger.debug("Could not send auth_error before close")
    try:
        await websocket.close(code=code)
    except Exception:
        pass


def token_has_expired(state: ConnectionState) -> bool:
    if state.token_exp is None:
        return False
    return datetime.now(timezone.utc) >= state.token_exp


async def send_json(websocket: WebSocket, payload: dict[str, Any]) -> None:
    await websocket.send_json(payload)


async def send_error(websocket: WebSocket, message: str) -> None:
    await send_json(websocket, {"type": "error", "message": message})


def _exception_text(exc: BaseException) -> str:
    """Flatten ExceptionGroup-style errors into one log line."""
    parts = [f"{type(exc).__name__}: {exc}"]
    inner = getattr(exc, "exceptions", None)
    if inner:
        for item in inner:
            parts.append(_exception_text(item))
    return " | ".join(parts)


def user_facing_error(exc: BaseException) -> str:
    """Map internal exceptions to a safe browser message. No stack traces."""
    text = _exception_text(exc).lower()
    if "anthropic" in text or "apistatus" in text or "apiconnection" in text:
        return LLM_UNAVAILABLE_MESSAGE
    if "mcp" in text or "connect" in text or "timeout" in text:
        return MCP_UNAVAILABLE_MESSAGE
    return GENERIC_ERROR_MESSAGE


async def register_session(session_id: str, state: ConnectionState) -> None:
    async with _registry_lock:
        _active_sessions[session_id] = state


async def unregister_session(session_id: str | None) -> None:
    if not session_id:
        return
    async with _registry_lock:
        _active_sessions.pop(session_id, None)
    destroy_chat_session(session_id)


async def cleanup_connection(state: ConnectionState) -> None:
    """Release ChatSession, history, registry entry, and session slot."""
    session_id = state.session_id
    if session_id:
        await unregister_session(session_id)
        logger.info("Cleaned up session %s", session_id)
    if state.slot_acquired:
        _session_slots.release()
        state.slot_acquired = False
    state.chat = None
    state.session_id = None
    state.token_exp = None
    state.phase = WAITING_FOR_AUTHENTICATION


def make_event_sink(state: ConnectionState):
    """Forward intermediate agent events only when Show Thinking is enabled."""

    async def sink(event_type: str, data: dict[str, Any]) -> None:
        if not state.show_thinking:
            return
        try:
            await send_json(state.websocket, {"type": event_type, **data})
        except Exception:
            logger.debug("Could not forward %s event to client", event_type)

    return sink


async def handle_jwt_auth(
    websocket: WebSocket,
    state: ConnectionState,
    payload: dict[str, Any],
) -> bool:
    """Validate the first-message JWT and create an isolated ChatSession.

    Returns True when the connection is authenticated and should stay open.
    """
    if state.phase == AUTHENTICATED:
        await send_error(websocket, "Already authenticated.")
        return True

    token = payload.get("token")
    if not isinstance(token, str) or not token.strip():
        await close_with_auth_error(
            websocket, CLOSE_AUTH_FAILED, AUTH_FAILED_MESSAGE
        )
        return False

    try:
        claims = decode_access_token(token)
    except TokenError:
        logger.info("WebSocket JWT rejected")
        await close_with_auth_error(
            websocket, CLOSE_AUTH_FAILED, AUTH_FAILED_MESSAGE
        )
        return False
    except Exception:
        logger.exception("Unexpected JWT validation error")
        await close_with_auth_error(
            websocket, CLOSE_AUTH_FAILED, AUTH_FAILED_MESSAGE
        )
        return False

    acquired = await _session_slots.try_acquire()
    if not acquired:
        logger.info("Rejected authenticated connection: session limit reached")
        await send_error(websocket, SESSION_LIMIT_MESSAGE)
        try:
            await websocket.close(code=CLOSE_SESSION_LIMIT)
        except Exception:
            pass
        return False

    session_id = str(uuid.uuid4())
    try:
        chat = create_chat_session(
            session_id,
            claims.user_id,
            claims.email,
        )
        state.chat = chat
        state.session_id = session_id
        state.token_exp = claims.exp
        state.slot_acquired = True
        state.phase = AUTHENTICATED
        await register_session(session_id, state)
    except Exception:
        _session_slots.release()
        state.slot_acquired = False
        logger.exception("Failed to create chat session")
        await send_error(websocket, GENERIC_ERROR_MESSAGE)
        try:
            await websocket.close(code=CLOSE_INTERNAL_ERROR)
        except Exception:
            pass
        return False

    await send_json(
        websocket,
        {
            "type": "auth_success",
            "session_id": session_id,
            "email": claims.email,
        },
    )
    logger.info("Authenticated session %s for %s", session_id, claims.email)
    return True


async def handle_user_message(
    websocket: WebSocket,
    state: ConnectionState,
    payload: dict[str, Any],
    mcp_session: ClientSession,
    agent_tools: list[dict[str, Any]],
) -> None:
    if state.phase != AUTHENTICATED or state.chat is None:
        await close_with_auth_error(
            websocket, CLOSE_AUTH_FAILED, AUTH_FAILED_MESSAGE
        )
        return

    if token_has_expired(state):
        logger.info("JWT expired during session %s", state.session_id)
        await close_with_auth_error(
            websocket, CLOSE_AUTH_FAILED, AUTH_FAILED_MESSAGE
        )
        return

    content = payload.get("content")
    if not isinstance(content, str) or not content.strip():
        await send_error(websocket, "Message cannot be empty.")
        return

    user_message_id = payload.get("message_id")
    if not isinstance(user_message_id, str) or not user_message_id.strip():
        user_message_id = str(uuid.uuid4())

    if state.request_lock.locked():
        await send_error(
            websocket,
            "A request is already being processed. Please wait.",
        )
        return

    async with state.request_lock:
        try:
            answer = await process_authenticated_message(
                mcp_session,
                agent_tools,
                content.strip(),
                state.chat,
                event_callback=make_event_sink(state),
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception(
                "Agent request failed for session %s", state.session_id
            )
            await send_error(websocket, user_facing_error(exc))
            return

        await send_json(
            websocket,
            {
                "type": "final",
                "message_id": str(uuid.uuid4()),
                "reply_to": user_message_id,
                "content": answer,
            },
        )


async def handle_thinking(
    websocket: WebSocket,
    state: ConnectionState,
    payload: dict[str, Any],
) -> None:
    if state.phase != AUTHENTICATED:
        await close_with_auth_error(
            websocket, CLOSE_AUTH_FAILED, AUTH_FAILED_MESSAGE
        )
        return
    enabled = payload.get("enabled")
    if not isinstance(enabled, bool):
        await send_error(websocket, "Thinking toggle requires enabled: true or false.")
        return
    state.show_thinking = enabled


async def handle_disconnect(websocket: WebSocket, state: ConnectionState) -> None:
    try:
        await send_json(
            websocket,
            {"type": "disconnected", "message": "Session closed."},
        )
    except Exception:
        logger.debug("Could not send disconnect acknowledgement")
    await cleanup_connection(state)
    try:
        await websocket.close(code=1000)
    except Exception:
        pass


@app.get("/")
async def serve_index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


@app.get("/index.html")
async def serve_index_alias() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


def _client_ip(request: Request) -> str:
    if request.client is None:
        return "unknown"
    return request.client.host or "unknown"


def _login_bucket_keys(ip: str, email: str) -> tuple[str, str]:
    return f"{ip}:{email}", ip


def _prune_login_bucket(key: str, now: float) -> deque[float]:
    bucket = _login_failures.get(key)
    if bucket is None:
        empty: deque[float] = deque()
        return empty
    cutoff = now - LOGIN_WINDOW_SECONDS
    while bucket and bucket[0] <= cutoff:
        bucket.popleft()
    if not bucket:
        _login_failures.pop(key, None)
        empty: deque[float] = deque()
        return empty
    return bucket


def login_is_rate_limited(ip: str, email: str) -> bool:
    now = time.monotonic()
    email_key, ip_key = _login_bucket_keys(ip, email)
    if len(_prune_login_bucket(email_key, now)) >= MAX_FAILURES_PER_EMAIL:
        return True
    if len(_prune_login_bucket(ip_key, now)) >= MAX_FAILURES_PER_IP:
        return True
    return False


def record_login_failure(ip: str, email: str) -> None:
    now = time.monotonic()
    for key in _login_bucket_keys(ip, email):
        _prune_login_bucket(key, now)
        bucket = _login_failures.get(key)
        if bucket is None:
            bucket = deque()
            _login_failures[key] = bucket
        bucket.append(now)


def clear_login_failures(ip: str, email: str) -> None:
    email_key, ip_key = _login_bucket_keys(ip, email)
    _login_failures.pop(email_key, None)
    _login_failures.pop(ip_key, None)


@app.post("/auth/login")
async def login(request: Request, body: LoginRequest) -> dict[str, Any]:
    """Authenticate by email and password and return a signed JWT."""
    email = (body.email or "").strip().lower()
    client_ip = _client_ip(request)

    if login_is_rate_limited(client_ip, email):
        logger.warning("Login rate-limited for %s from %s", email, client_ip)
        raise HTTPException(status_code=429, detail=RATE_LIMIT_DETAIL)

    try:
        async with open_mcp_client() as mcp_session:
            auth_result = await authenticate_user(
                mcp_session, email, body.password
            )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Login MCP lookup failed: %s", _exception_text(exc))
        raise HTTPException(status_code=503, detail=MCP_UNAVAILABLE_MESSAGE) from exc

    if not auth_result.success:
        record_login_failure(client_ip, email)
        logger.warning("Authentication failure for %s from %s", email, client_ip)
        raise HTTPException(status_code=401, detail=HTTP_AUTH_FAILED_DETAIL)

    clear_login_failures(client_ip, email)
    logger.info("Successful login for %s from %s", email, client_ip)

    try:
        token, expires_in = create_access_token(
            auth_result.user_id,
            auth_result.email,
        )
    except Exception:
        logger.exception("Failed to issue JWT")
        raise HTTPException(status_code=500, detail=GENERIC_ERROR_MESSAGE)

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": expires_in,
    }


async def _cancel_task(task: asyncio.Task[Any] | None) -> None:
    if task is None or task.done():
        return
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):
        pass


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await websocket.accept()
    state = ConnectionState(websocket)

    incoming: asyncio.Queue[str | None] = asyncio.Queue()
    reader_task: asyncio.Task[Any] | None = None
    agent_task: asyncio.Task[Any] | None = None
    mcp_session: ClientSession | None = None
    agent_tools: list[dict[str, Any]] = []

    async def reader() -> None:
        try:
            while True:
                text = await websocket.receive_text()
                await incoming.put(text)
        except WebSocketDisconnect:
            await incoming.put(None)
        except Exception:
            await incoming.put(None)

    async def ensure_mcp(stack: AsyncExitStack) -> bool:
        nonlocal mcp_session, agent_tools
        if mcp_session is not None:
            return True
        try:
            mcp_session, agent_tools = await stack.enter_async_context(
                open_mcp_session()
            )
            return True
        except Exception as exc:
            logger.warning("MCP connection failed: %s", _exception_text(exc))
            await send_error(websocket, MCP_UNAVAILABLE_MESSAGE)
            return False

    try:
        try:
            first_raw = await asyncio.wait_for(
                websocket.receive_text(),
                timeout=WS_AUTH_TIMEOUT_SECONDS,
            )
        except TimeoutError:
            logger.info("WebSocket authentication timed out")
            await close_with_auth_error(
                websocket, CLOSE_AUTH_TIMEOUT, AUTH_TIMEOUT_MESSAGE
            )
            return
        except WebSocketDisconnect:
            return

        try:
            first_payload = json.loads(first_raw)
        except json.JSONDecodeError:
            await close_with_auth_error(
                websocket, CLOSE_AUTH_FAILED, AUTH_FAILED_MESSAGE
            )
            return

        if not isinstance(first_payload, dict) or first_payload.get("type") != "auth":
            await close_with_auth_error(
                websocket, CLOSE_AUTH_FAILED, AUTH_FAILED_MESSAGE
            )
            return

        if not await handle_jwt_auth(websocket, state, first_payload):
            return

        async with AsyncExitStack() as stack:
            reader_task = asyncio.create_task(reader())
            while True:
                raw_text = await incoming.get()
                if raw_text is None:
                    logger.info(
                        "WebSocket disconnected (session %s)",
                        state.session_id or "unauthenticated",
                    )
                    break

                try:
                    payload = json.loads(raw_text)
                except json.JSONDecodeError:
                    await send_error(websocket, "Invalid JSON message.")
                    continue

                if not isinstance(payload, dict):
                    await send_error(websocket, "Invalid JSON message.")
                    continue

                message_type = payload.get("type")
                if not message_type:
                    await send_error(websocket, "Missing message type.")
                    continue

                if message_type == "thinking":
                    await handle_thinking(websocket, state, payload)
                    continue

                if message_type == "disconnect":
                    await _cancel_task(agent_task)
                    await handle_disconnect(websocket, state)
                    return

                if message_type == "user_message":
                    if token_has_expired(state):
                        logger.info(
                            "JWT expired during session %s", state.session_id
                        )
                        await _cancel_task(agent_task)
                        await close_with_auth_error(
                            websocket, CLOSE_AUTH_FAILED, AUTH_FAILED_MESSAGE
                        )
                        return
                    if not await ensure_mcp(stack) or mcp_session is None:
                        continue
                    if agent_task is not None and not agent_task.done():
                        await send_error(
                            websocket,
                            "A request is already being processed. Please wait.",
                        )
                        continue
                    agent_task = asyncio.create_task(
                        handle_user_message(
                            websocket,
                            state,
                            payload,
                            mcp_session,
                            agent_tools,
                        )
                    )
                    continue

                if message_type == "auth":
                    await send_error(websocket, "Already authenticated.")
                    continue

                await send_error(websocket, "Unsupported message type.")
    except WebSocketDisconnect:
        logger.info(
            "WebSocket disconnected (session %s)",
            state.session_id or "unauthenticated",
        )
    except Exception as exc:
        logger.warning("WebSocket session ended: %s", _exception_text(exc))
        try:
            await send_error(websocket, user_facing_error(exc))
        except Exception:
            pass
        try:
            await websocket.close(code=CLOSE_INTERNAL_ERROR)
        except Exception:
            pass
    finally:
        await _cancel_task(agent_task)
        await _cancel_task(reader_task)
        await cleanup_connection(state)


def active_session_count() -> int:
    """Test helper: number of authenticated Web sessions currently registered."""
    return len(_active_sessions)


def session_is_registered(session_id: str) -> bool:
    """Test helper: whether a session_id is still in the in-memory registry."""
    return session_id in _active_sessions and get_chat_session(session_id) is not None
