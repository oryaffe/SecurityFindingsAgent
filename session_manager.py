"""Per-session conversation history for an already authenticated user."""

from __future__ import annotations

from typing import Any

MAX_HISTORY_MESSAGES = 20  # 10 user + 10 assistant


class ChatSession:
    """Conversation state for one authenticated chat session.

    Histories are not shared across sessions. Only normal user/assistant
    messages are kept (no tool calls or tool results), capped at the last 20.
    """

    def __init__(
        self,
        session_id: str,
        authenticated_user_id: Any,
        authenticated_email: str,
    ) -> None:
        self.session_id = session_id
        self.authenticated_user_id = authenticated_user_id
        self.authenticated_email = authenticated_email
        self.history: list[dict[str, Any]] = []

    def add_turn(self, user_text: str, assistant_text: str) -> None:
        self.history.append({"role": "user", "content": user_text})
        self.history.append({"role": "assistant", "content": assistant_text})
        overflow = len(self.history) - MAX_HISTORY_MESSAGES
        if overflow > 0:
            self.history = self.history[overflow:]
        while self.history and self.history[0]["role"] != "user":
            self.history.pop(0)

    def clear_history(self) -> None:
        """Drop all conversation messages for this session."""
        self.history.clear()


_sessions: dict[str, ChatSession] = {}


def create_chat_session(
    session_id: str,
    authenticated_user_id: Any,
    authenticated_email: str,
) -> ChatSession:
    """Create an isolated chat session for an already authenticated user."""
    chat = ChatSession(
        session_id,
        authenticated_user_id,
        authenticated_email,
    )
    _sessions[session_id] = chat
    return chat


def get_chat_session(session_id: str) -> ChatSession | None:
    """Return a tracked chat session, or ``None`` if it is not registered."""
    return _sessions.get(session_id)


def destroy_chat_session(session_id: str) -> None:
    """Remove a session from memory and clear its conversation history."""
    chat = _sessions.pop(session_id, None)
    if chat is not None:
        chat.clear_history()
