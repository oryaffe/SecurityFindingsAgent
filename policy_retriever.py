"""Retrieve relevant cyber security policy documents from ChromaDB."""

from __future__ import annotations

import logging
import os
import warnings

os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")

logging.getLogger("huggingface_hub").setLevel(logging.ERROR)
logging.getLogger("transformers").setLevel(logging.ERROR)
logging.getLogger("sentence_transformers").setLevel(logging.ERROR)

warnings.filterwarnings(
    "ignore",
    message=".*unauthenticated requests to the HF Hub.*",
)

from pathlib import Path
from typing import Any

import chromadb
from sentence_transformers import SentenceTransformer

CHROMA_DB_PATH = Path(__file__).parent / "chroma_db"
TOP_K = 5
COLLECTION_NAME = "security_policies"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

_collection: Any = None
_embedding_model: SentenceTransformer | None = None


def init_retriever() -> tuple[Any, SentenceTransformer]:
    """Initialize the ChromaDB collection and embedding model (once)."""
    global _collection, _embedding_model
    if _collection is None or _embedding_model is None:
        chroma_client = chromadb.PersistentClient(path=str(CHROMA_DB_PATH))
        _collection = chroma_client.get_collection(name=COLLECTION_NAME)
        _embedding_model = SentenceTransformer(EMBEDDING_MODEL)
    return _collection, _embedding_model


def retrieve_policy_context(question: str, top_k: int = TOP_K) -> str:
    """Embed the question, retrieve top policy documents, and return formatted context."""
    collection, embedding_model = init_retriever()
    query_vector = embedding_model.encode(question).tolist()

    results = collection.query(
        query_embeddings=[query_vector],
        n_results=top_k,
        include=["documents", "metadatas"],
    )

    documents: list[str] = results["documents"][0] if results["documents"] else []
    metadatas: list[dict] = results["metadatas"][0] if results["metadatas"] else []

    if not documents:
        return "No relevant policies found."

    sections: list[str] = []
    for index, (doc_text, metadata) in enumerate(zip(documents, metadatas), start=1):
        title = metadata.get("title", f"Policy {index}")
        sections.append(f"--- Policy {index}: {title} ---\n{doc_text}")

    return "\n\n".join(sections)
