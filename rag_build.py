"""Build the RAG knowledge-base index in ChromaDB from policy documents."""

import re
from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer

# --- הגדרת משתנים ---
KB_PATH = Path(__file__).parent / "data" / "01_knowledge_base_documents.md"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"
COLLECTION_NAME = "security_policies"
CHROMA_DB_PATH = Path(__file__).parent / "chroma_db"

DOCUMENT_HEADER = re.compile(r"^## Document (\d+):\s*(.+)$", re.MULTILINE)
SHORT_DESC_PATTERN = re.compile(
    r"\*\*Short description:\*\*\s*\n(.+?)(?=\n\n\*\*Policy content:\*\*)",
    re.DOTALL,
)


def load_split(kb_path: Path = KB_PATH) -> list[dict]:
    """טעינת קובץ ה-KB וחלוקה למסמכים נפרדים."""
    text = kb_path.read_text(encoding="utf-8")
    headers = list(DOCUMENT_HEADER.finditer(text))

    documents: list[dict] = []
    for index, match in enumerate(headers):
        doc_number = int(match.group(1))
        title = match.group(2).strip()
        start = match.start()
        end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
        section = text[start:end].strip()

        desc_match = SHORT_DESC_PATTERN.search(section)
        short_description = (
            desc_match.group(1).strip().replace("\n", " ") if desc_match else ""
        )

        documents.append(
            {
                "doc_number": doc_number,
                "title": title,
                "short_description": short_description,
                "content": section,
            }
        )

    return documents


def embedding(documents: list[dict], model_name: str = EMBEDDING_MODEL) -> list[list[float]]:
    """שליחת המסמכים ל-embedding — מחזיר רשימת וקטורים."""
    model = SentenceTransformer(model_name)
    texts = [doc["content"] for doc in documents]
    vectors = model.encode(texts, show_progress_bar=True)
    return vectors.tolist()


def prepare_data(
    documents: list[dict],
    embeddings: list[list[float]],
) -> tuple[list[str], list[str], list[dict], list[list[float]]]:
    """הכנת שמות מסמכים, ID, metadata, ו-embeddings ל-ChromaDB."""
    ids: list[str] = []
    doc_texts: list[str] = []
    metadatas: list[dict] = []

    for doc in documents:
        doc_id = f"doc_{doc['doc_number']}"
        ids.append(doc_id)
        doc_texts.append(doc["content"])
        metadatas.append(
            {
                "title": doc["title"],
                "doc_number": doc["doc_number"],
                "short_description": doc["short_description"],
            }
        )

    return doc_texts, ids, metadatas, embeddings


def build_chroma_collection(
    documents: list[str],
    embeddings: list[list[float]],
    ids: list[str],
    metadatas: list[dict],
    chroma_path: Path = CHROMA_DB_PATH,
    collection_name: str = COLLECTION_NAME,
) -> None:
    """יצירת Persistent Client, Collection, והוספת המסמכים."""
    chroma_path.mkdir(parents=True, exist_ok=True)

    client = chromadb.PersistentClient(path=str(chroma_path))
    collection = client.get_or_create_collection(name=collection_name)

    collection.add(
        documents=documents,
        embeddings=embeddings,
        ids=ids,
        metadatas=metadatas,
    )

    print(f"Added {len(ids)} documents to collection '{collection_name}'")
    print(f"ChromaDB saved at: {chroma_path.resolve()}")


def main() -> None:
    docs = load_split()
    print(f"Loaded {len(docs)} documents from {KB_PATH.name}")

    vectors = embedding(docs)
    print(f"Generated {len(vectors)} embedding vectors")

    documents, ids, metadatas, embeddings = prepare_data(docs, vectors)
    build_chroma_collection(documents, embeddings, ids, metadatas)


if __name__ == "__main__":
    main()
