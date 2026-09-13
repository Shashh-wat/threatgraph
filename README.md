# ThreatGraph

A Neo4j-powered GraphRAG engine correlating structured vulnerability data
with unstructured threat intelligence using Neo4j. Built for BCSE406L
(NoSQL Databases) Digital Assignment 1.

## Stack

- **Neo4j 5.24 Community Edition** (Docker) — property graph + native vector index
- **sentence-transformers** (`all-MiniLM-L6-v2`, 384-dim, local, no API key) — embeddings
- **Groq** (`llama-3.3-70b-versatile`) — LLM answer synthesis
- **Streamlit** — UI

> The assignment document's sample records show 1536-dim embeddings (an
> OpenAI dimension). This build uses a free local embedding model instead
> (384-dim) to avoid requiring an OpenAI key — see `EMBEDDING_DIM` in `.env`.

## Setup

```bash
# 1. Start Neo4j
docker compose up -d

# 2. Python env
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Load the mock dataset (8 actors, 15 CVEs, 12 software, 20 reports)
python src/ingest.py

# 4. Run the app
streamlit run app.py
```

Neo4j Browser: http://localhost:7474 (user `neo4j`, password from `.env`).

## Layout

```
docker-compose.yml     # Neo4j container
data/mock_data.py      # mock dataset (no embeddings — computed at ingest time)
src/ingest.py          # loads data + embeddings + vector indexes into Neo4j
src/graphrag.py        # ThreatGraphRAG pipeline + Section 10 queries 3-8
app.py                 # Streamlit UI
```

## Notes vs. the assignment document

- **Query 2** (multi-hop expansion) has no `LIMIT` in the document's Cypher.
  The executable version in `src/graphrag.py` adds `LIMIT 50` to keep demo
  queries bounded; the unmodified doc text is kept as `QUERY_2_DOC_TEXT` for
  the write-up/UI display.
- Embedding dimension is 384 (local model), not the 1536 shown in the
  document's sample records (which assumed OpenAI embeddings).
