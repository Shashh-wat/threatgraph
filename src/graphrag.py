"""
ThreatGraphRAG pipeline: embed query -> vector search -> multi-hop graph
expansion -> LLM synthesis (Section 9 / Section 10 of the assignment doc).

Also exposes the 8 project queries from Section 10 as standalone functions
(run_query_3 .. run_query_8) so the Streamlit app and any test script can
call them directly for the CRUD-coverage demo.

NOTE on Query 2 (multi-hop expansion): the assignment document's Cypher has
no LIMIT. That's kept verbatim in QUERY_2_DOC_TEXT for the write-up, but the
executable version below adds `LIMIT 50` so a demo click can't return an
unbounded fan-out on a denser graph.
"""
import os

from dotenv import load_dotenv
from groq import Groq
from neo4j import GraphDatabase
from sentence_transformers import SentenceTransformer

load_dotenv()

NEO4J_URI = os.environ["NEO4J_URI"]
NEO4J_USER = os.environ["NEO4J_USER"]
NEO4J_PASSWORD = os.environ["NEO4J_PASSWORD"]
GROQ_API_KEY = os.environ["GROQ_API_KEY"]
GROQ_MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")
EMBEDDING_MODEL = os.environ.get("EMBEDDING_MODEL", "all-MiniLM-L6-v2")

MULTI_HOP_LIMIT = 50

# Exact Cypher text as written in the assignment document (Section 10),
# shown in the Streamlit UI for the write-up / inspection panel.
QUERY_2_DOC_TEXT = """MATCH (seed) WHERE seed.id = $seed_id
MATCH path = (seed)-[*1..2]-(connected)
RETURN DISTINCT connected, labels(connected)"""


class ThreatGraphRAG:
    def __init__(self):
        self._driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        self._embedder = SentenceTransformer(EMBEDDING_MODEL)
        self._groq = Groq(api_key=GROQ_API_KEY)

    def close(self):
        self._driver.close()

    # ---- Stage 1: embed query -------------------------------------------------
    def embed_query(self, question: str):
        return self._embedder.encode(question).tolist()

    # ---- Stage 2: vector search (Query 1) --------------------------------------
    def vector_search(self, query_vector, index="report_embedding_index", top_k=3):
        cypher = """
        CALL db.index.vector.queryNodes($index_name, $top_k, $query_vector)
        YIELD node, score
        RETURN node.id AS id, coalesce(node.title, node.cve_id) AS label, score
        """
        with self._driver.session() as session:
            result = session.run(
                cypher, index_name=index, top_k=top_k, query_vector=query_vector
            )
            return [dict(r) for r in result]

    # ---- Stage 3: multi-hop graph expansion (Query 2, LIMIT added) ------------
    def expand_from_seed(self, seed_id, limit=MULTI_HOP_LIMIT):
        cypher = """
        MATCH (seed) WHERE seed.id = $seed_id
        MATCH path = (seed)-[*1..2]-(connected)
        RETURN DISTINCT connected, labels(connected) AS labels
        LIMIT $limit
        """
        with self._driver.session() as session:
            result = session.run(cypher, seed_id=seed_id, limit=limit)
            return [{"node": dict(r["connected"]), "labels": r["labels"]} for r in result]

    # ---- Stage 4: LLM synthesis -------------------------------------------------
    def synthesize_answer(self, question, context_nodes):
        context_text = self._format_context(context_nodes)
        prompt = (
            "You are a cyber-threat-intelligence assistant. Answer the question "
            "using ONLY the graph context below. If the context does not contain "
            "enough information to answer, say so explicitly instead of guessing.\n\n"
            f"GRAPH CONTEXT:\n{context_text}\n\nQUESTION: {question}\n\nANSWER:"
        )
        response = self._groq.chat.completions.create(
            model=GROQ_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        )
        return response.choices[0].message.content

    @staticmethod
    def _format_context(context_nodes):
        lines = []
        for item in context_nodes:
            node, labels = item["node"], item["labels"]
            label = labels[0] if labels else "Node"
            summary = node.get("summary") or node.get("description") or node.get("text") or ""
            name = node.get("name") or node.get("cve_id") or node.get("title") or node.get("id")
            lines.append(f"[{label}] {name}: {summary}")
        return "\n".join(lines) if lines else "(no graph context retrieved)"

    # ---- Full pipeline (Stages 1-4) ---------------------------------------------
    def run(self, question: str, top_k=3, hop_limit=MULTI_HOP_LIMIT):
        query_vector = self.embed_query(question)
        seeds = self.vector_search(query_vector, top_k=top_k)

        expanded = []
        for seed in seeds:
            expanded.extend(self.expand_from_seed(seed["id"], limit=hop_limit))

        # de-duplicate by node id, preserving order
        seen, deduped = set(), []
        for item in expanded:
            nid = item["node"].get("id")
            if nid not in seen:
                seen.add(nid)
                deduped.append(item)

        answer = self.synthesize_answer(question, deduped)
        return {
            "question": question,
            "seeds": seeds,
            "expanded_nodes": deduped,
            "answer": answer,
            "cypher_run": [
                "CALL db.index.vector.queryNodes('report_embedding_index', "
                f"{top_k}, $query_vector) YIELD node, score RETURN node.id, "
                "node.title, score",
                QUERY_2_DOC_TEXT + f"  // executed with LIMIT {hop_limit}",
            ],
        }

    # ---- Section 10 queries 3-8 (CRUD + analytical) -----------------------------
    def run_query_3(self):
        """Which threat actors exploit vulnerabilities affecting database software."""
        cypher = """
        MATCH (a:ThreatActor)-[:EXPLOITS]->(v:Vulnerability)-[:AFFECTS]->(s:Software)
        WHERE s.category = 'Database System'
        RETURN DISTINCT a.name AS actor, v.cve_id AS cve, s.name AS software
        ORDER BY actor
        """
        with self._driver.session() as session:
            return [dict(r) for r in session.run(cypher)]

    def run_query_4(self, actor_name="FIN7"):
        """All reports describing a given actor's vulnerabilities."""
        cypher = """
        MATCH (a:ThreatActor {name: $actor_name})-[:EXPLOITS]->(v:Vulnerability)
        MATCH (r:Report)-[:DESCRIBES]->(v)
        RETURN v.cve_id AS cve, r.title AS report_title, r.text AS report_text
        """
        with self._driver.session() as session:
            return [dict(r) for r in session.run(cypher, actor_name=actor_name)]

    def run_query_5(self):
        """Rank software by number of distinct threat actors targeting it."""
        cypher = """
        MATCH (a:ThreatActor)-[:EXPLOITS]->(:Vulnerability)-[:AFFECTS]->(s:Software)
        RETURN s.name AS software, count(DISTINCT a) AS actor_count
        ORDER BY actor_count DESC
        """
        with self._driver.session() as session:
            return [dict(r) for r in session.run(cypher)]

    def create_cve(self, id, cve_id, severity, description, software_id, embedding=None):
        """Query 6: create a newly disclosed CVE and link it to affected software."""
        if embedding is None:
            embedding = self.embed_query(description)
        cypher = """
        MERGE (v:Vulnerability:CVE {id: $id})
        SET v.cve_id = $cve_id, v.severity = $severity,
            v.description = $description, v.embedding = $embedding
        WITH v
        MATCH (s:Software {id: $software_id})
        MERGE (v)-[:AFFECTS]->(s)
        RETURN v.id AS id
        """
        with self._driver.session() as session:
            return session.run(
                cypher, id=id, cve_id=cve_id, severity=severity,
                description=description, embedding=embedding, software_id=software_id,
            ).single()

    def update_severity(self, cve_id, new_severity):
        """Query 7: revise a vulnerability's severity after re-assessment."""
        cypher = """
        MATCH (v:Vulnerability {cve_id: $cve_id})
        SET v.severity = $new_severity
        RETURN v.cve_id AS cve_id, v.severity AS severity
        """
        with self._driver.session() as session:
            return session.run(cypher, cve_id=cve_id, new_severity=new_severity).single()

    def delete_report(self, report_id):
        """Query 8: remove a retracted report and its relationships."""
        cypher = "MATCH (r:Report {id: $report_id}) DETACH DELETE r"
        with self._driver.session() as session:
            session.run(cypher, report_id=report_id)


if __name__ == "__main__":
    rag = ThreatGraphRAG()
    try:
        result = rag.run("Which threat actors target our database systems, and how do we mitigate that?")
        print("ANSWER:\n", result["answer"])
        print("\nSEEDS:", result["seeds"])
        print("\nCYPHER RUN:")
        for c in result["cypher_run"]:
            print(c, "\n")
    finally:
        rag.close()
