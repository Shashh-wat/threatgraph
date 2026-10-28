"""
ThreatGraphRAG pipeline: embed query -> vector search -> multi-hop graph
expansion -> LLM synthesis (Section 9 / Section 10 of the assignment doc).

Also exposes the project queries from Section 10 as standalone functions
(run_query_3 .. run_query_10) so the Streamlit app and any test script can
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
MIN_SCORE = float(os.environ.get("MIN_SCORE", "0.30"))  # vector similarity cutoff
VECTOR_INDEXES = ["report_embedding_index", "vulnerability_embedding_index"]

# Exact Cypher text as written in the assignment document (Section 10),
# shown in the Streamlit UI for the write-up / inspection panel.
QUERY_2_DOC_TEXT = """MATCH (seed) WHERE seed.id = $seed_id
MATCH path = (seed)-[*1..2]-(connected)
RETURN DISTINCT connected, labels(connected)"""


SCHEMA_DESCRIPTION = """Neo4j property graph schema:
Nodes:
  (:ThreatActor {id, name, nickname, origin, motivation, summary})
  (:Vulnerability:CVE {id, cve_id, nickname, severity, description, mitigation})   severity in 'Critical','High','Medium','Low'
  (:Software {id, name, vendor, category})   category in 'Database System','Logging Library','Email Server','Network Device','Operating System','Virtualization','Collaboration Software'
  (:Report {id, title, text})
Relationships:
  (:ThreatActor)-[:EXPLOITS]->(:Vulnerability)
  (:Vulnerability)-[:AFFECTS]->(:Software)
  (:Report)-[:DESCRIBES]->(:Vulnerability or :ThreatActor)
Actor names: 'APT29 (Cozy Bear)', 'FIN7', 'Lazarus Group', 'APT41', 'Sandworm', 'Scattered Spider', 'Volt Typhoon', 'Conti (successor collective)'.
"""

TEXT_TO_CYPHER_RULES = """You translate questions into ONE read-only Cypher query for the schema above.
Rules:
- Output only the Cypher, no explanation, no markdown fences.
- Use only labels, properties and relationships from the schema.
- Read-only: MATCH / OPTIONAL MATCH / WITH / RETURN only. Never CREATE, MERGE, SET, DELETE, REMOVE or CALL.
- When the question is about connections or "who is linked to what", RETURN the nodes and relationships
  themselves (e.g. RETURN a, r1, v, r2, s with named relationships) so they can be drawn as a graph.
- For counts, rankings and lists, RETURN property values and aggregates.
- Add LIMIT 50 to non-aggregating queries.
- Match names case-insensitively with toLower(x.name) CONTAINS toLower('...') when the user gives a partial name."""


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

    # ---- Stage 2: vector search (Query 1) over Reports AND Vulnerabilities ----
    def vector_search(self, query_vector, top_k=3, min_score=MIN_SCORE, indexes=VECTOR_INDEXES):
        cypher = """
        CALL db.index.vector.queryNodes($index_name, $top_k, $query_vector)
        YIELD node, score
        WHERE score >= $min_score
        RETURN node.id AS id, coalesce(node.title, node.cve_id) AS label,
               score, $index_name AS index
        """
        rows = []
        with self._driver.session() as session:
            for index in indexes:
                result = session.run(
                    cypher, index_name=index, top_k=top_k,
                    query_vector=query_vector, min_score=min_score,
                )
                rows.extend(dict(r) for r in result)
        return sorted(rows, key=lambda r: r["score"], reverse=True)

    def get_node(self, node_id):
        """Fetch a seed node itself (expansion only returns its neighbours)."""
        with self._driver.session() as session:
            rec = session.run(
                "MATCH (n {id: $id}) RETURN n, labels(n) AS labels", id=node_id
            ).single()
        if not rec:
            return None
        return {"node": self._strip(rec["n"]), "labels": rec["labels"]}

    @staticmethod
    def _strip(node):
        return {k: v for k, v in dict(node).items() if k != "embedding"}

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
            return [{"node": self._strip(r["connected"]), "labels": r["labels"]} for r in result]

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
            if node.get("nickname"):
                name = f"{name} ({node['nickname']})"
            mitigation = node.get("mitigation")
            if mitigation:
                summary = f"{summary} Mitigation: {mitigation}"
            lines.append(f"[{label}] {name}: {summary}")
        return "\n".join(lines) if lines else "(no graph context retrieved)"

    # ---- Full pipeline (Stages 1-4) ---------------------------------------------
    def run(self, question: str, top_k=3, hop_limit=MULTI_HOP_LIMIT, min_score=MIN_SCORE):
        query_vector = self.embed_query(question)
        seeds = self.vector_search(query_vector, top_k=top_k, min_score=min_score)

        expanded = []
        for seed in seeds:
            seed_node = self.get_node(seed["id"])  # the seed's own text matters too
            if seed_node:
                expanded.append(seed_node)
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
            "graph": self.pipeline_graph(seeds, deduped),
            "question": question,
            "seeds": seeds,
            "expanded_nodes": deduped,
            "answer": answer,
            "cypher_run": [
                f"UNWIND ['report_embedding_index', 'vulnerability_embedding_index'] AS idx "
                f"CALL db.index.vector.queryNodes(idx, {top_k}, $query_vector) "
                f"YIELD node, score WHERE score >= {min_score} "
                "RETURN node.id, coalesce(node.title, node.cve_id), score",
                QUERY_2_DOC_TEXT + f"  // executed with LIMIT {hop_limit}",
            ],
        }


    # ---- Graph views for visualisation -----------------------------------------
    @staticmethod
    def _short(text, n=26):
        text = str(text)
        return text if len(text) <= n else text[: n - 1] + "\u2026"

    @classmethod
    def node_view(cls, nid, labels, props, seed=False):
        labels = list(labels)
        group = next((l for l in labels if l != "CVE"), labels[0] if labels else "Node")
        name = props.get("name") or props.get("cve_id") or props.get("title") or props.get("id") or nid
        nick = props.get("nickname")
        if nick and props.get("cve_id"):
            label = f"{cls._short(nick, 30)}\n{props['cve_id']}"
        elif nick:
            label = f"{cls._short(str(name).split(' (')[0], 22)}\n{cls._short(nick, 30)}"
        else:
            label = cls._short(name)
        tooltip = "\n".join(f"{k}: {cls._short(v, 140)}" for k, v in props.items() if k != "embedding")
        return {"id": nid, "group": group, "label": label, "title": tooltip, "seed": seed}

    def graph_between(self, ids):
        """Relationships among a set of node ids (so retrieved nodes can be drawn with arrows)."""
        cypher = """
        MATCH (a)-[r]->(b) WHERE a.id IN $ids AND b.id IN $ids
        RETURN a.id AS src, type(r) AS rel, b.id AS dst
        """
        with self._driver.session() as session:
            return [{"from": r["src"], "to": r["dst"], "label": r["rel"]}
                    for r in session.run(cypher, ids=list(ids))]

    def pipeline_graph(self, seeds, expanded):
        seed_ids = {s["id"] for s in seeds}
        nodes = [self.node_view(i["node"]["id"], i["labels"], i["node"], seed=i["node"]["id"] in seed_ids)
                 for i in expanded]
        edges = self.graph_between([n["id"] for n in nodes])
        return {"nodes": nodes, "edges": edges}

    # ---- English -> Cypher and direct Cypher execution -------------------------
    def text_to_cypher(self, question):
        prompt = (SCHEMA_DESCRIPTION + "\n" + TEXT_TO_CYPHER_RULES
                  + f"\n\nQuestion: {question}\nCypher:")
        response = self._groq.chat.completions.create(
            model=GROQ_MODEL, messages=[{"role": "user", "content": prompt}], temperature=0,
        )
        text = response.choices[0].message.content.strip()
        if text.startswith("```"):
            text = text.strip("`").strip()
            if text.lower().startswith("cypher"):
                text = text[6:].strip()
        return text

    @classmethod
    def _clean(cls, value):
        if isinstance(value, dict):
            return {k: cls._clean(v) for k, v in value.items() if k != "embedding"}
        if isinstance(value, (list, tuple)):
            return [cls._clean(v) for v in value]
        return value

    @classmethod
    def _cell(cls, value):
        """Flatten nodes / relationships / lists to text so one column never mixes types."""
        if (isinstance(value, (tuple, list)) and len(value) == 3 and isinstance(value[1], str)
                and isinstance(value[0], dict) and isinstance(value[2], dict)):
            start, rel, end = value
            return f"{cls._display_name(start)} -[:{rel}]-> {cls._display_name(end)}"
        if isinstance(value, dict):
            return cls._display_name(value)
        if isinstance(value, (list, tuple)):
            return ", ".join(str(cls._cell(v)) for v in value)
        return value

    @staticmethod
    def _display_name(props):
        if isinstance(props, dict):
            base = props.get("name") or props.get("cve_id") or props.get("title")
            if base and props.get("nickname"):
                return f"{base} \u2013 {props['nickname']}"
            return str(base or props)
        return str(props)

    def run_cypher(self, cypher, allow_write=False):
        """Run arbitrary Cypher. Read-only mode is enforced by Neo4j itself
        (execute_read), not by string matching."""

        def work(tx):
            result = tx.run(cypher)
            columns = list(result.keys())
            graph = result.graph()
            rows = [{k: self._cell(v) for k, v in self._clean(r.data()).items()} for r in result]
            nodes = [self.node_view(n.element_id, n.labels, dict(n)) for n in graph.nodes]
            edges = [{"from": r.start_node.element_id, "to": r.end_node.element_id, "label": r.type}
                     for r in graph.relationships]
            return {"columns": columns, "rows": rows, "nodes": nodes, "edges": edges}

        with self._driver.session() as session:
            return session.execute_write(work) if allow_write else session.execute_read(work)

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

    def run_query_9(self, severity="Critical"):
        """Range-index demo: PROFILE a severity lookup and report the plan operators."""
        cypher = "MATCH (v:Vulnerability) WHERE v.severity = $severity RETURN v.cve_id AS cve"
        with self._driver.session() as session:
            result = session.run("PROFILE " + cypher, severity=severity)
            rows = [dict(r) for r in result]
            profile = result.consume().profile

        operators = []

        def walk(p):
            operators.append(p["operatorType"])
            for child in p.get("children", []):
                walk(child)

        walk(profile)
        return {"rows": rows, "operators": operators,
                "uses_index": any("IndexSeek" in o for o in operators)}

    def run_query_10(self, actor_name="FIN7", software_name="Oracle Database"):
        """Shortest ThreatActor -> Software chain via EXPLOITS/AFFECTS."""
        cypher = """
        MATCH (a:ThreatActor {name: $actor_name}), (s:Software {name: $software_name})
        MATCH p = shortestPath((a)-[:EXPLOITS|AFFECTS*..4]-(s))
        RETURN [n IN nodes(p) | coalesce(n.name, n.cve_id)] AS path, length(p) AS hops
        """
        with self._driver.session() as session:
            return [dict(r) for r in session.run(
                cypher, actor_name=actor_name, software_name=software_name)]

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
