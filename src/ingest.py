"""
Loads the mock dataset (data/mock_data.py) into Neo4j:
  1. Creates uniqueness constraints for every node label.
  2. MERGEs ThreatActor, Vulnerability, Software, and Report nodes.
  3. Computes embeddings for Vulnerability.description and Report.text
     with the local sentence-transformers model, stored as node properties.
  4. Creates EXPLOITS, AFFECTS, and DESCRIBES relationships.
  5. Creates Neo4j native vector indexes over the Report and Vulnerability
     embeddings (report_embedding_index, vulnerability_embedding_index).

Run: python src/ingest.py
"""
import os
import sys

from dotenv import load_dotenv
from neo4j import GraphDatabase
from sentence_transformers import SentenceTransformer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from data.mock_data import THREAT_ACTORS, SOFTWARE, VULNERABILITIES, EXPLOITS, REPORTS

load_dotenv()

NEO4J_URI = os.environ["NEO4J_URI"]
NEO4J_USER = os.environ["NEO4J_USER"]
NEO4J_PASSWORD = os.environ["NEO4J_PASSWORD"]
EMBEDDING_MODEL = os.environ.get("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
EMBEDDING_DIM = int(os.environ.get("EMBEDDING_DIM", "384"))


def create_constraints(tx):
    tx.run("CREATE CONSTRAINT actor_id IF NOT EXISTS FOR (a:ThreatActor) REQUIRE a.id IS UNIQUE")
    tx.run("CREATE CONSTRAINT vuln_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE")
    tx.run("CREATE CONSTRAINT software_id IF NOT EXISTS FOR (s:Software) REQUIRE s.id IS UNIQUE")
    tx.run("CREATE CONSTRAINT report_id IF NOT EXISTS FOR (r:Report) REQUIRE r.id IS UNIQUE")


def load_actors(tx, actors):
    tx.run(
        """
        UNWIND $rows AS row
        MERGE (a:ThreatActor {id: row.id})
        SET a.name = row.name, a.origin = row.origin,
            a.motivation = row.motivation, a.summary = row.summary
        """,
        rows=actors,
    )


def load_software(tx, software):
    tx.run(
        """
        UNWIND $rows AS row
        MERGE (s:Software {id: row.id})
        SET s.name = row.name, s.vendor = row.vendor, s.category = row.category
        """,
        rows=software,
    )


def load_vulnerabilities(tx, vulns):
    tx.run(
        """
        UNWIND $rows AS row
        MERGE (v:Vulnerability:CVE {id: row.id})
        SET v.cve_id = row.cve_id, v.severity = row.severity,
            v.description = row.description, v.embedding = row.embedding
        WITH v, row
        MATCH (s:Software {id: row.affects})
        MERGE (v)-[:AFFECTS]->(s)
        """,
        rows=vulns,
    )


def load_exploits(tx, exploits_map):
    rows = [{"actor_id": a, "cve_id": c} for a, cves in exploits_map.items() for c in cves]
    tx.run(
        """
        UNWIND $rows AS row
        MATCH (a:ThreatActor {id: row.actor_id})
        MATCH (v:Vulnerability {id: row.cve_id})
        MERGE (a)-[:EXPLOITS]->(v)
        """,
        rows=rows,
    )


def load_reports(tx, reports):
    tx.run(
        """
        UNWIND $rows AS row
        MERGE (r:Report {id: row.id})
        SET r.title = row.title, r.text = row.text, r.embedding = row.embedding
        WITH r, row
        FOREACH (_ IN CASE WHEN row.vuln IS NOT NULL THEN [1] ELSE [] END |
            MERGE (v:Vulnerability {id: row.vuln})
            MERGE (r)-[:DESCRIBES]->(v)
        )
        FOREACH (_ IN CASE WHEN row.actor IS NOT NULL THEN [1] ELSE [] END |
            MERGE (a:ThreatActor {id: row.actor})
            MERGE (r)-[:DESCRIBES]->(a)
        )
        """,
        rows=reports,
    )


def create_vector_indexes(tx, dim):
    tx.run(
        f"""
        CREATE VECTOR INDEX report_embedding_index IF NOT EXISTS
        FOR (r:Report) ON (r.embedding)
        OPTIONS {{indexConfig: {{
            `vector.dimensions`: {dim},
            `vector.similarity_function`: 'cosine'
        }}}}
        """
    )
    tx.run(
        f"""
        CREATE VECTOR INDEX vulnerability_embedding_index IF NOT EXISTS
        FOR (v:Vulnerability) ON (v.embedding)
        OPTIONS {{indexConfig: {{
            `vector.dimensions`: {dim},
            `vector.similarity_function`: 'cosine'
        }}}}
        """
    )


def main():
    print(f"Loading embedding model '{EMBEDDING_MODEL}' ...")
    model = SentenceTransformer(EMBEDDING_MODEL)

    print("Embedding vulnerability descriptions and report text ...")
    vulns = [dict(v) for v in VULNERABILITIES]
    for v in vulns:
        v["embedding"] = model.encode(v["description"]).tolist()

    reports = [dict(r) for r in REPORTS]
    for r in reports:
        r["embedding"] = model.encode(r["text"]).tolist()

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    try:
        with driver.session() as session:
            print("Creating constraints ...")
            session.execute_write(create_constraints)

            print(f"Loading {len(THREAT_ACTORS)} threat actors ...")
            session.execute_write(load_actors, THREAT_ACTORS)

            print(f"Loading {len(SOFTWARE)} software nodes ...")
            session.execute_write(load_software, SOFTWARE)

            print(f"Loading {len(vulns)} vulnerabilities + AFFECTS relationships ...")
            session.execute_write(load_vulnerabilities, vulns)

            n_exploits = sum(len(v) for v in EXPLOITS.values())
            print(f"Loading {n_exploits} EXPLOITS relationships ...")
            session.execute_write(load_exploits, EXPLOITS)

            print(f"Loading {len(reports)} reports + DESCRIBES relationships ...")
            session.execute_write(load_reports, reports)

            print("Creating vector indexes ...")
            session.execute_write(create_vector_indexes, EMBEDDING_DIM)

        print("\nDone. Dataset loaded into Neo4j.")
        print(f"  ThreatActor : {len(THREAT_ACTORS)}")
        print(f"  Vulnerability: {len(vulns)}")
        print(f"  Software    : {len(SOFTWARE)}")
        print(f"  Report      : {len(reports)}")
        print(f"  EXPLOITS    : {n_exploits}")
    finally:
        driver.close()


if __name__ == "__main__":
    main()
