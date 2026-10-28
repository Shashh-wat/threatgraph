"""
Streamlit UI for ThreatGraph (Section 9 / Section 2 objective #5 of the
assignment doc): a user types a question and sees the answer, the Cypher
that ran, and the graph nodes that were retrieved.

Run: streamlit run app.py
"""
import streamlit as st

from src.graphrag import ThreatGraphRAG
from src.graphview import render_graph

st.set_page_config(page_title="ThreatGraph", page_icon="🕸️", layout="wide")


@st.cache_resource
def get_rag():
    return ThreatGraphRAG()


rag = get_rag()

st.title("🕸️ ThreatGraph")
st.caption("A Neo4j-powered GraphRAG engine correlating CVEs, threat actors, "
           "software, and threat intelligence reports.")

tab_ask, tab_lab, tab_queries = st.tabs(["Ask a question", "Query Lab", "Section 10 project queries"])

with tab_ask:
    question = st.text_input(
        "Ask a question",
        placeholder="Which threat actors target our database systems, and how do we mitigate that?",
    )
    top_k = st.slider("Vector search top-k (per index)", min_value=1, max_value=10, value=3)
    min_score = st.slider("Minimum similarity", min_value=0.0, max_value=0.9, value=0.30, step=0.05)

    if st.button("Run", type="primary") and question:
        with st.spinner("Embedding query, searching graph, synthesising answer..."):
            result = rag.run(question, top_k=top_k, min_score=min_score)

        st.subheader("Answer")
        st.write(result["answer"])

        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Cypher that ran")
            for c in result["cypher_run"]:
                st.code(c, language="cypher")
        with col2:
            st.subheader(f"Vector search seeds (top-{top_k} per index, {len(result['seeds'])} found)")
            if result["seeds"]:
                st.table(result["seeds"])
            else:
                st.warning("No nodes passed the similarity cutoff; lower it to retrieve context.")

        st.subheader("Graph view")
        render_graph(result["graph"]["nodes"], result["graph"]["edges"])

        st.subheader(f"Graph nodes retrieved ({len(result['expanded_nodes'])})")
        for item in result["expanded_nodes"]:
            label = item["labels"][0] if item["labels"] else "Node"
            node = item["node"]
            name = node.get("name") or node.get("cve_id") or node.get("title") or node.get("id")
            with st.expander(f"[{label}] {name}"):
                st.json(node)

with tab_lab:
    st.write("Type a question in English to get the Cypher, or write/edit Cypher yourself and run it. "
             "Both sides feed the same result below.")
    st.session_state.setdefault("cypher_text", "")
    left, right = st.columns(2)

    with left:
        st.subheader("English \u2192 Cypher")
        nl_question = st.text_input(
            "Ask in plain English", key="nl_question",
            placeholder="Which actors exploit vulnerabilities in database software?",
        )
        gen_clicked = st.button("Generate Cypher")
        gen_and_run = st.button("Generate & run", type="primary")
        if (gen_clicked or gen_and_run) and nl_question:
            with st.spinner("Translating to Cypher..."):
                st.session_state["cypher_text"] = rag.text_to_cypher(nl_question)

    with right:
        st.subheader("Cypher \u2192 Result")
        cypher_text = st.text_area("Cypher (editable)", key="cypher_text", height=220)
        allow_write = st.checkbox("Allow write queries (CREATE / SET / DELETE)", value=False)
        run_clicked = st.button("Run Cypher", type="primary")

    if (run_clicked or (gen_and_run and nl_question)) and st.session_state["cypher_text"].strip():
        try:
            out = rag.run_cypher(st.session_state["cypher_text"], allow_write=allow_write)
        except Exception as exc:  # surface Neo4j syntax / read-only errors to the user
            st.error(f"Query failed: {exc}")
        else:
            st.subheader(f"Table ({len(out['rows'])} rows)")
            if out["rows"]:
                st.dataframe(out["rows"], use_container_width=True)
            st.subheader(f"Graph ({len(out['nodes'])} nodes, {len(out['edges'])} relationships)")
            render_graph(out["nodes"], out["edges"])

with tab_queries:
    st.write("Queries 3-5 are retrieval/aggregation, 6-8 are create/update/delete, "
             "9 shows a range index in a PROFILE plan, 10 is a shortestPath traversal.")

    if st.button("Run Query 3: Actors exploiting DB-affecting CVEs"):
        st.table(rag.run_query_3())

    actor_name = st.text_input("Actor name for Query 4", value="FIN7")
    if st.button("Run Query 4: Reports describing this actor's CVEs"):
        st.table(rag.run_query_4(actor_name))

    if st.button("Run Query 5: Rank software by number of targeting actors"):
        st.table(rag.run_query_5())

    sev = st.selectbox("Severity for Query 9", ["Critical", "High", "Medium", "Low"])
    if st.button("Run Query 9: PROFILE severity lookup (range index)"):
        res = rag.run_query_9(sev)
        st.write(f"Plan operators: {' -> '.join(res['operators'])}")
        st.success("Uses NodeIndexSeek" if res["uses_index"] else "Index NOT used")
        st.table(res["rows"])

    col_a, col_s = st.columns(2)
    q10_actor = col_a.text_input("Actor for Query 10", value="FIN7")
    q10_sw = col_s.text_input("Software for Query 10", value="Oracle Database")
    if st.button("Run Query 10: shortest actor -> software path"):
        st.table(rag.run_query_10(q10_actor, q10_sw))

    st.divider()
    st.write("**Query 6 — Create:** add a newly disclosed CVE")
    with st.form("create_cve"):
        c_id = st.text_input("id", value="cve-2024-99999")
        c_cve_id = st.text_input("cve_id", value="CVE-2024-99999")
        c_severity = st.selectbox("severity", ["Low", "Medium", "High", "Critical"])
        c_description = st.text_area("description", value="Example newly disclosed vulnerability.")
        c_software_id = st.text_input("affected software id", value="sw-oracledb")
        if st.form_submit_button("Create CVE"):
            rag.create_cve(c_id, c_cve_id, c_severity, c_description, c_software_id)
            st.success(f"Created {c_cve_id} and linked to {c_software_id}")

    st.write("**Query 7 — Update:** revise a CVE's severity")
    with st.form("update_severity"):
        u_cve_id = st.text_input("cve_id", value="CVE-2017-15535")
        u_severity = st.selectbox("new severity", ["Low", "Medium", "High", "Critical"], index=2)
        if st.form_submit_button("Update severity"):
            res = rag.update_severity(u_cve_id, u_severity)
            st.success(f"Updated: {dict(res) if res else 'no matching CVE'}")

    st.write("**Query 8 — Delete:** remove a retracted report")
    with st.form("delete_report"):
        d_report_id = st.text_input("report_id", value="report-19")
        if st.form_submit_button("Delete report"):
            rag.delete_report(d_report_id)
            st.success(f"Deleted {d_report_id} and its relationships")
