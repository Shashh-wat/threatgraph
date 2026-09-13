"""
Streamlit UI for ThreatGraph (Section 9 / Section 2 objective #5 of the
assignment doc): a user types a question and sees the answer, the Cypher
that ran, and the graph nodes that were retrieved.

Run: streamlit run app.py
"""
import streamlit as st

from src.graphrag import ThreatGraphRAG

st.set_page_config(page_title="ThreatGraph", page_icon="🕸️", layout="wide")


@st.cache_resource
def get_rag():
    return ThreatGraphRAG()


rag = get_rag()

st.title("🕸️ ThreatGraph")
st.caption("A Neo4j-powered GraphRAG engine correlating CVEs, threat actors, "
           "software, and threat intelligence reports.")

tab_ask, tab_queries = st.tabs(["Ask a question", "Section 10 project queries"])

with tab_ask:
    question = st.text_input(
        "Ask a question",
        placeholder="Which threat actors target our database systems, and how do we mitigate that?",
    )
    top_k = st.slider("Vector search top-k", min_value=1, max_value=10, value=3)

    if st.button("Run", type="primary") and question:
        with st.spinner("Embedding query, searching graph, synthesising answer..."):
            result = rag.run(question, top_k=top_k)

        st.subheader("Answer")
        st.write(result["answer"])

        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Cypher that ran")
            for c in result["cypher_run"]:
                st.code(c, language="cypher")
        with col2:
            st.subheader(f"Vector search seeds (top-{top_k})")
            st.table(result["seeds"])

        st.subheader(f"Graph nodes retrieved ({len(result['expanded_nodes'])})")
        for item in result["expanded_nodes"]:
            label = item["labels"][0] if item["labels"] else "Node"
            node = item["node"]
            name = node.get("name") or node.get("cve_id") or node.get("title") or node.get("id")
            with st.expander(f"[{label}] {name}"):
                st.json(node)

with tab_queries:
    st.write("Queries 3-5 are the retrieval/aggregation queries from Section 10; "
             "6-8 demonstrate create/update/delete.")

    if st.button("Run Query 3: Actors exploiting DB-affecting CVEs"):
        st.table(rag.run_query_3())

    actor_name = st.text_input("Actor name for Query 4", value="FIN7")
    if st.button("Run Query 4: Reports describing this actor's CVEs"):
        st.table(rag.run_query_4(actor_name))

    if st.button("Run Query 5: Rank software by number of targeting actors"):
        st.table(rag.run_query_5())

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
