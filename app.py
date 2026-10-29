"""
Streamlit UI for ThreatGraph (Section 9 / Section 2 objective #5 of the
assignment doc): a user types a question and sees the answer, the Cypher
that ran, and the graph nodes that were retrieved.

Run: streamlit run app.py
"""
import streamlit as st

from src.graphrag import ThreatGraphRAG
from src.graphview import render_graph
from src.project_queries import PROJECT_QUERIES

st.set_page_config(page_title="ThreatGraph", page_icon="🕸️", layout="wide")


@st.cache_resource
def get_rag():
    return ThreatGraphRAG()


rag = get_rag()

def show_grounding(check):
    """Render the fact-check result: supported vs unsupported claims."""
    claims = check["claims"]
    if check["error"] or not claims:
        st.caption(f"Grounding check unavailable: {check['error'] or 'no claims returned'}")
        return
    ok = sum(1 for c in claims if c.get("supported"))
    st.subheader(f"Grounding check: {ok}/{len(claims)} claims supported by the graph")
    st.progress(ok / len(claims))
    for c in claims:
        if c.get("supported"):
            st.markdown(f"\u2705 {c['claim']}  \n<small>evidence: {c.get('evidence', '')}</small>",
                        unsafe_allow_html=True)
        else:
            st.markdown(f"\u26a0\ufe0f **Not supported by retrieved context:** {c['claim']}")


st.title("🕸️ ThreatGraph")
st.caption("A Neo4j-powered GraphRAG engine correlating CVEs, threat actors, "
           "software, and threat intelligence reports.")

tab_ask, tab_patch, tab_lab, tab_queries = st.tabs(
    ["Ask a question", "Patch priority", "Query Lab", "Section 10 project queries"]
)

with tab_ask:
    question = st.text_input(
        "Ask a question",
        placeholder="Which threat actors target our database systems, and how do we mitigate that?",
    )
    top_k = st.slider("Vector search top-k (per index)", min_value=1, max_value=10, value=3)
    min_score = st.slider("Minimum similarity", min_value=0.0, max_value=0.9, value=0.30, step=0.05)
    verify = st.checkbox("Fact-check the answer against the retrieved graph", value=True)

    if st.button("Run", type="primary") and question:
        with st.spinner("Embedding query, searching graph, synthesising answer..."):
            result = rag.run(question, top_k=top_k, min_score=min_score)

        st.subheader("Answer")
        st.write(result["answer"])
        if verify:
            with st.spinner("Fact-checking the answer..."):
                show_grounding(rag.verify_answer(result["answer"], result["expanded_nodes"]))

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

with tab_patch:
    st.write("Pick the software you run. The graph finds every CVE that affects it and every actor that "
             "exploits those CVEs, then ranks what to patch first (the CVE that touches the most "
             "still-exposed actors).")
    software = rag.list_software()
    by_name = {s["name"]: s["id"] for s in software}
    defaults = [n for n in ("Oracle Database", "MySQL", "Microsoft SQL Server", "Windows Server") if n in by_name]
    chosen = st.multiselect("Software we run", list(by_name), default=defaults)
    if st.button("Compute patch priority", type="primary") and chosen:
        plan = rag.patch_priority([by_name[n] for n in chosen])
        steps = plan["steps"]
        if not steps:
            st.info("No known CVEs affect the selected software.")
        else:
            total = plan["exposed_total"]
            if not total:
                st.info("CVEs exist for this software, but no tracked actor exploits them.")
            else:
                n = min(3, len(steps))
                st.success(f"{total} threat actors are exposed through your stack. Patching the top {n} "
                           f"CVE(s) fully blocks {steps[n - 1]['neutralised_after']} of them "
                           f"(an actor is blocked once every CVE they use on your stack is patched).")
            st.dataframe([{
                "Patch order": s["rank"], "CVE": s["cve_id"], "What it is": s["nickname"],
                "Severity": s["severity"], "Software": s["software"],
                "Actors using it": ", ".join(s["actors_touched"]) or "none known",
                f"Actors fully blocked so far (of {total})": s["neutralised_after"],
            } for s in steps], use_container_width=True, hide_index=True)
            st.subheader("Attack surface graph")
            render_graph(plan["graph"]["nodes"], plan["graph"]["edges"], ring_label="patch first")

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
    st.write("Fifteen showcase queries over the threat graph. Each shows the Cypher, what it demonstrates, "
             "the result table and (when it returns nodes or paths) the graph. All are read-only.")
    for i, q in enumerate(PROJECT_QUERIES, start=1):
        with st.expander(f"Query {i}: {q['title']}"):
            st.caption(f"Technique: {q['technique']}")
            st.write(q["explain"])
            st.code(q["cypher"], language="cypher")
            if st.button("Run", key=f"pq_{i}", type="primary"):
                try:
                    out = rag.run_cypher(q["cypher"])
                except Exception as exc:  # show Neo4j errors instead of crashing the page
                    st.error(f"Query failed: {exc}")
                else:
                    st.markdown(f"**Result: {len(out['rows'])} rows**")
                    if out["rows"]:
                        st.dataframe(out["rows"], use_container_width=True, hide_index=True)
                    if out["nodes"]:
                        render_graph(out["nodes"], out["edges"], height=420)
