// Q7: Shortest path between two actors (Conti replaces DarkSide, which is not in the dataset)
MATCH p = shortestPath(
  (a1:ThreatActor {name: 'APT29 (Cozy Bear)'})-[*..6]-(a2:ThreatActor {name: 'Conti (successor collective)'})
)
RETURN [n IN nodes(p) | coalesce(n.name, n.cve_id, n.title)] AS path, length(p) AS hops;

// Q8: Actors ranked by average severity of the CVEs they exploit.
// Ties on the average are broken by how many CVEs the actor exploits, then by name.
MATCH (a:ThreatActor)-[:EXPLOITS]->(v:Vulnerability)
WITH a, CASE v.severity WHEN 'Critical' THEN 3 WHEN 'High' THEN 2 ELSE 1 END AS score
RETURN a.name, round(avg(score), 2) AS avg_severity_score, count(*) AS cve_count
ORDER BY avg_severity_score DESC, cve_count DESC, a.name;
