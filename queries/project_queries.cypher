// ThreatGraph: 15 showcase queries (generated from src/project_queries.py)

// Q1: Attack chains that reach our databases
// Technique: Multi-hop path pattern
// Every actor -> CVE -> database-software chain in the graph, returned as full paths so the whole chain can be drawn.
MATCH p = (a:ThreatActor)-[:EXPLOITS]->(v:Vulnerability)-[:AFFECTS]->(s:Software)
WHERE s.category = 'Database System'
RETURN p;

// Q2: Which actors use the same playbook? (Jaccard similarity)
// Technique: Set overlap + aggregation
// For every pair of actors, shared CVEs divided by all CVEs either uses. A score of 1.0 means identical toolkits; this is how analysts cluster threat groups.
MATCH (a1:ThreatActor)-[:EXPLOITS]->(v:Vulnerability)<-[:EXPLOITS]-(a2:ThreatActor)
WHERE a1.id < a2.id
WITH a1, a2, count(v) AS shared
MATCH (a1)-[:EXPLOITS]->(x:Vulnerability)
WITH a1, a2, shared, count(x) AS cves1
MATCH (a2)-[:EXPLOITS]->(y:Vulnerability)
WITH a1, a2, shared, cves1, count(y) AS cves2
RETURN a1.name AS actor_1, a2.name AS actor_2, shared AS shared_cves,
       round(1.0 * shared / (cves1 + cves2 - shared), 2) AS similarity
ORDER BY similarity DESC, shared_cves DESC
LIMIT 10;

// Q3: Risk score per software product
// Technique: Weighted aggregation across two hops
// Each CVE is weighted by severity (Critical 4 ... Low 1) and multiplied by how many actors exploit it. Summed per product, it ranks where a defender should worry most.
MATCH (s:Software)<-[:AFFECTS]-(v:Vulnerability)
OPTIONAL MATCH (a:ThreatActor)-[:EXPLOITS]->(v)
WITH s, v, count(DISTINCT a) AS actors,
     CASE v.severity WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 ELSE 1 END AS weight
RETURN s.name AS software, s.category AS category, count(v) AS cves,
       sum(actors) AS actor_links, sum(weight * actors) AS risk_score
ORDER BY risk_score DESC
LIMIT 8;

// Q4: Intelligence gaps: exploited CVEs with no report
// Technique: Negative existence pattern (NOT EXISTS)
// CVEs that actors actively exploit but that no threat-intel report describes. These are blind spots in the knowledge base.
MATCH (a:ThreatActor)-[:EXPLOITS]->(v:Vulnerability)
WHERE NOT EXISTS { (:Report)-[:DESCRIBES]->(v) }
RETURN v.cve_id AS cve, v.nickname AS what_it_is, v.severity AS severity,
       collect(a.name) AS exploited_by;

// Q5: Which actors have the widest reach across software types?
// Technique: Distinct counts + collect
// How many different products and software categories each actor can hit. Wide reach means an actor is hard to defend against with a single control.
MATCH (a:ThreatActor)-[:EXPLOITS]->(:Vulnerability)-[:AFFECTS]->(s:Software)
WITH a, count(DISTINCT s) AS products, collect(DISTINCT s.category) AS categories
RETURN a.name AS actor, a.nickname AS nickname, products,
       size(categories) AS category_count, categories
ORDER BY category_count DESC, products DESC;

// Q6: Indirect peers of FIN7 (friends of friends)
// Technique: Two-step traversal with an exclusion filter
// Actors that share no CVE with FIN7 directly but are linked through a middleman actor. Shows relationships that a flat table join would miss.
MATCH (f:ThreatActor {name: 'FIN7'})-[:EXPLOITS]->(:Vulnerability)<-[:EXPLOITS]-(bridge:ThreatActor)
MATCH (bridge)-[:EXPLOITS]->(:Vulnerability)<-[:EXPLOITS]-(c:ThreatActor)
WHERE c <> f AND NOT EXISTS { (f)-[:EXPLOITS]->(:Vulnerability)<-[:EXPLOITS]-(c) }
RETURN c.name AS indirect_peer, collect(DISTINCT bridge.name) AS connected_through
ORDER BY indirect_peer;

// Q7: Lateral movement: from Exchange to Oracle Database
// Technique: shortestPath over mixed relationships
// The shortest chain linking two unrelated products via the actors and CVEs that connect them. Read it as the route a campaign could follow between systems.
MATCH p = shortestPath(
  (a:Software {name: 'Microsoft Exchange Server'})-[:AFFECTS|EXPLOITS*..8]-(b:Software {name: 'Oracle Database'})
)
RETURN p;

// Q8: Actors that only go after Critical vulnerabilities
// Technique: ALL() predicate over a collected list
// Separates the actors that only chase the worst bugs from those who also use lower-severity ones. Useful for deciding who is picky and who is opportunistic.
MATCH (a:ThreatActor)-[:EXPLOITS]->(v:Vulnerability)
WITH a, collect(DISTINCT v.severity) AS severities, count(v) AS cve_count
RETURN a.name AS actor, cve_count, severities,
       ALL(s IN severities WHERE s = 'Critical') AS only_critical
ORDER BY only_critical DESC, cve_count DESC;

// Q9: Fix one, stop many: most-shared CVEs with the fix
// Technique: Aggregation joined to a stored property
// CVEs used by the most actors, together with the recommended mitigation stored on the node. The best patching return on effort.
MATCH (v:Vulnerability)<-[:EXPLOITS]-(a:ThreatActor)
MATCH (v)-[:AFFECTS]->(s:Software)
RETURN v.nickname AS weakness, v.cve_id AS cve, s.name AS software,
       count(a) AS actors_using_it, collect(a.name) AS who, v.mitigation AS fix
ORDER BY actors_using_it DESC, cve
LIMIT 6;

// Q10: Edge-to-domain actors (two-stage intrusions)
// Technique: EXISTS subqueries combined with AND
// Actors that exploit both a network device (the way in) and an operating system (the takeover). These can chain an edge compromise into full network control.
MATCH (a:ThreatActor)
WHERE EXISTS { (a)-[:EXPLOITS]->(:Vulnerability)-[:AFFECTS]->(:Software {category: 'Network Device'}) }
  AND EXISTS { (a)-[:EXPLOITS]->(:Vulnerability)-[:AFFECTS]->(:Software {category: 'Operating System'}) }
MATCH p = (a)-[:EXPLOITS]->(:Vulnerability)-[:AFFECTS]->(s:Software)
WHERE s.category IN ['Network Device', 'Operating System']
RETURN p;

// Q11: What does each motivation favour attacking?
// Technique: Two-level grouping (aggregate of an aggregate)
// Groups actors by motivation, then finds the software category each motivation hits most. Answers 'what do spies go after versus criminals?'.
MATCH (a:ThreatActor)-[:EXPLOITS]->(:Vulnerability)-[:AFFECTS]->(s:Software)
WITH a.motivation AS motivation, s.category AS category, count(*) AS hits
ORDER BY hits DESC
WITH motivation, collect({category: category, hits: hits}) AS breakdown, sum(hits) AS total
RETURN motivation, total AS exploit_links,
       breakdown[0].category AS favourite_target, breakdown[0].hits AS hits_on_it
ORDER BY total DESC;

// Q12: How well-documented is each threat?
// Technique: OPTIONAL MATCH with multiple distinct counts
// For each CVE: how many reports describe it and how many actors use it, multiplied into an evidence weight. High weight means a well-evidenced, widely used threat.
MATCH (v:Vulnerability)
OPTIONAL MATCH (r:Report)-[:DESCRIBES]->(v)
OPTIONAL MATCH (a:ThreatActor)-[:EXPLOITS]->(v)
WITH v, count(DISTINCT r) AS reports, count(DISTINCT a) AS actors
RETURN v.nickname AS weakness, v.cve_id AS cve, reports, actors,
       reports * actors AS evidence_weight
ORDER BY evidence_weight DESC, reports DESC
LIMIT 8;

// Q13: From one report to the wider threat picture
// Technique: Five-hop path from a single starting node
// Start at one intel report and follow it to the CVE it describes, the actors using that CVE, their other CVEs and the software those hit. This is the GraphRAG expansion made visible.
MATCH p = (r:Report {id: 'report-9'})-[:DESCRIBES]->(v:Vulnerability)
          <-[:EXPLOITS]-(a:ThreatActor)-[:EXPLOITS]->(other:Vulnerability)-[:AFFECTS]->(s:Software)
WHERE other <> v AND a.name = 'Scattered Spider'
RETURN p;

// Q14: Which vendors are exploited the most?
// Technique: Aggregation on a property of the far end of a path
// Rolls the attack graph up to vendor level: distinct CVEs, distinct actors and total exploit links. Useful for vendor risk reviews.
MATCH (a:ThreatActor)-[:EXPLOITS]->(v:Vulnerability)-[:AFFECTS]->(s:Software)
RETURN s.vendor AS vendor, count(DISTINCT v) AS cves_exploited,
       count(DISTINCT a) AS actors, count(*) AS exploit_links
ORDER BY exploit_links DESC, vendor;

// Q15: Defender's playbook for FIN7
// Technique: Property lookup along a path, custom ordering
// Everything FIN7 uses, the product it hits and the recommended fix, ordered by severity. One query turns the graph into an action list.
MATCH (a:ThreatActor {name: 'FIN7'})-[:EXPLOITS]->(v:Vulnerability)-[:AFFECTS]->(s:Software)
RETURN s.name AS product, v.nickname AS weakness, v.severity AS severity, v.mitigation AS what_to_do
ORDER BY CASE v.severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, product;
