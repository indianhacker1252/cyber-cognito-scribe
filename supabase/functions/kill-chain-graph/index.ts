// Kill-Chain Graph Engine — builds attack graph from all signals,
// runs Dijkstra from "anonymous" to high-value goals, emits ranked chains.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};
const db = () => createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

type N = { id: string; node_type: string; label: string; capability_tags: string[]; metadata: any; source_finding_id?: string | null };
type E = { from: string; to: string; technique: string; cost: number; confidence: number; evidence: any };

// STRIDE-ish capability assignment based on vuln class
function tagsForFinding(title: string, severity: string): string[] {
  const t = (title || "").toLowerCase();
  const tags: string[] = [];
  if (/xss|html.injection|csp/.test(t)) tags.push("Tamper", "EoP-client");
  if (/sql|nosql|orm/.test(t)) tags.push("InfoDisclose", "Tamper", "EoP-server");
  if (/idor|bola|broken.access|authz|privilege/.test(t)) tags.push("EoP-server", "InfoDisclose");
  if (/ssrf/.test(t)) tags.push("InfoDisclose", "Pivot-internal");
  if (/rce|command|deserialization|template.injection|ssti/.test(t)) tags.push("EoP-server", "Code-exec");
  if (/jwt|oauth|auth.bypass|session/.test(t)) tags.push("Spoof", "EoP-server");
  if (/redirect|csrf/.test(t)) tags.push("Spoof", "Tamper");
  if (/leak|exposure|disclosure|debug|secret|key/.test(t)) tags.push("InfoDisclose");
  if (/upload|path.traversal|lfi|rfi/.test(t)) tags.push("Code-exec", "InfoDisclose");
  if (/desync|smuggl|cache/.test(t)) tags.push("Tamper", "Spoof");
  if (/prototype.pollution/.test(t)) tags.push("EoP-client", "Code-exec");
  if (severity === "critical") tags.push("Critical-impact");
  return [...new Set(tags)];
}

// Default cost: lower = easier exploit
function costFor(tags: string[], confidence: number): number {
  let c = 20;
  if (tags.includes("Code-exec")) c -= 8;
  if (tags.includes("EoP-server")) c -= 5;
  if (tags.includes("InfoDisclose")) c -= 3;
  if (tags.includes("Spoof")) c -= 4;
  if (confidence >= 0.8) c -= 3;
  return Math.max(1, c);
}

// Heuristic edge inference between capability tags
const TRANSITIONS: { from: string; to: string; technique: string; cost: number }[] = [
  { from: "InfoDisclose", to: "Spoof",       technique: "use leaked credentials/tokens", cost: 5 },
  { from: "InfoDisclose", to: "EoP-server",  technique: "leaked admin route/secret",     cost: 6 },
  { from: "Spoof",        to: "EoP-server",  technique: "authenticated privilege abuse", cost: 4 },
  { from: "EoP-client",   to: "Spoof",       technique: "session theft via XSS",         cost: 6 },
  { from: "Pivot-internal", to: "EoP-server",technique: "internal admin endpoint hit",   cost: 5 },
  { from: "Tamper",       to: "Code-exec",   technique: "cache-poison → stored payload", cost: 7 },
  { from: "Code-exec",    to: "Critical-impact", technique: "RCE → goal",                cost: 1 },
  { from: "EoP-server",   to: "Critical-impact", technique: "admin → PII / fund / data dump", cost: 2 },
];

function dijkstra(nodes: N[], edges: E[], startIds: string[], goalTag: string) {
  const idx = new Map(nodes.map((n, i) => [n.id, i]));
  const adj: Map<string, { to: string; cost: number; e: E }[]> = new Map();
  for (const e of edges) {
    if (!adj.has(e.from)) adj.set(e.from, []);
    adj.get(e.from)!.push({ to: e.to, cost: e.cost, e });
  }
  const dist = new Map<string, number>();
  const prev = new Map<string, { node: string; edge: E } | null>();
  const pq: [number, string][] = [];
  for (const s of startIds) { dist.set(s, 0); pq.push([0, s]); prev.set(s, null); }

  while (pq.length) {
    pq.sort((a, b) => a[0] - b[0]);
    const [d, u] = pq.shift()!;
    if (d > (dist.get(u) ?? Infinity)) continue;
    for (const { to, cost, e } of adj.get(u) || []) {
      const nd = d + cost;
      if (nd < (dist.get(to) ?? Infinity)) {
        dist.set(to, nd);
        prev.set(to, { node: u, edge: e });
        pq.push([nd, to]);
      }
    }
  }

  // Find goals (nodes with goalTag)
  const goals = nodes.filter(n => n.capability_tags.includes(goalTag) && dist.has(n.id));
  goals.sort((a, b) => (dist.get(a.id)! - dist.get(b.id)!));
  const chains: { goal: N; cost: number; path: { node: N; edge?: E }[] }[] = [];
  for (const g of goals.slice(0, 5)) {
    const path: { node: N; edge?: E }[] = [];
    let cur: string | null = g.id;
    while (cur) {
      const p = prev.get(cur);
      path.unshift({ node: nodes[idx.get(cur)!], edge: p?.edge });
      cur = p?.node || null;
    }
    chains.push({ goal: g, cost: dist.get(g.id)!, path });
  }
  return chains;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const { targetId } = await req.json();
    if (!targetId) throw new Error("targetId required");
    const supa = db();

    // 1. Pull all signals
    const [findings, endpoints, oob, code] = await Promise.all([
      supa.from("vulnerability_findings").select("id,title,severity,confidence_score,affected_url,payload").eq("target_id", targetId).limit(200),
      supa.from("discovered_endpoints").select("id,url,method,parameters").eq("target_id", targetId).limit(200),
      supa.from("oob_callbacks").select("id,callback_type,source_url").eq("target_id", targetId).limit(50),
      supa.from("code_findings").select("id,vuln_class,file_path,severity").eq("target_id", targetId).limit(100),
    ]);

    // 2. Clear prior graph for this target
    await supa.from("attack_graph_edges").delete().eq("target_id", targetId);
    await supa.from("attack_graph_nodes").delete().eq("target_id", targetId);

    // 3. Build nodes
    const nodes: N[] = [];
    const anon: N = { id: crypto.randomUUID(), node_type: "actor", label: "Anonymous Attacker", capability_tags: ["Anon"], metadata: {} };
    nodes.push(anon);

    for (const f of (findings.data || [])) {
      const tags = tagsForFinding(f.title, f.severity);
      if (!tags.length) continue;
      nodes.push({
        id: crypto.randomUUID(),
        node_type: "finding",
        label: `${f.title} @ ${f.affected_url || "?"}`.slice(0, 200),
        capability_tags: tags,
        metadata: { severity: f.severity, confidence: f.confidence_score, payload: f.payload },
        source_finding_id: f.id,
      });
    }
    for (const c of (code.data || [])) {
      const tags = tagsForFinding(c.vuln_class || "", c.severity || "medium");
      if (!tags.length) continue;
      nodes.push({
        id: crypto.randomUUID(),
        node_type: "code",
        label: `SAST: ${c.vuln_class} in ${c.file_path}`.slice(0, 200),
        capability_tags: tags,
        metadata: { severity: c.severity },
      });
    }
    for (const o of (oob.data || [])) {
      nodes.push({
        id: crypto.randomUUID(), node_type: "oob",
        label: `OOB ${o.callback_type} from ${o.source_url || "?"}`.slice(0, 200),
        capability_tags: ["InfoDisclose", "Pivot-internal"],
        metadata: {},
      });
    }
    // Goal anchor nodes
    nodes.push({ id: crypto.randomUUID(), node_type: "goal", label: "Full Compromise (RCE / Admin / PII Dump)", capability_tags: ["Critical-impact"], metadata: {} });

    // 4. Persist nodes (need real ids in DB)
    const inserted = await supa.from("attack_graph_nodes").insert(
      nodes.map(n => ({ target_id: targetId, node_type: n.node_type, label: n.label, capability_tags: n.capability_tags, metadata: n.metadata, source_finding_id: n.source_finding_id }))
    ).select("id,node_type,label,capability_tags,metadata,source_finding_id");

    const dbNodes: N[] = (inserted.data || []).map((r: any) => ({ id: r.id, node_type: r.node_type, label: r.label, capability_tags: r.capability_tags || [], metadata: r.metadata || {}, source_finding_id: r.source_finding_id }));

    // 5. Build edges: Anon → any node whose tags trigger from any "free" precondition
    const anonNode = dbNodes.find(n => n.node_type === "actor")!;
    const edges: E[] = [];
    for (const n of dbNodes) {
      if (n.id === anonNode.id) continue;
      // direct reach from anon if InfoDisclose / Tamper / EoP-client / Spoof  achievable unauthenticated
      if (n.capability_tags.some(t => ["InfoDisclose", "Tamper", "EoP-client", "Spoof", "Code-exec", "Pivot-internal"].includes(t))) {
        const conf = n.metadata?.confidence ?? 0.6;
        edges.push({ from: anonNode.id, to: n.id, technique: `Exploit ${n.label.slice(0, 60)}`, cost: costFor(n.capability_tags, conf), confidence: conf, evidence: { payload: n.metadata?.payload } });
      }
    }
    // Capability transitions: for each pair (a,b) where a's outputs match b's preconditions
    for (const a of dbNodes) {
      for (const b of dbNodes) {
        if (a.id === b.id || a.node_type === "actor") continue;
        for (const tr of TRANSITIONS) {
          if (a.capability_tags.includes(tr.from) && b.capability_tags.includes(tr.to)) {
            edges.push({ from: a.id, to: b.id, technique: tr.technique, cost: tr.cost, confidence: 0.55, evidence: {} });
          }
        }
      }
    }

    if (edges.length) {
      await supa.from("attack_graph_edges").insert(edges.map(e => ({
        target_id: targetId, from_node: e.from, to_node: e.to, technique: e.technique, cost: e.cost, confidence: e.confidence, evidence: e.evidence,
      })));
    }

    // 6. Dijkstra: anon → Critical-impact
    const chains = dijkstra(dbNodes, edges, [anonNode.id], "Critical-impact");

    // 7. Persist kill_chains
    await supa.from("kill_chains").delete().eq("target_id", targetId);
    const chainRows = chains.map(c => ({
      target_id: targetId,
      goal: c.goal.label,
      total_cost: c.cost,
      severity: c.cost <= 15 ? "critical" : c.cost <= 25 ? "high" : "medium",
      node_path: c.path.map(p => p.node.id),
      step_plan: c.path.map((p, i) => ({
        order: i,
        node: p.node.label,
        node_type: p.node.node_type,
        technique: p.edge?.technique || "initial access",
        finding_id: p.node.source_finding_id || null,
      })),
      status: "proposed",
    }));
    if (chainRows.length) await supa.from("kill_chains").insert(chainRows);

    await supa.from("scan_logs").insert({
      target_id: targetId, log_type: chains.length ? "result" : "info",
      message: `⛓️ Kill-Chain Graph: ${dbNodes.length} nodes, ${edges.length} edges, ${chains.length} chains discovered`,
      metadata: { nodes: dbNodes.length, edges: edges.length, chains: chains.length },
    });

    return new Response(JSON.stringify({
      nodes: dbNodes.length, edges: edges.length, chains: chainRows.length,
      topChain: chainRows[0] || null,
    }), { headers: { ...cors, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : String(e) }), {
      status: 200, headers: { ...cors, "Content-Type": "application/json" },
    });
  }
});
