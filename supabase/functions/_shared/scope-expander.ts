// scope-expander.ts — materialize every asset (apex + subdomains + related)
// the scanner should fan out to. Backed by `scan_assets`.

export interface Asset {
  host: string;
  base_url: string;
  source: "apex" | "subdomain" | "related";
}

function normHost(s: string): string {
  return String(s || "").trim().toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "")
    .replace(/:\d+$/, "");
}

export async function expandScope(db: any, targetId: string): Promise<Asset[]> {
  const [{ data: tgt }, { data: eps }, { data: dead }] = await Promise.all([
    db.from("target_workspaces").select("domain,url").eq("id", targetId).maybeSingle(),
    db.from("discovered_endpoints").select("url").eq("target_id", targetId).limit(500),
    db.from("dead_targets").select("host").eq("target_id", targetId),
  ]);

  const apex = normHost(tgt?.domain || tgt?.url || "");
  const deadSet = new Set((dead || []).map((d: any) => normHost(d.host)));
  const seen = new Map<string, Asset>();

  if (apex && !deadSet.has(apex)) {
    seen.set(apex, { host: apex, base_url: `https://${apex}`, source: "apex" });
  }

  for (const ep of eps || []) {
    try {
      const u = new URL(ep.url);
      const h = normHost(u.host);
      if (!h || deadSet.has(h) || seen.has(h)) continue;
      const src: Asset["source"] =
        apex && (h === apex || h.endsWith("." + apex)) ? (h === apex ? "apex" : "subdomain") : "related";
      seen.set(h, { host: h, base_url: `${u.protocol}//${h}`, source: src });
    } catch { /* ignore */ }
  }

  const assets = Array.from(seen.values());

  // Persist into scan_assets for orchestrator fan-out + UI visibility
  try {
    if (assets.length) {
      await db.from("scan_assets").upsert(
        assets.map((a) => ({
          target_id: targetId, host: a.host, base_url: a.base_url, source: a.source,
        })),
        { onConflict: "target_id,host", ignoreDuplicates: true },
      );
    }
  } catch { /* ignore */ }

  return assets;
}
