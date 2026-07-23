// Per-target World Model — persistent belief state shared across all scanner
// modules. Any detector/recon module can read it to skip inapplicable vuln
// classes and write to it to refine the belief. Concurrent writes are safe
// because the DB-side `merge_world_model` RPC does a jsonb `||` merge.
//
// Shape (all keys optional; unknown keys are preserved):
//   tech:            { server?, framework?, cms?, lang?, versions?: Record<string,string> }
//   waf:             { vendor?, blockingCodes?: number[], observedAt?: string }
//   routing:         "spa" | "mpa" | "api" | "hybrid" | "unknown"
//   auth:            { mode?: "cookie"|"jwt"|"basic"|"none", csrf?: "double_submit"|"token"|"none", loginUrl?: string }
//   rate:            { limitPerMin?: number, cooldownMs?: number }
//   interestingParams: string[]     // param names seen across the app
//   sinks:           { xss?: string[], sqli?: string[], ssrf?: string[], redirect?: string[] }
//   sources:         string[]        // JS source URLs analysed
//   applicability:   Record<string, boolean>  // e.g. { ssti:false, xxe:false }
//   updatedBy:       Record<string, string>   // module -> ISO timestamp
export interface WorldModel {
  tech?: { server?: string; framework?: string; cms?: string; lang?: string; versions?: Record<string, string> };
  waf?: { vendor?: string; blockingCodes?: number[]; observedAt?: string };
  routing?: "spa" | "mpa" | "api" | "hybrid" | "unknown";
  auth?: { mode?: "cookie" | "jwt" | "basic" | "none"; csrf?: "double_submit" | "token" | "none"; loginUrl?: string };
  rate?: { limitPerMin?: number; cooldownMs?: number };
  interestingParams?: string[];
  sinks?: { xss?: string[]; sqli?: string[]; ssrf?: string[]; redirect?: string[] };
  sources?: string[];
  applicability?: Record<string, boolean>;
  updatedBy?: Record<string, string>;
  [k: string]: unknown;
}

export async function getWorld(db: any, targetId: string): Promise<WorldModel> {
  try {
    const { data } = await db.from("target_world_model").select("model").eq("target_id", targetId).maybeSingle();
    return (data?.model as WorldModel) || {};
  } catch {
    return {};
  }
}

/** Deep-merge patch into world model. Concurrency-safe via DB RPC. */
export async function updateWorld(
  db: any,
  targetId: string,
  patch: Partial<WorldModel>,
  module?: string,
): Promise<void> {
  try {
    const stamped: WorldModel = { ...patch };
    if (module) stamped.updatedBy = { [module]: new Date().toISOString() };
    await db.rpc("merge_world_model", { _target_id: targetId, _patch: stamped });
  } catch (e) {
    // Never let a world-model write break the caller.
    console.warn("updateWorld failed", (e as Error)?.message);
  }
}

/** Should this vuln class be tested against the current target?
 *  Returns true when we don't yet know enough to skip (fail-open). */
export function isApplicable(world: WorldModel, vulnClass: string): boolean {
  const app = world.applicability || {};
  if (vulnClass in app) return app[vulnClass] !== false;
  // Heuristics
  const routing = world.routing;
  const tech = world.tech || {};
  const framework = (tech.framework || "").toLowerCase();
  const server = (tech.server || "").toLowerCase();
  switch (vulnClass) {
    case "ssti":
      // Only meaningful on server-rendered stacks
      if (routing === "spa") return false;
      return true;
    case "xxe":
      // Requires XML processing — rare on modern JSON APIs
      if (routing === "api" && !framework.match(/java|php|asp/)) return false;
      return true;
    case "prototype_pollution":
      return !!(framework.match(/express|next|nest|node/) || server.includes("node"));
    case "deserialization":
      return !!framework.match(/java|php|rails|django|asp/);
    default:
      return true;
  }
}

/** Compact rendering for LLM prompts. */
export function renderWorld(world: WorldModel): string {
  const parts: string[] = [];
  if (world.tech) parts.push(`tech=${JSON.stringify(world.tech)}`);
  if (world.routing) parts.push(`routing=${world.routing}`);
  if (world.waf?.vendor) parts.push(`waf=${world.waf.vendor}`);
  if (world.auth?.mode) parts.push(`auth=${world.auth.mode}${world.auth.csrf ? `/csrf:${world.auth.csrf}` : ""}`);
  if (world.interestingParams?.length) parts.push(`params=${world.interestingParams.slice(0, 12).join(",")}`);
  return parts.join(" | ") || "(empty world model)";
}
