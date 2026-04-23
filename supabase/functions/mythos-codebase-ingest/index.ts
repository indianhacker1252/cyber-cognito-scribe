// Pillar 1: Codebase ingestion + taint analysis
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

const SOURCES = ["req.body", "req.query", "req.params", "request.GET", "request.POST", "$_GET", "$_POST", "$_REQUEST", "params[", "ctx.request"];
const SINKS: Record<string, RegExp[]> = {
  sql_injection: [/\.query\s*\(/i, /\.execute\s*\(/i, /sequelize\.literal/i, /raw\s*\(/i, /SELECT\s+.*\$\{/i],
  command_injection: [/exec\s*\(/i, /spawn\s*\(/i, /system\s*\(/i, /shell_exec/i, /Runtime\.getRuntime/i],
  xss: [/innerHTML\s*=/i, /dangerouslySetInnerHTML/i, /document\.write/i, /\.html\s*\(/i],
  ssrf: [/fetch\s*\(/i, /axios\.(get|post)/i, /requests\.(get|post)/i, /http\.get/i, /urlopen/i],
  path_traversal: [/readFile\s*\(/i, /open\s*\(/i, /createReadStream/i, /sendFile/i],
  deserialization: [/pickle\.loads/i, /unserialize/i, /yaml\.load/i, /JSON\.parse/i],
  ssti: [/render_template_string/i, /Template\s*\(/i, /eval\s*\(/i],
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  try {
    const { targetId, repoUrl, branch = "main", sourceFiles } = await req.json();
    if (!targetId) throw new Error("targetId required");

    const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

    const { data: repo, error: repoErr } = await db.from("code_repositories").insert({
      target_id: targetId, repo_url: repoUrl ?? null, branch, ingestion_status: "scanning",
    }).select().single();
    if (repoErr) throw repoErr;

    let files: Array<{ path: string; content: string }> = [];

    if (sourceFiles && Array.isArray(sourceFiles)) {
      files = sourceFiles.slice(0, 50);
    } else if (repoUrl) {
      // Fetch via GitHub raw API (lightweight — no clone)
      const m = repoUrl.match(/github\.com\/([^\/]+)\/([^\/\s]+)/);
      if (m) {
        const [, owner, rawRepo] = m;
        const repoName = rawRepo.replace(/\.git$/, "");
        const treeResp = await fetch(`https://api.github.com/repos/${owner}/${repoName}/git/trees/${branch}?recursive=1`);
        if (treeResp.ok) {
          const tree = await treeResp.json();
          const codeFiles = (tree.tree || [])
            .filter((n: any) => n.type === "blob" && /\.(js|ts|jsx|tsx|py|php|rb|java|go)$/i.test(n.path))
            .slice(0, 30);
          for (const f of codeFiles) {
            const r = await fetch(`https://raw.githubusercontent.com/${owner}/${repoName}/${branch}/${f.path}`);
            if (r.ok) files.push({ path: f.path, content: (await r.text()).slice(0, 20000) });
          }
        }
      }
    }

    const findings: any[] = [];
    for (const f of files) {
      const lines = f.content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const hasSource = SOURCES.some(s => line.includes(s));
        if (!hasSource) continue;
        // Look forward 15 lines for a sink
        const window = lines.slice(i, Math.min(i + 15, lines.length)).join("\n");
        for (const [vulnClass, patterns] of Object.entries(SINKS)) {
          if (patterns.some(p => p.test(window))) {
            const sinkLine = lines.slice(i, i + 15).findIndex(l => patterns.some(p => p.test(l)));
            findings.push({
              repository_id: repo.id,
              target_id: targetId,
              vuln_class: vulnClass,
              severity: vulnClass === "command_injection" || vulnClass === "deserialization" ? "critical" : "high",
              file_path: f.path,
              line_start: i + 1,
              line_end: i + sinkLine + 1,
              source_snippet: line.trim().slice(0, 300),
              sink_snippet: lines[i + sinkLine]?.trim().slice(0, 300),
              taint_path: [{ from: "user_input", line: i + 1 }, { to: vulnClass, line: i + sinkLine + 1 }],
              ai_reasoning: `User-controlled data flows from line ${i + 1} into ${vulnClass} sink at line ${i + sinkLine + 1} without sanitization.`,
            });
            break;
          }
        }
      }
    }

    if (findings.length) await db.from("code_findings").insert(findings);

    await db.from("code_repositories").update({
      ingestion_status: "complete",
      file_count: files.length,
      ingestion_log: [{ ts: new Date().toISOString(), msg: `Scanned ${files.length} files, found ${findings.length} taint flows` }],
    }).eq("id", repo.id);

    await db.from("scan_logs").insert({
      target_id: targetId, log_type: "info",
      message: `🧠 Mythos SAST: ${findings.length} taint flows found in ${files.length} files`,
      metadata: { repository_id: repo.id, findings: findings.length },
    });

    return new Response(JSON.stringify({ repositoryId: repo.id, fileCount: files.length, findingsCount: findings.length, findings: findings.slice(0, 10) }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    console.error(e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : String(e) }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
