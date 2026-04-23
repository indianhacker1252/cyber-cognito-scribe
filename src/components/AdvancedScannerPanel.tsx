// Advanced Scanner Control Panel — exposes Sprint 1-4 capabilities per-target.
// Auth profiles, OOB tokens, exploit chains, JSON fuzzer, browser scan, canary drift, job queue.
import { useState, useEffect } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import { Switch } from "@/components/ui/switch";
import { Shield, Key, Link2, Code, Globe, Activity, Loader2, Brain } from "lucide-react";

interface Props { targetId: string; baseUrl: string; }

export const AdvancedScannerPanel = ({ targetId, baseUrl }: Props) => {
  const [authProfile, setAuthProfile] = useState<any>({
    auth_type: "cookie", cookie_header: "", bearer_token: "",
    login_url: "", login_username: "", login_password: "",
  });
  const [savingAuth, setSavingAuth] = useState(false);
  const [oobTokens, setOobTokens] = useState<any[]>([]);
  const [chains, setChains] = useState<any[]>([]);
  const [jsonEndpoint, setJsonEndpoint] = useState("");
  const [jsonBody, setJsonBody] = useState(`{"username":"test","email":"a@b.c"}`);
  const [busy, setBusy] = useState<string | null>(null);
  const [jobs, setJobs] = useState<any[]>([]);
  const [drifts, setDrifts] = useState<any[]>([]);
  const [mythosRuns, setMythosRuns] = useState<any[]>([]);
  const [mythosChains, setMythosChains] = useState<any[]>([]);
  const [mythosVariants, setMythosVariants] = useState<any[]>([]);
  const [mythosPatches, setMythosPatches] = useState<any[]>([]);
  const [mythosDebates, setMythosDebates] = useState<any[]>([]);
  const [autoMythos, setAutoMythos] = useState(false);
  const [repoUrl, setRepoUrl] = useState("");

  useEffect(() => { void loadAll(); }, [targetId]);

  const loadAll = async () => {
    const [{ data: ap }, { data: oob }, { data: ch }, { data: jb }, { data: dr }, { data: mr }, { data: mc }, { data: mv }, { data: mp }, mdRes, { data: tgt }] = await Promise.all([
      supabase.from("auth_profiles").select("*").eq("target_id", targetId).maybeSingle(),
      supabase.from("oob_callbacks").select("*").eq("target_id", targetId).order("created_at", { ascending: false }).limit(10),
      supabase.from("exploit_chains").select("*").eq("target_id", targetId).order("created_at", { ascending: false }).limit(5),
      supabase.from("scan_jobs").select("*").eq("target_id", targetId).order("created_at", { ascending: false }).limit(10),
      supabase.from("canary_baselines").select("*").eq("target_id", targetId).order("last_checked_at", { ascending: false }),
      supabase.from("mythos_runs").select("*").eq("target_id", targetId).order("created_at", { ascending: false }).limit(5),
      supabase.from("mythos_chains").select("*").eq("target_id", targetId).order("created_at", { ascending: false }).limit(8),
      supabase.from("mythos_variants").select("*").eq("target_id", targetId).order("created_at", { ascending: false }).limit(10),
      supabase.from("mythos_patches").select("*").eq("target_id", targetId).order("created_at", { ascending: false }).limit(8),
      (supabase.from("mythos_debates" as any).select("*").eq("target_id", targetId).order("created_at", { ascending: false }).limit(6)) as any,
      supabase.from("target_workspaces").select("auto_mythos").eq("id", targetId).maybeSingle(),
    ]);
    if (ap) setAuthProfile(ap);
    setOobTokens(oob || []);
    setChains(ch || []);
    setJobs(jb || []);
    setDrifts(dr || []);
    setMythosRuns(mr || []);
    setMythosChains(mc || []);
    setMythosVariants(mv || []);
    setMythosPatches(mp || []);
    setMythosDebates(((mdRes as any)?.data as any[]) || []);
    setAutoMythos(!!(tgt as any)?.auto_mythos);
  };

  const saveAuth = async () => {
    setSavingAuth(true);
    try {
      const { error } = await supabase.from("auth_profiles").upsert({
        target_id: targetId, profile_name: "default", ...authProfile,
      } as any, { onConflict: "target_id,profile_name" } as any);
      if (error) throw error;
      toast.success("Auth profile saved");
      void loadAll();
    } catch (e: any) { toast.error(e.message); }
    finally { setSavingAuth(false); }
  };

  const issueOob = async () => {
    setBusy("oob");
    const { data, error } = await supabase.functions.invoke("oob-collector", {
      body: { targetId, vulnClass: "manual", payloadContext: "manual issue" },
    });
    setBusy(null);
    if (error) return toast.error(error.message);
    toast.success(`OOB token issued: ${data.token}`);
    void loadAll();
  };

  const enqueueJob = async (type: string, payload: any = {}) => {
    setBusy(type);
    const { error } = await supabase.from("scan_jobs").insert({
      target_id: targetId, job_type: type, payload, priority: 7,
    });
    setBusy(null);
    if (error) return toast.error(error.message);
    toast.success(`Queued ${type} job — worker picks within 60s`);
    void loadAll();
  };

  const runJsonFuzz = async () => {
    setBusy("json_fuzz");
    try {
      const sample = JSON.parse(jsonBody);
      const { data, error } = await supabase.functions.invoke("json-fuzzer", {
        body: { targetId, endpoint: jsonEndpoint, method: "POST", sampleBody: sample },
      });
      if (error) throw error;
      toast.success(`JSON fuzz: ${data.findings?.length || 0} hits across ${data.testsRun} tests`);
    } catch (e: any) { toast.error(e.message); }
    setBusy(null);
  };

  const runBrowserScan = async () => {
    setBusy("browser");
    const { data, error } = await supabase.functions.invoke("headless-browser", {
      body: { targetId, url: baseUrl },
    });
    setBusy(null);
    if (error) return toast.error(error.message);
    toast.success(`Browser scan (${data.mode}) — ${data.endpoints?.length || 0} SPA endpoints`);
  };

  const runCanary = async () => {
    setBusy("canary");
    const { data, error } = await supabase.functions.invoke("canary-drift-monitor", {
      body: { targetId, baseUrl },
    });
    setBusy(null);
    if (error) return toast.error(error.message);
    toast.success(`Canary drift: ${data.drifts?.length || 0} drifted of ${data.canariesTested}`);
    void loadAll();
  };

  const runMythos = async () => {
    setBusy("mythos");
    toast.info("🧠 Mythos agent starting — this may take 1-3 minutes");
    const { data, error } = await supabase.functions.invoke("mythos-agent", {
      body: { targetId, triggerType: "manual", maxIterations: 3, repoUrl: repoUrl || undefined },
    });
    setBusy(null);
    if (error) return toast.error(error.message);
    if (data?.error) return toast.error(data.error);
    toast.success(`✅ Mythos: ${data.totalChains} chains, ${data.totalVariants} variants, ${data.totalFindings} SAST findings`);
    void loadAll();
  };

  const ingestRepo = async () => {
    if (!repoUrl) return toast.error("Enter a GitHub repo URL");
    setBusy("sast");
    const { data, error } = await supabase.functions.invoke("mythos-codebase-ingest", {
      body: { targetId, repoUrl },
    });
    setBusy(null);
    if (error) return toast.error(error.message);
    toast.success(`SAST: ${data.findingsCount} taint flows in ${data.fileCount} files`);
    void loadAll();
  };

  const generatePatch = async (findingId: string) => {
    setBusy(`patch-${findingId}`);
    const { data, error } = await supabase.functions.invoke("mythos-patcher", {
      body: { findingId, targetId },
    });
    setBusy(null);
    if (error) return toast.error(error.message);
    toast.success("Patch generated");
    void loadAll();
  };

  const toggleAutoMythos = async (val: boolean) => {
    setAutoMythos(val);
    const { error } = await supabase.from("target_workspaces").update({ auto_mythos: val } as any).eq("id", targetId);
    if (error) { toast.error(error.message); setAutoMythos(!val); }
    else toast.success(`Auto-Mythos ${val ? "enabled" : "disabled"} — runs after every recon`);
  };

  return (
    <Card className="border-primary/30">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-primary" />
          Advanced Scanner (Sprints 1–4)
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="mythos">
          <TabsList className="grid grid-cols-7">
            <TabsTrigger value="mythos"><Brain className="w-3 h-3 mr-1" />Mythos</TabsTrigger>
            <TabsTrigger value="auth"><Key className="w-3 h-3 mr-1" />Auth</TabsTrigger>
            <TabsTrigger value="oob"><Link2 className="w-3 h-3 mr-1" />OOB</TabsTrigger>
            <TabsTrigger value="chain"><Activity className="w-3 h-3 mr-1" />Chains</TabsTrigger>
            <TabsTrigger value="json"><Code className="w-3 h-3 mr-1" />JSON Fuzz</TabsTrigger>
            <TabsTrigger value="browser"><Globe className="w-3 h-3 mr-1" />Browser</TabsTrigger>
            <TabsTrigger value="drift">Drift / Jobs</TabsTrigger>
          </TabsList>

          <TabsContent value="mythos" className="space-y-3 pt-3">
            <div className="flex items-center justify-between border border-primary/40 rounded p-2 bg-primary/5">
              <div>
                <div className="text-sm font-semibold flex items-center gap-2"><Brain className="w-4 h-4 text-primary" />Auto-Mythos after Recon</div>
                <div className="text-xs text-muted-foreground">Long-horizon agent runs automatically when recon completes</div>
              </div>
              <Switch checked={autoMythos} onCheckedChange={toggleAutoMythos} />
            </div>

            <div className="space-y-2">
              <Label className="text-xs">Optional: GitHub repo URL for SAST taint analysis (Pillar 1)</Label>
              <div className="flex gap-2">
                <Input placeholder="https://github.com/owner/repo" value={repoUrl} onChange={(e) => setRepoUrl(e.target.value)} />
                <Button size="sm" variant="outline" onClick={ingestRepo} disabled={busy === "sast" || !repoUrl}>
                  {busy === "sast" ? <Loader2 className="w-3 h-3 animate-spin" /> : "SAST"}
                </Button>
              </div>
            </div>

            <Button className="w-full" onClick={runMythos} disabled={busy === "mythos"}>
              {busy === "mythos" ? <Loader2 className="w-3 h-3 animate-spin mr-1" /> : <Brain className="w-3 h-3 mr-1" />}
              Run Mythos Agent (5 Pillars: SAST + Chainer + Variants + Patches)
            </Button>

            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="border border-border rounded p-2">
                <div className="font-semibold mb-1">Recent Runs</div>
                {mythosRuns.length === 0 && <div className="text-muted-foreground">No runs yet</div>}
                {mythosRuns.map((r) => (
                  <div key={r.id} className="flex justify-between border-b border-border py-1">
                    <span>{r.current_phase} ({r.iteration}/{r.max_iterations})</span>
                    <Badge variant={r.status === "complete" ? "default" : r.status === "running" ? "outline" : "destructive"}>{r.status}</Badge>
                  </div>
                ))}
              </div>
              <div className="border border-border rounded p-2">
                <div className="font-semibold mb-1">🔗 Auto Kill-Chains</div>
                {mythosChains.length === 0 && <div className="text-muted-foreground">None discovered</div>}
                {mythosChains.map((c) => (
                  <div key={c.id} className="border-b border-border py-1">
                    <div className="flex justify-between"><span className="truncate">{c.chain_name}</span><Badge>{c.combined_severity}</Badge></div>
                    <div className="text-muted-foreground text-[10px] truncate">{c.chain_narrative}</div>
                  </div>
                ))}
              </div>
            </div>

            <div className="border border-border rounded p-2 text-xs">
              <div className="font-semibold mb-1">🌀 Zero-Day Variants</div>
              {mythosVariants.length === 0 && <div className="text-muted-foreground">No variants yet</div>}
              {mythosVariants.map((v) => (
                <div key={v.id} className="flex justify-between border-b border-border py-1">
                  <code className="truncate max-w-[60%]">{v.variant_payload}</code>
                  <Badge variant={v.is_zero_day_candidate ? "destructive" : "outline"}>
                    {v.is_zero_day_candidate ? "🚨 0-DAY" : v.test_status}
                  </Badge>
                </div>
              ))}
            </div>

            <div className="border border-border rounded p-2 text-xs">
              <div className="font-semibold mb-1">🛡️ Defensive Patches (validated)</div>
              {mythosPatches.length === 0 && <div className="text-muted-foreground">No patches generated yet</div>}
              {mythosPatches.map((p) => (
                <details key={p.id} className="border-b border-border py-1">
                  <summary className="cursor-pointer flex justify-between items-center gap-2">
                    <span className="truncate">{p.framework} / {p.language}</span>
                    <span className="flex gap-1">
                      <Badge variant={p.validation_status === "passed" ? "default" : p.validation_status === "failed" ? "destructive" : "outline"}>
                        {p.validation_status || "pending"} • risk {p.risk_score ?? "?"}
                      </Badge>
                      <Badge variant="outline">{p.patch_type}</Badge>
                    </span>
                  </summary>
                  <pre className="text-[10px] bg-muted/30 p-2 rounded mt-1 overflow-auto max-h-40 whitespace-pre-wrap">{p.patch_diff}</pre>
                  {p.waf_rule && <pre className="text-[10px] bg-muted/30 p-2 rounded mt-1 whitespace-pre-wrap">WAF: {p.waf_rule}</pre>}
                </details>
              ))}
            </div>

            <div className="border border-border rounded p-2 text-xs">
              <div className="font-semibold mb-1">🥷 Two-Agent Debates (FP elimination)</div>
              {mythosDebates.length === 0 && <div className="text-muted-foreground">No debates yet — runs during Mythos iterations</div>}
              {mythosDebates.map((d) => (
                <details key={d.id} className="border-b border-border py-1">
                  <summary className="cursor-pointer flex justify-between items-center gap-2">
                    <span className="truncate">{d.param_name} @ {(() => { try { return new URL(d.endpoint_url).pathname; } catch { return d.endpoint_url; } })()}</span>
                    <Badge variant={d.fp_verdict === "true_positive" ? "destructive" : d.fp_verdict === "false_positive" ? "outline" : "secondary"}>
                      {d.fp_verdict} • {d.confidence_score}%
                    </Badge>
                  </summary>
                  <div className="mt-1 space-y-1">
                    <div className="bg-muted/30 p-1 rounded"><span className="text-cyber-cyan font-bold">A:</span> {d.transcript?.[0]?.msg}</div>
                    <div className="bg-muted/30 p-1 rounded"><span className="text-cyber-green font-bold">B:</span> {d.transcript?.[1]?.msg}</div>
                    <div className="bg-muted/30 p-1 rounded"><span className="text-cyber-amber font-bold">⚔️ Payload:</span> <code>{d.agreed_payload}</code></div>
                    <div className="bg-muted/30 p-1 rounded text-[10px]"><span className="font-bold">Debate:</span> {d.fp_reasoning?.slice(0, 300)}</div>
                  </div>
                </details>
              ))}
            </div>
          </TabsContent>

          <TabsContent value="auth" className="space-y-3 pt-3">
            <Select value={authProfile.auth_type} onValueChange={(v) => setAuthProfile({ ...authProfile, auth_type: v })}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="cookie">Cookie header</SelectItem>
                <SelectItem value="bearer">Bearer token</SelectItem>
                <SelectItem value="login_replay">Login replay</SelectItem>
              </SelectContent>
            </Select>
            {authProfile.auth_type === "cookie" && (
              <div><Label>Cookie</Label><Textarea rows={2} value={authProfile.cookie_header || ""} onChange={(e) => setAuthProfile({ ...authProfile, cookie_header: e.target.value })} placeholder="session=abc; csrf=xyz" /></div>
            )}
            {authProfile.auth_type === "bearer" && (
              <div><Label>Bearer Token</Label><Input value={authProfile.bearer_token || ""} onChange={(e) => setAuthProfile({ ...authProfile, bearer_token: e.target.value })} /></div>
            )}
            {authProfile.auth_type === "login_replay" && (
              <div className="space-y-2">
                <Input placeholder="Login URL (POST endpoint)" value={authProfile.login_url || ""} onChange={(e) => setAuthProfile({ ...authProfile, login_url: e.target.value })} />
                <div className="grid grid-cols-2 gap-2">
                  <Input placeholder="Username" value={authProfile.login_username || ""} onChange={(e) => setAuthProfile({ ...authProfile, login_username: e.target.value })} />
                  <Input placeholder="Password" type="password" value={authProfile.login_password || ""} onChange={(e) => setAuthProfile({ ...authProfile, login_password: e.target.value })} />
                </div>
                <Input placeholder='Body template e.g. username={U}&password={P}' value={authProfile.login_body_template || ""} onChange={(e) => setAuthProfile({ ...authProfile, login_body_template: e.target.value })} />
                <Input placeholder='Optional regex to extract token, e.g. "token":"([^"]+)"' value={authProfile.session_extract_regex || ""} onChange={(e) => setAuthProfile({ ...authProfile, session_extract_regex: e.target.value })} />
              </div>
            )}
            <Button size="sm" onClick={saveAuth} disabled={savingAuth}>{savingAuth ? <Loader2 className="w-3 h-3 animate-spin mr-1" /> : null}Save Auth Profile</Button>
          </TabsContent>

          <TabsContent value="oob" className="space-y-3 pt-3">
            <Button size="sm" onClick={issueOob} disabled={busy === "oob"}>Issue New OOB Token</Button>
            <div className="text-xs space-y-1 max-h-48 overflow-auto">
              {oobTokens.map((t) => (
                <div key={t.id} className="flex justify-between border-b border-border py-1">
                  <code className="text-primary">{t.token}</code>
                  <Badge variant={t.received_at ? "default" : "outline"}>{t.received_at ? "🎯 HIT" : "waiting"}</Badge>
                </div>
              ))}
              {oobTokens.length === 0 && <div className="text-muted-foreground">No tokens yet.</div>}
            </div>
          </TabsContent>

          <TabsContent value="chain" className="space-y-3 pt-3">
            <Button size="sm" onClick={() => enqueueJob("chain", {
              chainName: "auth-bypass-then-idor-demo",
              steps: [
                { name: "fetch home", method: "GET", url: baseUrl, extract: [{ var: "csrf", from: "body", regex: 'csrf[_-]token["\']?\\s*[:=]\\s*["\']([^"\']+)' }] },
                { name: "probe IDOR", method: "GET", url: `${baseUrl}/api/users/1`, expect: { status: 200 } },
              ],
            })} disabled={busy === "chain"}>Run Demo Chain (Auth→IDOR)</Button>
            <div className="text-xs space-y-1 max-h-48 overflow-auto">
              {chains.map((c) => (
                <div key={c.id} className="border border-border rounded p-2">
                  <div className="flex justify-between"><span>{c.chain_name}</span><Badge>{c.status}</Badge></div>
                  <div className="text-muted-foreground">{(c.execution_log as any[])?.length || 0} steps executed</div>
                </div>
              ))}
              {chains.length === 0 && <div className="text-muted-foreground">No chains executed.</div>}
            </div>
          </TabsContent>

          <TabsContent value="json" className="space-y-3 pt-3">
            <Input placeholder="POST endpoint URL (e.g. https://app.com/api/users)" value={jsonEndpoint} onChange={(e) => setJsonEndpoint(e.target.value)} />
            <Textarea rows={4} value={jsonBody} onChange={(e) => setJsonBody(e.target.value)} placeholder='{"key":"value"}' />
            <Button size="sm" onClick={runJsonFuzz} disabled={busy === "json_fuzz" || !jsonEndpoint}>
              {busy === "json_fuzz" ? <Loader2 className="w-3 h-3 animate-spin mr-1" /> : null}Run Recursive JSON Fuzz
            </Button>
          </TabsContent>

          <TabsContent value="browser" className="space-y-3 pt-3">
            <p className="text-xs text-muted-foreground">Renders SPA + extracts XHR endpoints. Set <code>BROWSERLESS_API_KEY</code> secret for full headless mode; otherwise falls back to inline-script parsing.</p>
            <Button size="sm" onClick={runBrowserScan} disabled={busy === "browser"}>
              {busy === "browser" ? <Loader2 className="w-3 h-3 animate-spin mr-1" /> : null}Browser Scan
            </Button>
          </TabsContent>

          <TabsContent value="drift" className="space-y-3 pt-3">
            <Button size="sm" onClick={runCanary} disabled={busy === "canary"}>Run Canary Drift Now</Button>
            <div className="grid grid-cols-2 gap-2 text-xs">
              {drifts.map((d) => (
                <div key={d.id} className="border border-border rounded p-2 flex justify-between">
                  <span>{d.canary_name}</span>
                  <Badge variant={d.drift_detected ? "destructive" : d.baseline_blocked ? "default" : "outline"}>
                    {d.drift_detected ? "DRIFT" : d.baseline_blocked ? "blocked" : "ok"}
                  </Badge>
                </div>
              ))}
            </div>
            <div className="text-xs font-semibold mt-2">Recent jobs (queue worker runs every 60s):</div>
            <div className="text-xs space-y-1 max-h-32 overflow-auto">
              {jobs.map(j => (
                <div key={j.id} className="flex justify-between border-b border-border py-1">
                  <span>{j.job_type}</span>
                  <Badge variant={j.status === "done" ? "default" : j.status === "failed" ? "destructive" : "outline"}>{j.status}</Badge>
                </div>
              ))}
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};
