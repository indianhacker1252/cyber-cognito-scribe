import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import {
  Key, Sparkles, ShieldCheck, Trash2, Save, Container, Globe, Radio, CheckCircle2, XCircle, Loader2, Activity, Brain, Zap,
} from "lucide-react";

// ──────────────────────────────────────────────────────────────────────────
// AI provider section (existing)
// ──────────────────────────────────────────────────────────────────────────
interface ProviderConfig {
  id: string; provider: string; api_key: string; is_active: boolean; priority: number;
}

const PROVIDERS = [
  { id: "gemini", name: "Google Gemini", description: "Uses Gemini 2.5 Flash. Get API key from Google AI Studio.", link: "https://aistudio.google.com/apikey", placeholder: "AIza..." },
  { id: "openai", name: "OpenAI / ChatGPT", description: "Uses GPT-4o-mini. Get API key from OpenAI Platform.", link: "https://platform.openai.com/api-keys", placeholder: "sk-..." },
  { id: "anthropic", name: "Anthropic Claude", description: "Uses Claude 3.5 Sonnet. Get API key from Anthropic Console.", link: "https://console.anthropic.com/settings/keys", placeholder: "sk-ant-..." },
  { id: "ollama", name: "Local AI (Ollama)", description: "Connect to a local Ollama instance for offline VAPT analysis.", link: "https://ollama.com/download", placeholder: "http://localhost:11434" },
];

// ──────────────────────────────────────────────────────────────────────────
// External infrastructure section (new)
// ──────────────────────────────────────────────────────────────────────────
interface InfraRow {
  id?: string;
  service: "docker_worker" | "browserless" | "oob";
  mode: string;
  endpoint_url: string | null;
  auth_token: string | null;
  is_active: boolean;
  health_status?: string | null;
  last_health_check?: string | null;
}

const INFRA_DEFS = [
  {
    service: "docker_worker" as const,
    name: "Docker Worker (nuclei / ffuf / sqlmap)",
    icon: Container,
    description: "Container that runs nuclei, ffuf, and sqlmap and streams output back into your Live Neural Log.",
    modes: [
      { value: "self_hosted", label: "Self-hosted", hint: "Fly.io / Railway / VPS — see docker-worker-reference/README.md" },
    ],
    needsToken: true,
    healthPath: "/health",
  },
  {
    service: "browserless" as const,
    name: "Browserless (real Chromium)",
    icon: Globe,
    description: "Real browser rendering for SPA bug discovery (DOM XSS, postMessage, hidden XHRs).",
    modes: [
      { value: "cloud", label: "Browserless Cloud", hint: "Sign up at browserless.io — paste your API token below" },
      { value: "self_hosted", label: "Self-hosted", hint: "Run browserless/chrome on your own host" },
    ],
    needsToken: true,
  },
  {
    service: "oob" as const,
    name: "Out-of-Band (Blind SSRF / XXE / SQLi)",
    icon: Radio,
    description: "Callback collector for blind vulnerabilities. Use public oast.fun for MVP, self-hosted interactsh for production.",
    modes: [
      { value: "local", label: "Local (this server)", hint: "Default — uses this Lovable backend as the callback receiver" },
      { value: "oast_fun", label: "Public oast.fun", hint: "Free, shared, rate-limited — good for MVP" },
      { value: "self_hosted", label: "Self-hosted interactsh", hint: "Production-grade — needs DNS wildcard + interactsh-server on your VPS" },
    ],
    needsToken: false,
  },
];

export default function Settings() {
  const queryClient = useQueryClient();
  const [keys, setKeys] = useState<Record<string, string>>({});

  // ── AI providers ──
  const { data: configs } = useQuery({
    queryKey: ["ai-provider-config"],
    queryFn: async () => {
      const { data } = await supabase.from("ai_provider_config").select("*").order("priority");
      return (data || []) as ProviderConfig[];
    },
  });

  const upsertProvider = useMutation({
    mutationFn: async ({ provider, api_key, priority }: { provider: string; api_key: string; priority: number }) => {
      const { error } = await supabase.from("ai_provider_config").upsert(
        { provider, api_key, is_active: true, priority, updated_at: new Date().toISOString() },
        { onConflict: "provider" }
      );
      if (error) throw error;
    },
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["ai-provider-config"] }); toast.success("API key saved"); },
    onError: (e: Error) => toast.error(`Failed: ${e.message}`),
  });

  const toggleProvider = useMutation({
    mutationFn: async ({ id, is_active }: { id: string; is_active: boolean }) => {
      const { error } = await supabase.from("ai_provider_config").update({ is_active }).eq("id", id);
      if (error) throw error;
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["ai-provider-config"] }),
  });

  const deleteProvider = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await supabase.from("ai_provider_config").delete().eq("id", id);
      if (error) throw error;
    },
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["ai-provider-config"] }); toast.success("Provider removed"); },
  });

  const getExistingConfig = (provider: string) => configs?.find((c) => c.provider === provider);

  // ── External infra ──
  const { data: infraRows } = useQuery({
    queryKey: ["external-infra"],
    queryFn: async () => {
      const { data } = await (supabase as any).from("external_infra_config").select("*");
      return (data || []) as InfraRow[];
    },
  });

  const upsertInfra = useMutation({
    mutationFn: async (row: InfraRow) => {
      const { error } = await (supabase as any).from("external_infra_config").upsert(
        { ...row, updated_at: new Date().toISOString() },
        { onConflict: "service" }
      );
      if (error) throw error;
    },
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["external-infra"] }); toast.success("Configuration saved"); },
    onError: (e: Error) => toast.error(`Save failed: ${e.message}`),
  });

  const getInfra = (service: string): InfraRow =>
    infraRows?.find((r) => r.service === service) || {
      service: service as InfraRow["service"], mode: "disabled",
      endpoint_url: "", auth_token: "", is_active: false,
    };

  return (
    <div className="space-y-8 max-w-3xl pb-12">
      {/* ── AI Provider Settings ── */}
      <div>
        <h1 className="text-2xl font-mono font-bold text-foreground flex items-center gap-2">
          <Key className="h-6 w-6 text-primary" /> AI Provider Settings
        </h1>
        <p className="text-sm text-muted-foreground mt-1">
          Configure fallback AI providers. When Lovable AI credits are exhausted, the system automatically falls back to these providers.
        </p>
      </div>

      <Card className="border-primary/30 bg-primary/5">
        <CardContent className="p-4 flex items-center gap-3">
          <Sparkles className="h-5 w-5 text-primary shrink-0" />
          <div>
            <p className="text-sm font-mono font-semibold text-primary">Lovable AI (Default)</p>
            <p className="text-xs text-muted-foreground">Primary provider — always tried first. No configuration needed.</p>
          </div>
          <Badge variant="outline" className="ml-auto border-primary/50 text-primary">ACTIVE</Badge>
        </CardContent>
      </Card>

      {PROVIDERS.map((p, idx) => {
        const existing = getExistingConfig(p.id);
        const inputKey = keys[p.id] || "";
        const maskedKey = existing ? `${existing.api_key.slice(0, 6)}...${existing.api_key.slice(-4)}` : "";
        return (
          <Card key={p.id} className="border-border">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-base font-mono">{p.name}</CardTitle>
                  <CardDescription className="text-xs">{p.description}</CardDescription>
                </div>
                {existing && (
                  <div className="flex items-center gap-2">
                    <Switch checked={existing.is_active} onCheckedChange={(checked) => toggleProvider.mutate({ id: existing.id, is_active: checked })} />
                    <Badge variant={existing.is_active ? "default" : "secondary"} className="text-[10px]">
                      {existing.is_active ? "ACTIVE" : "DISABLED"}
                    </Badge>
                  </div>
                )}
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              {existing && (
                <div className="flex items-center gap-2 text-xs font-mono text-muted-foreground">
                  <ShieldCheck className="h-3.5 w-3.5 text-primary" />
                  Current key: <span className="text-foreground">{maskedKey}</span>
                  <Button variant="ghost" size="sm" className="h-6 px-2" onClick={() => deleteProvider.mutate(existing.id)}>
                    <Trash2 className="h-3 w-3 text-destructive" />
                  </Button>
                </div>
              )}
              <div className="flex gap-2">
                <Input type="password" placeholder={p.placeholder} value={inputKey}
                  onChange={(e) => setKeys((prev) => ({ ...prev, [p.id]: e.target.value }))}
                  className="font-mono text-xs h-9" />
                <Button size="sm" className="h-9" disabled={!inputKey.trim()}
                  onClick={() => {
                    upsertProvider.mutate({ provider: p.id, api_key: inputKey.trim(), priority: idx + 1 });
                    setKeys((prev) => ({ ...prev, [p.id]: "" }));
                  }}>
                  <Save className="h-3.5 w-3.5 mr-1" /> Save
                </Button>
              </div>
              <a href={p.link} target="_blank" rel="noopener noreferrer" className="text-[10px] text-primary hover:underline">
                Get API key →
              </a>
            </CardContent>
          </Card>
        );
      })}

      {/* ── External Infrastructure ── */}
      <div className="pt-6 border-t border-border">
        <h2 className="text-2xl font-mono font-bold text-foreground flex items-center gap-2">
          <Container className="h-6 w-6 text-primary" /> External Infrastructure
        </h2>
        <p className="text-sm text-muted-foreground mt-1">
          Connect external services to unlock real exploit tooling, browser-based scans, and out-of-band detection.
        </p>
      </div>

      {INFRA_DEFS.map((def) => (
        <InfraCard key={def.service} def={def} initial={getInfra(def.service)} onSave={(row) => upsertInfra.mutate(row)} />
      ))}

      <Card className="border-border">
        <CardContent className="p-4">
          <p className="text-xs text-muted-foreground font-mono">
            <strong>Fallback order:</strong> Lovable AI → OpenAI → Gemini → Anthropic → heuristics. Auto-switches on 402/429 errors.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────
// Infra config card — collapsible per service with mode picker + test button
// ──────────────────────────────────────────────────────────────────────────
function InfraCard({
  def, initial, onSave,
}: {
  def: typeof INFRA_DEFS[number];
  initial: InfraRow;
  onSave: (row: InfraRow) => void;
}) {
  const [mode, setMode] = useState(initial.mode || def.modes[0].value);
  const [endpoint, setEndpoint] = useState(initial.endpoint_url || "");
  const [token, setToken] = useState(initial.auth_token || "");
  const [active, setActive] = useState(initial.is_active);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; msg: string } | null>(null);

  useEffect(() => {
    setMode(initial.mode || def.modes[0].value);
    setEndpoint(initial.endpoint_url || "");
    setToken(initial.auth_token || "");
    setActive(initial.is_active);
  }, [initial.id]);

  const Icon = def.icon;
  const currentMode = def.modes.find((m) => m.value === mode) || def.modes[0];
  const showEndpoint = mode !== "local";
  const showToken = def.needsToken && mode !== "local";

  const handleTest = async () => {
    if (!endpoint) { toast.error("Endpoint required to test"); return; }
    setTesting(true); setTestResult(null);
    try {
      const url = endpoint.replace(/\/$/, "") + (def.healthPath || "");
      const headers: Record<string, string> = {};
      if (token && def.needsToken) headers["Authorization"] = `Bearer ${token}`;
      const r = await fetch(url, { headers, signal: AbortSignal.timeout(8000) });
      if (r.ok) {
        setTestResult({ ok: true, msg: `HTTP ${r.status} — reachable` });
      } else {
        setTestResult({ ok: false, msg: `HTTP ${r.status}` });
      }
    } catch (e) {
      setTestResult({ ok: false, msg: e instanceof Error ? e.message : "unreachable" });
    } finally {
      setTesting(false);
    }
  };

  return (
    <Card className="border-border">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Icon className="h-5 w-5 text-primary" />
            <div>
              <CardTitle className="text-base font-mono">{def.name}</CardTitle>
              <CardDescription className="text-xs">{def.description}</CardDescription>
            </div>
          </div>
          <Badge variant={active ? "default" : "secondary"} className="text-[10px]">
            {active ? "ACTIVE" : "DISABLED"}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Mode picker */}
        <div>
          <Label className="text-xs font-mono text-muted-foreground">Mode</Label>
          <RadioGroup value={mode} onValueChange={setMode} className="mt-2 space-y-2">
            {def.modes.map((m) => (
              <div key={m.value} className="flex items-start gap-2">
                <RadioGroupItem value={m.value} id={`${def.service}-${m.value}`} className="mt-1" />
                <Label htmlFor={`${def.service}-${m.value}`} className="cursor-pointer flex-1">
                  <div className="text-sm font-mono">{m.label}</div>
                  <div className="text-[11px] text-muted-foreground">{m.hint}</div>
                </Label>
              </div>
            ))}
          </RadioGroup>
        </div>

        {/* Endpoint */}
        {showEndpoint && (
          <div className="space-y-1">
            <Label className="text-xs font-mono text-muted-foreground">
              {def.service === "oob" && mode === "self_hosted" ? "Wildcard host (e.g. oob.example.com)" : "Endpoint URL"}
            </Label>
            <Input value={endpoint} onChange={(e) => setEndpoint(e.target.value)}
              placeholder="https://your-host.fly.dev" className="font-mono text-xs h-9" />
          </div>
        )}

        {/* Token */}
        {showToken && (
          <div className="space-y-1">
            <Label className="text-xs font-mono text-muted-foreground">Auth Token (Bearer)</Label>
            <Input type="password" value={token} onChange={(e) => setToken(e.target.value)}
              placeholder="paste token..." className="font-mono text-xs h-9" />
          </div>
        )}

        {/* Active toggle + test + save */}
        <div className="flex items-center justify-between pt-2 border-t border-border">
          <div className="flex items-center gap-2">
            <Switch checked={active} onCheckedChange={setActive} />
            <span className="text-xs font-mono text-muted-foreground">Enable</span>
          </div>
          <div className="flex gap-2">
            {showEndpoint && def.healthPath && (
              <Button size="sm" variant="outline" className="h-9" disabled={testing || !endpoint} onClick={handleTest}>
                {testing
                  ? <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" />
                  : testResult?.ok
                    ? <CheckCircle2 className="h-3.5 w-3.5 mr-1 text-primary" />
                    : testResult && !testResult.ok
                      ? <XCircle className="h-3.5 w-3.5 mr-1 text-destructive" />
                      : null}
                Test
              </Button>
            )}
            <Button size="sm" className="h-9" onClick={() => onSave({
              ...initial, service: def.service, mode, endpoint_url: endpoint, auth_token: token, is_active: active,
            })}>
              <Save className="h-3.5 w-3.5 mr-1" /> Save
            </Button>
          </div>
        </div>
        {testResult && (
          <p className={`text-[11px] font-mono ${testResult.ok ? "text-primary" : "text-destructive"}`}>
            {testResult.ok ? "✓" : "✗"} {testResult.msg}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
