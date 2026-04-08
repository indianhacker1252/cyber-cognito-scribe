import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { Key, Sparkles, ShieldCheck, Trash2, Save } from "lucide-react";

interface ProviderConfig {
  id: string;
  provider: string;
  api_key: string;
  is_active: boolean;
  priority: number;
}

const PROVIDERS = [
  {
    id: "gemini",
    name: "Google Gemini",
    description: "Uses Gemini 2.5 Flash. Get API key from Google AI Studio.",
    link: "https://aistudio.google.com/apikey",
    placeholder: "AIza...",
  },
  {
    id: "openai",
    name: "OpenAI / ChatGPT",
    description: "Uses GPT-4o-mini. Get API key from OpenAI Platform.",
    link: "https://platform.openai.com/api-keys",
    placeholder: "sk-...",
  },
];

export default function Settings() {
  const queryClient = useQueryClient();
  const [keys, setKeys] = useState<Record<string, string>>({});

  const { data: configs, isLoading } = useQuery({
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
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ai-provider-config"] });
      toast.success("API key saved");
    },
    onError: (e) => toast.error(`Failed: ${e.message}`),
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
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ai-provider-config"] });
      toast.success("Provider removed");
    },
  });

  const getExistingConfig = (provider: string) => configs?.find((c) => c.provider === provider);

  return (
    <div className="space-y-6 max-w-3xl">
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
                    <Switch
                      checked={existing.is_active}
                      onCheckedChange={(checked) => toggleProvider.mutate({ id: existing.id, is_active: checked })}
                    />
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
                <Input
                  type="password"
                  placeholder={p.placeholder}
                  value={inputKey}
                  onChange={(e) => setKeys((prev) => ({ ...prev, [p.id]: e.target.value }))}
                  className="font-mono text-xs h-9"
                />
                <Button
                  size="sm"
                  className="h-9"
                  disabled={!inputKey.trim()}
                  onClick={() => {
                    upsertProvider.mutate({ provider: p.id, api_key: inputKey.trim(), priority: idx + 1 });
                    setKeys((prev) => ({ ...prev, [p.id]: "" }));
                  }}
                >
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

      <Card className="border-border">
        <CardContent className="p-4">
          <p className="text-xs text-muted-foreground font-mono">
            <strong>Fallback order:</strong> Lovable AI → Google Gemini → OpenAI. The system auto-switches when a 402 (credits exhausted) error is received.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
