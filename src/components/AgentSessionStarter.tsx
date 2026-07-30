import { useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "sonner";
import { Rocket } from "lucide-react";

// Kicks off an Option-B agent session (VPS runtime picks it up within ~3s)
export function AgentSessionStarter({ targetId }: { targetId: string }) {
  const [provider, setProvider] = useState<"lovable" | "openai" | "gemini">("lovable");
  const [busy, setBusy] = useState(false);

  const modelFor = {
    lovable: "google/gemini-3.6-flash",
    openai: "gpt-4.1-mini",
    gemini: "gemini-2.0-flash-exp",
  }[provider];

  async function start() {
    setBusy(true);
    try {
      const { data, error } = await supabase.functions.invoke("agent-start", {
        body: { target_id: targetId, provider, model: modelFor, budget_credits: 300, budget_seconds: 3600 },
      });
      if (error) throw error;
      if ((data as any)?.error) throw new Error((data as any).error);
      toast.success("Agent session queued", { description: `session ${(data as any).session.id.slice(0, 8)} — VPS runtime will pick it up.` });
    } catch (e: any) {
      toast.error("Failed to start agent", { description: e?.message ?? String(e) });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex items-center gap-2">
      <Select value={provider} onValueChange={(v) => setProvider(v as any)}>
        <SelectTrigger className="w-40 h-9"><SelectValue /></SelectTrigger>
        <SelectContent>
          <SelectItem value="lovable">Lovable AI (Gemini)</SelectItem>
          <SelectItem value="openai">OpenAI (direct)</SelectItem>
          <SelectItem value="gemini">Gemini (direct)</SelectItem>
        </SelectContent>
      </Select>
      <Button onClick={start} disabled={busy} size="sm" className="gap-2">
        <Rocket className="w-4 h-4" />
        {busy ? "Starting…" : "Start Agent Scan"}
      </Button>
    </div>
  );
}
