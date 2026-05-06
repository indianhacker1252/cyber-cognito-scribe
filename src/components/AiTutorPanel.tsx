import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { supabase } from "@/integrations/supabase/client";
import { toast } from "sonner";
import { GraduationCap, BookOpen, Sparkles } from "lucide-react";

export default function AiTutorPanel() {
  const [busy, setBusy] = useState(false);
  const [counts, setCounts] = useState<{ corpus: number; sessions: number }>({ corpus: 0, sessions: 0 });

  const refresh = async () => {
    const { count: c1 } = await supabase.from("rag_corpus").select("id", { head: true, count: "exact" });
    const { count: c2 } = await supabase.from("ai_tutoring_sessions").select("id", { head: true, count: "exact" });
    setCounts({ corpus: c1 || 0, sessions: c2 || 0 });
  };
  useEffect(() => { refresh(); }, []);

  const distill = async () => {
    setBusy(true);
    try {
      const { data, error } = await supabase.functions.invoke("ai-tutor-distill", { body: {} });
      if (error) throw error;
      if (!data?.ok) throw new Error(data?.error || "failed");
      toast.success(`Distilled ${data.inserted}/${data.phases} VAPT playbooks into local RAG corpus`);
      refresh();
    } catch (e: any) { toast.error(e.message); }
    finally { setBusy(false); }
  };

  return (
    <Card className="border-border bg-card">
      <CardHeader>
        <CardTitle className="font-mono text-sm flex items-center gap-2">
          <GraduationCap className="h-4 w-4 text-cyber-cyan" /> AI Tutor (Gemini → Local Model)
        </CardTitle>
        <CardDescription className="font-mono text-xs">
          Gemini distills VAPT methodology into a local RAG corpus your offline Ollama queries during scans.
          Hard cases also trigger live tutoring; corrections are fed back into the corpus.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex gap-3">
          <Badge variant="outline" className="font-mono text-[10px] gap-1">
            <BookOpen className="h-3 w-3" /> Corpus: {counts.corpus} entries
          </Badge>
          <Badge variant="outline" className="font-mono text-[10px] gap-1">
            <Sparkles className="h-3 w-3" /> Tutor sessions: {counts.sessions}
          </Badge>
        </div>
        <Button onClick={distill} disabled={busy} size="sm" className="font-mono text-xs gap-1">
          <GraduationCap className="h-3 w-3" /> {busy ? "Distilling…" : "Distill VAPT corpus from Gemini"}
        </Button>
        <p className="text-[10px] text-muted-foreground font-mono">
          Admin only. Runs ~9 phases × ~1 LLM call each. Costs Gemini credits but only once per refresh.
        </p>
      </CardContent>
    </Card>
  );
}
