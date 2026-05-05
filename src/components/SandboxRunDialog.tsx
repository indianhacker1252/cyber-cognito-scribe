import { useState } from "react";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { supabase } from "@/integrations/supabase/client";
import { toast } from "sonner";
import { Box, Play } from "lucide-react";

interface Props { finding: any; open: boolean; onOpenChange: (o: boolean) => void; }

const TEMPLATES: Record<string, string> = {
  "curl-basic": `curl -sk -i "TARGET_URL"`,
  "curl-payload": `curl -sk -i "TARGET_URL?test=PAYLOAD"`,
  "python-diff": `import requests
r1 = requests.get("TARGET_URL", params={"test":"1"}, timeout=10)
r2 = requests.get("TARGET_URL", params={"test":"PAYLOAD"}, timeout=10)
print("diff:", abs(len(r1.text)-len(r2.text)))`,
};

export default function SandboxRunDialog({ finding, open, onOpenChange }: Props) {
  const [language, setLanguage] = useState<"curl" | "python" | "bash">("curl");
  const [mode, setMode] = useState<"auto" | "worker" | "edge">("auto");
  const [script, setScript] = useState(
    TEMPLATES["curl-payload"]
      .replace("TARGET_URL", finding?.endpoint_url || "https://example.com")
      .replace("PAYLOAD", encodeURIComponent(finding?.payload || "test"))
  );
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<any>(null);

  const run = async () => {
    setBusy(true); setResult(null);
    try {
      const { data, error } = await supabase.functions.invoke("sandbox-exec", {
        body: { findingId: finding.id, targetId: finding.target_id, script, language, mode },
      });
      if (error) throw error;
      setResult(data);
      if (data?.proven) toast.success(`Sandbox PROVEN via ${data.executor}`);
      else if (data?.ok) toast.message(`Sandbox completed via ${data.executor}`);
      else toast.error("Sandbox run failed");
    } catch (e: any) { toast.error(e.message); }
    finally { setBusy(false); }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl">
        <DialogHeader>
          <DialogTitle className="font-mono flex items-center gap-2"><Box className="h-4 w-4" /> Sandboxed Exploit Run</DialogTitle>
          <DialogDescription className="font-mono text-xs">
            Tries your Docker worker first, falls back to edge sandbox automatically.
          </DialogDescription>
        </DialogHeader>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <Label className="text-xs">Language</Label>
            <Select value={language} onValueChange={(v: any) => setLanguage(v)}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="curl">curl</SelectItem>
                <SelectItem value="python">python</SelectItem>
                <SelectItem value="bash">bash</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label className="text-xs">Executor mode</Label>
            <Select value={mode} onValueChange={(v: any) => setMode(v)}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="auto">Auto (worker → edge)</SelectItem>
                <SelectItem value="worker">Worker only</SelectItem>
                <SelectItem value="edge">Edge only</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
        <div>
          <Label className="text-xs">Script</Label>
          <Textarea value={script} onChange={(e) => setScript(e.target.value)} className="font-mono text-[11px] h-44" />
        </div>
        {result && (
          <div className="rounded border border-border bg-muted/30 p-2">
            <p className="font-mono text-[10px] text-muted-foreground mb-1">
              executor=<span className="text-primary">{result.executor}</span>{" "}
              proven=<span className={result.proven ? "text-cyber-green" : "text-muted-foreground"}>{String(result.proven)}</span>
            </p>
            <pre className="font-mono text-[11px] whitespace-pre-wrap max-h-60 overflow-auto">{result.output}</pre>
          </div>
        )}
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>Close</Button>
          <Button onClick={run} disabled={busy}><Play className="h-3 w-3 mr-1" />{busy ? "Running..." : "Run in Sandbox"}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
