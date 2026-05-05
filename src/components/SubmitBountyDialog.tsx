import { useState } from "react";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { supabase } from "@/integrations/supabase/client";
import { toast } from "sonner";
import { Send, Copy, Download } from "lucide-react";

interface Props {
  finding: any;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}

export default function SubmitBountyDialog({ finding, open, onOpenChange }: Props) {
  const [platform, setPlatform] = useState<"hackerone" | "bugcrowd" | "export">("hackerone");
  const [program, setProgram] = useState("");
  const [busy, setBusy] = useState(false);
  const [exported, setExported] = useState<string | null>(null);

  const submit = async () => {
    setBusy(true);
    setExported(null);
    try {
      const { data, error } = await supabase.functions.invoke("bb-submit", {
        body: { findingId: finding.id, platform, programHandle: program || undefined },
      });
      if (error) throw error;
      if (data?.status === "submitted") {
        toast.success(`Submitted to ${platform} (id: ${data.remoteId || "n/a"})`);
        onOpenChange(false);
      } else if (data?.status === "exported") {
        setExported(data.result?.markdown || "");
        toast.message(`Exported as Markdown — ${data.result?.exportReason || "ready to copy"}`);
      } else {
        toast.error(data?.result?.error || "Submission failed");
      }
    } catch (e: any) {
      toast.error(e.message);
    } finally { setBusy(false); }
  };

  const copyMd = () => {
    if (!exported) return;
    navigator.clipboard.writeText(exported);
    toast.success("Copied to clipboard");
  };
  const downloadMd = () => {
    if (!exported) return;
    const blob = new Blob([exported], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `finding-${finding.id}.md`; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="font-mono">Submit to Bug Bounty Platform</DialogTitle>
          <DialogDescription className="font-mono text-xs">
            {finding?.title} — {finding?.severity}
          </DialogDescription>
        </DialogHeader>
        <Tabs value={platform} onValueChange={(v) => setPlatform(v as any)}>
          <TabsList>
            <TabsTrigger value="hackerone">HackerOne</TabsTrigger>
            <TabsTrigger value="bugcrowd">Bugcrowd</TabsTrigger>
            <TabsTrigger value="export">Export Markdown</TabsTrigger>
          </TabsList>
          <TabsContent value="hackerone" className="space-y-3">
            <Label>Program handle (optional, uses default if blank)</Label>
            <Input value={program} onChange={(e) => setProgram(e.target.value)} placeholder="e.g. acme" />
            <p className="text-[11px] text-muted-foreground font-mono">
              Requires H1 username + API token in Settings → Bug Bounty. If missing, falls back to Markdown export.
            </p>
          </TabsContent>
          <TabsContent value="bugcrowd" className="space-y-3">
            <Label>Program handle (required for API submit)</Label>
            <Input value={program} onChange={(e) => setProgram(e.target.value)} placeholder="e.g. acme-public" />
            <p className="text-[11px] text-muted-foreground font-mono">
              Requires Bugcrowd API token in Settings. If missing, falls back to Markdown export.
            </p>
          </TabsContent>
          <TabsContent value="export">
            <p className="text-xs text-muted-foreground font-mono">Generate a perfectly formatted submission you can paste into any platform.</p>
          </TabsContent>
        </Tabs>

        {exported && (
          <div className="space-y-2">
            <Label className="font-mono text-xs">Submission Markdown</Label>
            <Textarea value={exported} readOnly className="font-mono text-[11px] h-64" />
            <div className="flex gap-2">
              <Button size="sm" variant="outline" onClick={copyMd}><Copy className="h-3 w-3 mr-1" />Copy</Button>
              <Button size="sm" variant="outline" onClick={downloadMd}><Download className="h-3 w-3 mr-1" />Download .md</Button>
            </div>
          </div>
        )}

        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>Close</Button>
          <Button onClick={submit} disabled={busy}>
            <Send className="h-3 w-3 mr-1" />
            {busy ? "Submitting..." : platform === "export" ? "Generate Markdown" : "Submit"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
