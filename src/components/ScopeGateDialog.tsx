import { useEffect, useState } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter, DialogDescription } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Badge } from "@/components/ui/badge";
import { ShieldCheck, ShieldAlert } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { toast } from "sonner";

type Mode = "unauthorized" | "attestation" | "bug_bounty" | "both";

export function ScopeGateDialog({ targetId, targetName }: { targetId: string; targetName: string }) {
  const [open, setOpen] = useState(false);
  const [mode, setMode] = useState<Mode>("unauthorized");
  const [attested, setAttested] = useState(false);
  const [program, setProgram] = useState("");
  const [scopeUrl, setScopeUrl] = useState("");
  const [notes, setNotes] = useState("");
  const [saving, setSaving] = useState(false);
  const [authorized, setAuthorized] = useState(false);

  useEffect(() => {
    if (!open) return;
    (async () => {
      const { data } = await supabase
        .from("target_workspaces")
        .select("authorization_mode,attestation_accepted,bug_bounty_program,bug_bounty_scope_url,authorization_notes")
        .eq("id", targetId).maybeSingle();
      if (data) {
        setMode((data.authorization_mode as Mode) || "unauthorized");
        setAttested(!!data.attestation_accepted);
        setProgram(data.bug_bounty_program || "");
        setScopeUrl(data.bug_bounty_scope_url || "");
        setNotes(data.authorization_notes || "");
      }
      const { data: ok } = await supabase.rpc("target_is_exploit_authorized", { _target_id: targetId });
      setAuthorized(!!ok);
    })();
  }, [open, targetId]);

  const save = async () => {
    setSaving(true);
    const { data: u } = await supabase.auth.getUser();
    const userId = u?.user?.id || null;
    const ok = (mode === "attestation" || mode === "both") ? attested : true;
    if (!ok && (mode === "attestation" || mode === "both")) {
      toast.error("Tick the attestation box to enable exploit-tier modules.");
      setSaving(false); return;
    }
    if ((mode === "bug_bounty" || mode === "both") && (!program.trim() || !scopeUrl.trim())) {
      toast.error("Bug bounty mode needs both program name and scope URL.");
      setSaving(false); return;
    }
    const { error } = await supabase.from("target_workspaces").update({
      authorization_mode: mode,
      attestation_accepted: attested,
      attestation_accepted_at: attested ? new Date().toISOString() : null,
      attestation_accepted_by: attested ? userId : null,
      bug_bounty_program: program || null,
      bug_bounty_scope_url: scopeUrl || null,
      authorization_notes: notes || null,
    }).eq("id", targetId);
    setSaving(false);
    if (error) { toast.error(error.message); return; }
    toast.success("Scope updated.");
    setOpen(false);
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" className="font-mono text-[10px] gap-1 border-amber-500/30 text-amber-400 hover:bg-amber-500/10">
          {authorized ? <ShieldCheck className="h-3 w-3" /> : <ShieldAlert className="h-3 w-3" />}
          Scope
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="font-mono">Scope &amp; Authorization — {targetName}</DialogTitle>
          <DialogDescription className="text-xs">
            Exploit-tier modules (exploit-engine, advanced-detectors) require an authorized scope. Recon/passive modules are unaffected.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 text-xs">
          <div className="flex items-center gap-2">
            <span className="font-mono">Current:</span>
            {authorized
              ? <Badge className="bg-emerald-600/20 text-emerald-300 border-emerald-500/40">AUTHORIZED</Badge>
              : <Badge className="bg-amber-600/20 text-amber-300 border-amber-500/40">NOT AUTHORIZED</Badge>}
          </div>

          <div className="space-y-1">
            <Label className="font-mono">Authorization mode</Label>
            <select value={mode} onChange={(e) => setMode(e.target.value as Mode)} className="w-full bg-muted border border-border rounded px-2 py-1 font-mono">
              <option value="unauthorized">Unauthorized (block exploit-tier)</option>
              <option value="attestation">Self-attestation only</option>
              <option value="bug_bounty">Bug bounty program scope only</option>
              <option value="both">Either path accepted</option>
            </select>
          </div>

          {(mode === "attestation" || mode === "both") && (
            <label className="flex items-start gap-2 cursor-pointer">
              <Checkbox checked={attested} onCheckedChange={(v) => setAttested(!!v)} />
              <span className="text-[11px] leading-snug">
                I confirm I own this asset OR I have written authorization to perform security testing against it. I accept full responsibility for the resulting requests.
              </span>
            </label>
          )}

          {(mode === "bug_bounty" || mode === "both") && (
            <>
              <div className="space-y-1">
                <Label className="font-mono">Bug bounty program</Label>
                <Input value={program} onChange={(e) => setProgram(e.target.value)} placeholder="HackerOne / Bugcrowd / Intigriti / private" />
              </div>
              <div className="space-y-1">
                <Label className="font-mono">Program scope URL</Label>
                <Input value={scopeUrl} onChange={(e) => setScopeUrl(e.target.value)} placeholder="https://hackerone.com/<program>" />
              </div>
            </>
          )}

          <div className="space-y-1">
            <Label className="font-mono">Notes (optional)</Label>
            <Input value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Ticket #, scope nuances, …" />
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
          <Button onClick={save} disabled={saving}>{saving ? "Saving…" : "Save scope"}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
