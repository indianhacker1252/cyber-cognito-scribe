import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import { useAuth } from "@/hooks/useAuth";
import { Send } from "lucide-react";

export default function BugBountySettings() {
  const { user } = useAuth();
  const [t, setT] = useState({ h1_username: "", h1_api_token: "", h1_program_handle: "", bc_api_token: "", bc_program_handle: "" });
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!user) return;
    supabase.from("bug_bounty_tokens").select("*").eq("user_id", user.id).maybeSingle()
      .then(({ data }) => { if (data) setT({ ...t, ...data } as any); });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user]);

  const save = async () => {
    if (!user) return;
    setLoading(true);
    const { error } = await supabase.from("bug_bounty_tokens").upsert({ user_id: user.id, ...t });
    setLoading(false);
    if (error) toast.error(error.message); else toast.success("Bug bounty tokens saved");
  };

  return (
    <Card>
      <CardHeader><CardTitle className="font-mono text-sm flex items-center gap-2"><Send className="h-4 w-4" />Bug Bounty Submission</CardTitle></CardHeader>
      <CardContent className="space-y-3">
        <div className="grid grid-cols-2 gap-3">
          <div><Label className="text-xs">HackerOne Username</Label><Input value={t.h1_username || ""} onChange={(e) => setT({ ...t, h1_username: e.target.value })} /></div>
          <div><Label className="text-xs">HackerOne API Token</Label><Input type="password" value={t.h1_api_token || ""} onChange={(e) => setT({ ...t, h1_api_token: e.target.value })} /></div>
          <div><Label className="text-xs">H1 Default Program Handle</Label><Input value={t.h1_program_handle || ""} onChange={(e) => setT({ ...t, h1_program_handle: e.target.value })} /></div>
          <div></div>
          <div><Label className="text-xs">Bugcrowd API Token</Label><Input type="password" value={t.bc_api_token || ""} onChange={(e) => setT({ ...t, bc_api_token: e.target.value })} /></div>
          <div><Label className="text-xs">BC Default Program Handle</Label><Input value={t.bc_program_handle || ""} onChange={(e) => setT({ ...t, bc_program_handle: e.target.value })} /></div>
        </div>
        <p className="text-[10px] font-mono text-muted-foreground">Tokens are stored per user (RLS). When missing, submissions fall back to Markdown export you can paste manually.</p>
        <Button onClick={save} disabled={loading} className="font-mono text-xs">{loading ? "Saving..." : "Save Tokens"}</Button>
      </CardContent>
    </Card>
  );
}
