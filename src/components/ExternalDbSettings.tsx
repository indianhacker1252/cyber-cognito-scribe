import { useState, useEffect } from "react";
import { supabase } from "@/integrations/supabase/client";
import { useAuth } from "@/hooks/useAuth";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { Database, CheckCircle2, XCircle, Loader2 } from "lucide-react";

export function ExternalDbSettings() {
  const { user } = useAuth();
  const [enabled, setEnabled] = useState(false);
  const [conn, setConn] = useState("");
  const [status, setStatus] = useState<{ ok?: boolean; at?: string; err?: string }>({});
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!user) return;
    supabase.from("external_db_config" as any).select("*").eq("user_id", user.id).maybeSingle()
      .then(({ data }) => {
        const d = data as any;
        if (d) {
          setEnabled(!!d.enabled);
          setConn(d.pg_connection_string || "");
          setStatus({ ok: d.last_test_ok, at: d.last_test_at, err: d.last_error });
        }
      });
  }, [user]);

  const save = async () => {
    if (!user) return;
    setBusy(true);
    const { error } = await supabase.from("external_db_config" as any).upsert({
      user_id: user.id, enabled, pg_connection_string: conn || null,
    });
    setBusy(false);
    if (error) toast.error(error.message); else toast.success("External DB settings saved");
  };

  const test = async () => {
    setBusy(true);
    const { data, error } = await supabase.functions.invoke("external-db-mirror", {
      body: { action: "test", connectionString: conn },
    });
    setBusy(false);
    if (error) { toast.error(error.message); return; }
    if ((data as any)?.ok) {
      toast.success("Connected — schema ready");
      setStatus({ ok: true, at: new Date().toISOString() });
    } else {
      toast.error((data as any)?.error || "Test failed");
      setStatus({ ok: false, at: new Date().toISOString(), err: (data as any)?.error });
    }
  };

  return (
    <Card className="border-border bg-card">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 font-mono text-sm">
          <Database className="h-4 w-4 text-primary" /> External Database (BYO Postgres)
        </CardTitle>
        <CardDescription className="text-xs">
          Mirror all your findings to your own Postgres database. Works with any Postgres provider — Neon, Supabase self-hosted, AWS RDS, or local Docker.
          Use a connection string like <code className="text-cyber-cyan">postgres://user:pass@host:5432/dbname</code>.
          See README for one-line local setup.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono text-muted-foreground">Enable mirroring</span>
          <Switch checked={enabled} onCheckedChange={setEnabled} />
        </div>
        <Input
          type="password"
          placeholder="postgres://user:password@host:5432/dbname"
          value={conn}
          onChange={(e) => setConn(e.target.value)}
          className="font-mono text-xs"
        />
        <div className="flex gap-2">
          <Button size="sm" onClick={test} disabled={busy || !conn}>
            {busy && <Loader2 className="h-3 w-3 animate-spin" />} Test & Init Schema
          </Button>
          <Button size="sm" variant="outline" onClick={save} disabled={busy}>Save</Button>
          {status.ok === true && <Badge className="bg-cyber-green/20 text-cyber-green"><CheckCircle2 className="h-3 w-3 mr-1" />Connected</Badge>}
          {status.ok === false && <Badge className="bg-cyber-red/20 text-cyber-red"><XCircle className="h-3 w-3 mr-1" />Failed</Badge>}
        </div>
        {status.err && <p className="text-[10px] font-mono text-cyber-red">{status.err}</p>}
      </CardContent>
    </Card>
  );
}
