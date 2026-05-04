import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { supabase } from "@/integrations/supabase/client";
import { lovable } from "@/integrations/lovable";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import { Crosshair, Loader2 } from "lucide-react";
import { useAuth } from "@/hooks/useAuth";

export default function AuthPage() {
  const nav = useNavigate();
  const { session } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => { if (session) nav("/", { replace: true }); }, [session, nav]);

  const signIn = async () => {
    setBusy(true);
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    setBusy(false);
    if (error) return toast.error(error.message);
    toast.success("Signed in");
    nav("/", { replace: true });
  };

  const signUp = async () => {
    setBusy(true);
    const { error } = await supabase.auth.signUp({
      email, password,
      options: { emailRedirectTo: `${window.location.origin}/` },
    });
    setBusy(false);
    if (error) return toast.error(error.message);
    toast.success("Account created — you have 3 free scans");
  };

  const google = async () => {
    setBusy(true);
    const r = await lovable.auth.signInWithOAuth("google", { redirect_uri: window.location.origin });
    if (r.error) { setBusy(false); toast.error(r.error.message); }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <Card className="w-full max-w-md border-primary/30 bg-card glow-green">
        <CardHeader className="text-center">
          <div className="mx-auto h-12 w-12 rounded-md bg-primary/20 border border-primary/40 flex items-center justify-center glow-green mb-2">
            <Crosshair className="h-6 w-6 text-primary" />
          </div>
          <CardTitle className="font-mono text-primary text-glow-green">CYBERSCOPE ACCESS</CardTitle>
          <p className="text-xs text-muted-foreground font-mono">Authenticate to begin operations</p>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="signin">
            <TabsList className="w-full">
              <TabsTrigger value="signin" className="flex-1">Sign In</TabsTrigger>
              <TabsTrigger value="signup" className="flex-1">Sign Up</TabsTrigger>
            </TabsList>
            <TabsContent value="signin" className="space-y-3 pt-4">
              <Input placeholder="Email" type="email" value={email} onChange={e => setEmail(e.target.value)} />
              <Input placeholder="Password" type="password" value={password} onChange={e => setPassword(e.target.value)} />
              <Button onClick={signIn} disabled={busy} className="w-full">
                {busy && <Loader2 className="h-4 w-4 animate-spin" />} Sign In
              </Button>
            </TabsContent>
            <TabsContent value="signup" className="space-y-3 pt-4">
              <Input placeholder="Email" type="email" value={email} onChange={e => setEmail(e.target.value)} />
              <Input placeholder="Password (min 6)" type="password" value={password} onChange={e => setPassword(e.target.value)} />
              <Button onClick={signUp} disabled={busy} className="w-full">
                {busy && <Loader2 className="h-4 w-4 animate-spin" />} Create Account
              </Button>
              <p className="text-[10px] text-muted-foreground font-mono">3 free target scans included</p>
            </TabsContent>
          </Tabs>
          <div className="my-4 flex items-center gap-2">
            <div className="h-px flex-1 bg-border" />
            <span className="text-[10px] font-mono text-muted-foreground">OR</span>
            <div className="h-px flex-1 bg-border" />
          </div>
          <Button variant="outline" onClick={google} disabled={busy} className="w-full">
            Continue with Google
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
