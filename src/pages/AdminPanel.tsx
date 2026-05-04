import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { useAuth } from "@/hooks/useAuth";
import { useState } from "react";
import { toast } from "sonner";
import { Navigate } from "react-router-dom";
import { Crown, Plus } from "lucide-react";

export default function AdminPanel() {
  const { isAdmin, loading } = useAuth();
  const qc = useQueryClient();
  const [grantAmount, setGrantAmount] = useState<Record<string, number>>({});

  const { data: users } = useQuery({
    queryKey: ["admin-users"],
    enabled: isAdmin,
    queryFn: async () => {
      const { data: profiles } = await supabase.from("profiles" as any).select("*");
      const { data: credits } = await supabase.from("scan_credits" as any).select("*");
      const { data: roles } = await supabase.from("user_roles" as any).select("*");
      return (profiles as any[] || []).map((p: any) => ({
        ...p,
        credits: (credits as any[] || []).find((c: any) => c.user_id === p.id),
        roles: (roles as any[] || []).filter((r: any) => r.user_id === p.id).map((r: any) => r.role),
      }));
    },
  });

  const grant = useMutation({
    mutationFn: async ({ userId, amount }: { userId: string; amount: number }) => {
      const { data, error } = await supabase.rpc("grant_scan_credits" as any, { _user_id: userId, _amount: amount });
      if (error) throw error;
      return data;
    },
    onSuccess: () => { toast.success("Credits granted"); qc.invalidateQueries({ queryKey: ["admin-users"] }); },
    onError: (e: any) => toast.error(e.message),
  });

  const promote = useMutation({
    mutationFn: async (userId: string) => {
      const { error } = await supabase.from("user_roles" as any).insert({ user_id: userId, role: "admin" });
      if (error) throw error;
    },
    onSuccess: () => { toast.success("Promoted to admin"); qc.invalidateQueries({ queryKey: ["admin-users"] }); },
    onError: (e: any) => toast.error(e.message),
  });

  if (loading) return <div className="p-6 text-muted-foreground">Loading…</div>;
  if (!isAdmin) return <Navigate to="/" replace />;

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Crown className="text-cyber-amber" />
        <h1 className="text-2xl font-mono font-bold text-primary text-glow-green">ADMIN PANEL</h1>
      </div>
      <Card className="border-border bg-card">
        <CardHeader><CardTitle className="font-mono text-sm">Users & Scan Credits</CardTitle></CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Email</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Remaining</TableHead>
                <TableHead>Used</TableHead>
                <TableHead>Grant</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {users?.map((u: any) => (
                <TableRow key={u.id}>
                  <TableCell className="font-mono text-xs">{u.email}</TableCell>
                  <TableCell>
                    {u.roles.includes("admin") ? <Badge className="bg-cyber-amber/20 text-cyber-amber">ADMIN ∞</Badge> : <Badge variant="outline">user</Badge>}
                  </TableCell>
                  <TableCell className="font-mono">{u.credits?.remaining ?? 0}</TableCell>
                  <TableCell className="font-mono text-muted-foreground">{u.credits?.total_used ?? 0}</TableCell>
                  <TableCell>
                    <div className="flex gap-1">
                      <Input type="number" className="w-20 h-8" value={grantAmount[u.id] ?? 5}
                        onChange={(e) => setGrantAmount({ ...grantAmount, [u.id]: parseInt(e.target.value) || 0 })} />
                      <Button size="sm" onClick={() => grant.mutate({ userId: u.id, amount: grantAmount[u.id] ?? 5 })}>
                        <Plus className="h-3 w-3" />
                      </Button>
                    </div>
                  </TableCell>
                  <TableCell>
                    {!u.roles.includes("admin") && (
                      <Button size="sm" variant="outline" onClick={() => promote.mutate(u.id)}>Make Admin</Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
