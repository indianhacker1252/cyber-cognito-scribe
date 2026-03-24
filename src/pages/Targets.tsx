import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Plus, Crosshair, Trash2 } from "lucide-react";
import { toast } from "sonner";

const statusColors: Record<string, string> = {
  queued: "bg-cyber-amber/20 text-cyber-amber border-cyber-amber/30",
  scanning: "bg-cyber-cyan/20 text-cyber-cyan border-cyber-cyan/30",
  completed: "bg-cyber-green/20 text-cyber-green border-cyber-green/30",
  error: "bg-destructive/20 text-destructive border-destructive/30",
};

export default function Targets() {
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [domain, setDomain] = useState("");
  const [ipRange, setIpRange] = useState("");
  const [apiSchema, setApiSchema] = useState("");

  const { data: targets, isLoading } = useQuery({
    queryKey: ["targets"],
    queryFn: async () => {
      const { data } = await supabase.from("target_workspaces").select("*").order("created_at", { ascending: false });
      return data || [];
    },
  });

  const addTarget = useMutation({
    mutationFn: async () => {
      const { error } = await supabase.from("target_workspaces").insert({
        name,
        domain: domain || null,
        ip_range: ipRange || null,
        api_schema_url: apiSchema || null,
      });
      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["targets"] });
      toast.success("Target added");
      setOpen(false);
      setName("");
      setDomain("");
      setIpRange("");
      setApiSchema("");
    },
    onError: (e) => toast.error(e.message),
  });

  const deleteTarget = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await supabase.from("target_workspaces").delete().eq("id", id);
      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["targets"] });
      toast.success("Target removed");
    },
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold font-mono text-primary text-glow-green">Target Management</h1>
          <p className="text-xs font-mono text-muted-foreground">Configure scanning targets</p>
        </div>
        <Dialog open={open} onOpenChange={setOpen}>
          <DialogTrigger asChild>
            <Button size="sm" className="font-mono text-xs gap-1">
              <Plus className="h-3 w-3" /> Add Target
            </Button>
          </DialogTrigger>
          <DialogContent className="bg-card border-border">
            <DialogHeader>
              <DialogTitle className="font-mono text-primary">New Target</DialogTitle>
            </DialogHeader>
            <div className="space-y-3">
              <Input placeholder="Target name" value={name} onChange={(e) => setName(e.target.value)} className="font-mono text-xs bg-muted border-border" />
              <Input placeholder="Domain (e.g. example.com)" value={domain} onChange={(e) => setDomain(e.target.value)} className="font-mono text-xs bg-muted border-border" />
              <Input placeholder="IP Range (e.g. 192.168.1.0/24)" value={ipRange} onChange={(e) => setIpRange(e.target.value)} className="font-mono text-xs bg-muted border-border" />
              <Input placeholder="API Schema URL" value={apiSchema} onChange={(e) => setApiSchema(e.target.value)} className="font-mono text-xs bg-muted border-border" />
              <Button onClick={() => addTarget.mutate()} disabled={!name || addTarget.isPending} className="w-full font-mono text-xs">
                {addTarget.isPending ? "Adding..." : "Add Target"}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <div className="space-y-2">
        {isLoading ? (
          <p className="text-xs font-mono text-muted-foreground">Loading targets...</p>
        ) : targets && targets.length > 0 ? (
          targets.map((target) => (
            <div key={target.id} className="rounded-lg border border-border bg-card p-4 flex items-center justify-between hover:border-primary/30 transition-colors">
              <div className="flex items-center gap-3">
                <Crosshair className="h-4 w-4 text-primary" />
                <div>
                  <p className="text-sm font-mono font-semibold text-card-foreground">{target.name}</p>
                  <p className="text-[10px] font-mono text-muted-foreground">
                    {target.domain || target.ip_range || target.api_schema_url || "No target specified"}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant="outline" className={`text-[9px] font-mono ${statusColors[target.status]}`}>
                  {target.status}
                </Badge>
                <Button variant="ghost" size="icon" className="h-7 w-7 text-muted-foreground hover:text-destructive" onClick={() => deleteTarget.mutate(target.id)}>
                  <Trash2 className="h-3 w-3" />
                </Button>
              </div>
            </div>
          ))
        ) : (
          <div className="text-center py-12 border border-dashed border-border rounded-lg">
            <Crosshair className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
            <p className="text-xs font-mono text-muted-foreground">No targets configured. Add a target to begin.</p>
          </div>
        )}
      </div>
    </div>
  );
}
