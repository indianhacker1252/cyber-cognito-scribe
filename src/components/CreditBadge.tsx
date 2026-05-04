import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { useAuth } from "@/hooks/useAuth";
import { Badge } from "@/components/ui/badge";
import { Infinity as InfIcon, Zap } from "lucide-react";

export function CreditBadge() {
  const { user, isAdmin } = useAuth();
  const { data } = useQuery({
    queryKey: ["scan-credits", user?.id],
    enabled: !!user && !isAdmin,
    refetchInterval: 10000,
    queryFn: async () => {
      const { data } = await supabase.from("scan_credits" as any).select("remaining").eq("user_id", user!.id).maybeSingle();
      return data as any;
    },
  });
  if (!user) return null;
  if (isAdmin) return <Badge className="bg-cyber-amber/20 text-cyber-amber border-cyber-amber/40 font-mono"><InfIcon className="h-3 w-3 mr-1" />UNLIMITED</Badge>;
  return <Badge className="bg-primary/20 text-primary border-primary/40 font-mono"><Zap className="h-3 w-3 mr-1" />{data?.remaining ?? 0} SCANS</Badge>;
}
