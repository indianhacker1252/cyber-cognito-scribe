import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ChartContainer, ChartTooltip, ChartTooltipContent } from "@/components/ui/chart";
import { BarChart, Bar, XAxis, YAxis, PieChart, Pie, Cell, ResponsiveContainer, CartesianGrid } from "recharts";
import { ShieldOff, Trash2, TrendingDown, Brain, Target, Activity } from "lucide-react";
import { toast } from "sonner";
import { format } from "date-fns";

const COLORS = ["hsl(160,100%,45%)", "hsl(200,100%,50%)", "hsl(280,80%,60%)", "hsl(0,85%,55%)", "hsl(45,100%,50%)"];

export default function FalsePositives() {
  const queryClient = useQueryClient();

  const { data: suppressionVectors = [] } = useQuery({
    queryKey: ["suppression-vectors"],
    queryFn: async () => {
      const { data } = await supabase.from("suppression_vectors").select("*").order("created_at", { ascending: false });
      return data || [];
    },
  });

  const { data: approvals = [] } = useQuery({
    queryKey: ["all-approvals-fp"],
    queryFn: async () => {
      const { data } = await supabase.from("pending_approvals").select("finding_type, severity, confidence_score, status, ai_verified");
      return data || [];
    },
  });

  const { data: findings = [] } = useQuery({
    queryKey: ["all-findings-fp"],
    queryFn: async () => {
      const { data } = await supabase.from("vulnerability_findings").select("title, severity, confidence_score, validation_status, ai_verified");
      return data || [];
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await supabase.from("suppression_vectors").delete().eq("id", id);
      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["suppression-vectors"] });
      toast.success("Suppression vector removed");
    },
  });

  // FP rate by vuln class
  const vulnClassStats = (() => {
    const map: Record<string, { total: number; suppressed: number }> = {};
    approvals.forEach((a: any) => {
      const cls = a.finding_type || "unknown";
      if (!map[cls]) map[cls] = { total: 0, suppressed: 0 };
      map[cls].total++;
      if (a.status === "rejected") map[cls].suppressed++;
    });
    suppressionVectors.forEach((v: any) => {
      const cls = v.vuln_class || v.finding_type || "unknown";
      if (!map[cls]) map[cls] = { total: 0, suppressed: 0 };
      map[cls].suppressed++;
    });
    return Object.entries(map)
      .map(([name, v]) => ({ name: name.slice(0, 20), total: v.total, suppressed: v.suppressed, fpRate: v.total > 0 ? Math.round((v.suppressed / v.total) * 100) : 0 }))
      .sort((a, b) => b.fpRate - a.fpRate)
      .slice(0, 10);
  })();

  // Confidence distribution
  const confidenceDist = (() => {
    const buckets = [
      { range: "0-20", count: 0 },
      { range: "21-40", count: 0 },
      { range: "41-60", count: 0 },
      { range: "61-80", count: 0 },
      { range: "81-100", count: 0 },
    ];
    [...approvals, ...findings].forEach((item: any) => {
      const score = item.confidence_score || 0;
      if (score <= 20) buckets[0].count++;
      else if (score <= 40) buckets[1].count++;
      else if (score <= 60) buckets[2].count++;
      else if (score <= 80) buckets[3].count++;
      else buckets[4].count++;
    });
    return buckets;
  })();

  // Severity breakdown for pie chart
  const severityBreakdown = (() => {
    const map: Record<string, number> = {};
    suppressionVectors.forEach((v: any) => {
      const s = v.vuln_class || "unknown";
      map[s] = (map[s] || 0) + 1;
    });
    return Object.entries(map).map(([name, value]) => ({ name: name.slice(0, 18), value }));
  })();

  const totalApprovals = approvals.length;
  const rejectedCount = approvals.filter((a: any) => a.status === "rejected").length;
  const overallFpRate = totalApprovals > 0 ? Math.round((rejectedCount / totalApprovals) * 100) : 0;
  const avgConfidence = approvals.length > 0 ? Math.round(approvals.reduce((s: number, a: any) => s + (a.confidence_score || 0), 0) / approvals.length) : 0;
  const aiVerifiedCount = [...approvals, ...findings].filter((a: any) => a.ai_verified).length;

  const fpChartConfig = {
    total: { label: "Total", color: "hsl(200,100%,50%)" },
    suppressed: { label: "Suppressed", color: "hsl(0,85%,55%)" },
    fpRate: { label: "FP Rate %", color: "hsl(280,80%,60%)" },
  };

  const confChartConfig = {
    count: { label: "Findings", color: "hsl(160,100%,45%)" },
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <ShieldOff className="h-6 w-6 text-destructive" />
        <div>
          <h1 className="text-xl font-bold font-mono text-foreground">False Positive Analytics</h1>
          <p className="text-xs text-muted-foreground font-mono">Suppression vectors, FP rates, and confidence distributions</p>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          { label: "Suppression Vectors", value: suppressionVectors.length, icon: ShieldOff, color: "text-destructive" },
          { label: "Overall FP Rate", value: `${overallFpRate}%`, icon: TrendingDown, color: "text-accent" },
          { label: "Avg Confidence", value: avgConfidence, icon: Target, color: "text-primary" },
          { label: "AI Verified", value: aiVerifiedCount, icon: Brain, color: "text-secondary" },
          { label: "Total Assessed", value: totalApprovals + findings.length, icon: Activity, color: "text-muted-foreground" },
        ].map((stat) => (
          <Card key={stat.label} className="border-border/50">
            <CardContent className="p-4">
              <div className="flex items-center gap-2 mb-1">
                <stat.icon className={`h-4 w-4 ${stat.color}`} />
                <span className="text-[10px] font-mono text-muted-foreground uppercase">{stat.label}</span>
              </div>
              <p className="text-2xl font-bold font-mono text-foreground">{stat.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <Tabs defaultValue="rates" className="space-y-4">
        <TabsList className="bg-muted/50 border border-border/50">
          <TabsTrigger value="rates" className="font-mono text-xs">FP Rates by Class</TabsTrigger>
          <TabsTrigger value="confidence" className="font-mono text-xs">Confidence Distribution</TabsTrigger>
          <TabsTrigger value="vectors" className="font-mono text-xs">Suppression Vectors</TabsTrigger>
        </TabsList>

        <TabsContent value="rates">
          <Card className="border-border/50">
            <CardHeader>
              <CardTitle className="text-sm font-mono">False Positive Rate by Vulnerability Class</CardTitle>
              <CardDescription className="text-xs font-mono">Higher FP rate = more suppressed/rejected findings</CardDescription>
            </CardHeader>
            <CardContent>
              {vulnClassStats.length > 0 ? (
                <ChartContainer config={fpChartConfig} className="h-[300px] w-full">
                  <BarChart data={vulnClassStats}>
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(220,15%,15%)" />
                    <XAxis dataKey="name" tick={{ fontSize: 10, fill: "hsl(220,10%,50%)" }} />
                    <YAxis tick={{ fontSize: 10, fill: "hsl(220,10%,50%)" }} />
                    <ChartTooltip content={<ChartTooltipContent />} />
                    <Bar dataKey="total" fill="hsl(200,100%,50%)" radius={[4, 4, 0, 0]} />
                    <Bar dataKey="suppressed" fill="hsl(0,85%,55%)" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ChartContainer>
              ) : (
                <p className="text-sm text-muted-foreground font-mono text-center py-8">No data yet — run scans to populate</p>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="confidence">
          <div className="grid md:grid-cols-2 gap-4">
            <Card className="border-border/50">
              <CardHeader>
                <CardTitle className="text-sm font-mono">Confidence Score Distribution</CardTitle>
                <CardDescription className="text-xs font-mono">How confident are findings across all scans</CardDescription>
              </CardHeader>
              <CardContent>
                <ChartContainer config={confChartConfig} className="h-[250px] w-full">
                  <BarChart data={confidenceDist}>
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(220,15%,15%)" />
                    <XAxis dataKey="range" tick={{ fontSize: 10, fill: "hsl(220,10%,50%)" }} />
                    <YAxis tick={{ fontSize: 10, fill: "hsl(220,10%,50%)" }} />
                    <ChartTooltip content={<ChartTooltipContent />} />
                    <Bar dataKey="count" fill="hsl(160,100%,45%)" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ChartContainer>
              </CardContent>
            </Card>

            <Card className="border-border/50">
              <CardHeader>
                <CardTitle className="text-sm font-mono">Suppression by Vuln Class</CardTitle>
              </CardHeader>
              <CardContent>
                {severityBreakdown.length > 0 ? (
                  <ChartContainer config={confChartConfig} className="h-[250px] w-full">
                    <PieChart>
                      <Pie data={severityBreakdown} cx="50%" cy="50%" outerRadius={80} dataKey="value" label={({ name, value }) => `${name}: ${value}`}>
                        {severityBreakdown.map((_, i) => (
                          <Cell key={i} fill={COLORS[i % COLORS.length]} />
                        ))}
                      </Pie>
                      <ChartTooltip content={<ChartTooltipContent />} />
                    </PieChart>
                  </ChartContainer>
                ) : (
                  <p className="text-sm text-muted-foreground font-mono text-center py-8">No suppression vectors yet</p>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="vectors">
          <Card className="border-border/50">
            <CardHeader>
              <CardTitle className="text-sm font-mono">Active Suppression Vectors</CardTitle>
              <CardDescription className="text-xs font-mono">Patterns that auto-suppress future false positives</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow className="border-border/30">
                    <TableHead className="font-mono text-[10px]">Finding Type</TableHead>
                    <TableHead className="font-mono text-[10px]">Vuln Class</TableHead>
                    <TableHead className="font-mono text-[10px]">Reason</TableHead>
                    <TableHead className="font-mono text-[10px]">Created</TableHead>
                    <TableHead className="font-mono text-[10px]">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {suppressionVectors.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center text-muted-foreground font-mono text-xs py-8">
                        No suppression vectors — mark findings as false positives to populate
                      </TableCell>
                    </TableRow>
                  ) : (
                    suppressionVectors.map((v: any) => (
                      <TableRow key={v.id} className="border-border/20">
                        <TableCell className="font-mono text-xs">{(v.finding_type || "").slice(0, 30)}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className="text-[10px] font-mono">{v.vuln_class || "—"}</Badge>
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground max-w-[200px] truncate">{v.suppression_reason || "—"}</TableCell>
                        <TableCell className="text-xs text-muted-foreground font-mono">{format(new Date(v.created_at), "MMM dd HH:mm")}</TableCell>
                        <TableCell>
                          <Button variant="ghost" size="sm" onClick={() => deleteMutation.mutate(v.id)}>
                            <Trash2 className="h-3 w-3 text-destructive" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
