import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ScrollArea } from "@/components/ui/scroll-area";
import { supabase } from "@/integrations/supabase/client";
import { triggerManualSync, getLatestSyncStatus, getSyncHistory, getIntelFeeds } from "@/services/SyncCron";
import { fetchUnreadNotifications, markAllRead } from "@/services/SyncAlert";
import { toast } from "sonner";
import {
  Rss, RefreshCw, Bell, BellOff, ExternalLink, Zap, Clock,
  Shield, AlertTriangle, CheckCircle2, FileCode, Trash2, Download,
  Crosshair, Play,
} from "lucide-react";

export default function IntelFeed() {
  const [feeds, setFeeds] = useState<any[]>([]);
  const [notifications, setNotifications] = useState<any[]>([]);
  const [syncHistory, setSyncHistory] = useState<any[]>([]);
  const [latestSync, setLatestSync] = useState<any>(null);
  const [isSyncing, setIsSyncing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [selectedFeed, setSelectedFeed] = useState<any>(null);
  const [rescanning, setRescanning] = useState<string | null>(null);
  const [targets, setTargets] = useState<any[]>([]);

  useEffect(() => {
    loadAll();
    loadTargets();
    const channel = supabase
      .channel("intel-notifications")
      .on("postgres_changes", { event: "INSERT", schema: "public", table: "intel_notifications" }, (payload) => {
        setNotifications((prev) => [payload.new as any, ...prev]);
        toast.info((payload.new as any).title);
      })
      .subscribe();

    return () => { supabase.removeChannel(channel); };
  }, []);

  async function loadAll() {
    setLoading(true);
    const [feedData, notifData, histData, syncData] = await Promise.all([
      getIntelFeeds({ limit: 200 }),
      fetchUnreadNotifications(50),
      getSyncHistory(20),
      getLatestSyncStatus(),
    ]);
    setFeeds(feedData);
    setNotifications(notifData);
    setSyncHistory(histData);
    setLatestSync(syncData);
    setLoading(false);
  }

  async function loadTargets() {
    const { data } = await supabase.from("target_workspaces").select("id, name, domain, status");
    setTargets(data || []);
  }

  async function handleSync() {
    setIsSyncing(true);
    toast.info("🔄 Intel sync started — fetching global security disclosures...");
    const result = await triggerManualSync();
    if (result.success) {
      toast.success(`✅ Sync complete — ${result.syncRunId ? "check results below" : "done"}`);
      await loadAll();
    } else {
      toast.error(`Sync failed: ${result.error}`);
    }
    setIsSyncing(false);
  }

  async function handleRescan(feedId: string, targetId: string, vulnClass?: string) {
    setRescanning(`${feedId}-${targetId}`);
    try {
      const { data, error } = await supabase.functions.invoke("intel-sync", {
        body: { action: "trigger-rescan", targetId, vulnClass, intelFeedId: feedId },
      });
      if (error) throw error;
      if (data?.triggered) {
        toast.success(`✅ Rescan triggered on target — check Approvals page for results`);
      } else {
        toast.warning(data?.error || data?.message || "Rescan could not be triggered");
      }
    } catch (e: any) {
      toast.error(`Rescan failed: ${e.message}`);
    } finally {
      setRescanning(null);
    }
  }

  async function handleMarkAllRead() {
    await markAllRead();
    setNotifications([]);
    toast.success("All notifications marked as read");
  }

  async function handleDeleteFeed(id: string) {
    await supabase.from("intel_feeds").delete().eq("id", id);
    setFeeds((prev) => prev.filter((f) => f.id !== id));
    toast.success("Feed entry deleted");
  }

  async function handleClearHistory() {
    await supabase.from("intel_sync_runs").delete().neq("id", "00000000-0000-0000-0000-000000000000");
    setSyncHistory([]);
    toast.success("Sync history cleared");
  }

  async function handleClearAllFeeds() {
    await supabase.from("intel_feeds").delete().neq("id", "00000000-0000-0000-0000-000000000000");
    setFeeds([]);
    toast.success("All feeds cleared");
  }

  const signalBadge = (s: string) => {
    if (s === "high") return <Badge className="bg-red-500/20 text-red-400 border-red-500/30">🔴 High Signal</Badge>;
    if (s === "medium") return <Badge className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30">🟡 Medium</Badge>;
    return <Badge className="bg-green-500/20 text-green-400 border-green-500/30">🟢 Low</Badge>;
  };

  const sevBadge = (s: string) => {
    const colors: Record<string, string> = {
      critical: "bg-red-500/20 text-red-400", high: "bg-orange-500/20 text-orange-400",
      medium: "bg-yellow-500/20 text-yellow-400", low: "bg-blue-500/20 text-blue-400",
    };
    return <Badge className={`${colors[s] || colors.medium} border-0`}>{s}</Badge>;
  };

  // Targets available for rescanning
  const completedTargets = targets.filter(t => t.status === "completed");

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground tracking-tight flex items-center gap-2">
            <Rss className="h-6 w-6 text-primary" /> Intel Feed
          </h1>
          <p className="text-muted-foreground text-sm">Phase 10 — Intelligence-Feed Ingestion Engine</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={loadAll} disabled={loading}>
            <RefreshCw className={`h-4 w-4 mr-1 ${loading ? "animate-spin" : ""}`} /> Refresh
          </Button>
          <Button size="sm" onClick={handleSync} disabled={isSyncing} className="bg-primary text-primary-foreground">
            <Zap className={`h-4 w-4 mr-1 ${isSyncing ? "animate-pulse" : ""}`} />
            {isSyncing ? "Syncing..." : "Sync Now"}
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Card className="bg-card border-border">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-foreground">{feeds.length}</p>
            <p className="text-xs text-muted-foreground">Intel Entries</p>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-primary">{feeds.filter((f) => f.signal_strength === "high").length}</p>
            <p className="text-xs text-muted-foreground">High Signal</p>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-foreground">{feeds.filter((f) => f.rescan_triggered).length}</p>
            <p className="text-xs text-muted-foreground">Rescans Triggered</p>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-foreground">{notifications.length}</p>
            <p className="text-xs text-muted-foreground">Unread Alerts</p>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-foreground">{completedTargets.length}</p>
            <p className="text-xs text-muted-foreground">Scannable Targets</p>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="feeds" className="space-y-4">
        <TabsList className="bg-muted">
          <TabsTrigger value="feeds">📡 Feeds ({feeds.length})</TabsTrigger>
          <TabsTrigger value="notifications">🔔 Alerts ({notifications.length})</TabsTrigger>
          <TabsTrigger value="history">📊 Sync History</TabsTrigger>
        </TabsList>

        {/* Feeds Tab */}
        <TabsContent value="feeds">
          <Card className="bg-card border-border">
            <CardHeader className="pb-2 flex flex-row items-center justify-between">
              <CardTitle className="text-sm text-muted-foreground">Ingested Security Disclosures</CardTitle>
              {feeds.length > 0 && (
                <Button variant="outline" size="sm" onClick={handleClearAllFeeds} className="text-destructive border-destructive/30 hover:bg-destructive/10 text-xs">
                  <Trash2 className="h-3 w-3 mr-1" /> Clear All
                </Button>
              )}
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[500px]">
                {feeds.length === 0 ? (
                  <div className="text-center py-12 text-muted-foreground">
                    <Rss className="h-12 w-12 mx-auto mb-4 opacity-30" />
                    <p>No intel feeds yet. Click "Sync Now" to ingest global security disclosures.</p>
                  </div>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow className="border-border">
                        <TableHead>Source</TableHead>
                        <TableHead>Title</TableHead>
                        <TableHead>Vuln Class</TableHead>
                        <TableHead>Signal</TableHead>
                        <TableHead>Severity</TableHead>
                        <TableHead>Matched</TableHead>
                        <TableHead>Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {feeds.map((feed) => (
                        <TableRow key={feed.id} className="border-border cursor-pointer hover:bg-muted/50" onClick={() => setSelectedFeed(feed)}>
                          <TableCell>
                            <Badge variant="outline" className="text-xs">{feed.source}</Badge>
                          </TableCell>
                          <TableCell className="max-w-[250px] truncate text-foreground">{feed.title}</TableCell>
                          <TableCell>
                            <Badge variant="secondary" className="text-xs">{feed.vulnerability_class || "unknown"}</Badge>
                          </TableCell>
                          <TableCell>{signalBadge(feed.signal_strength)}</TableCell>
                          <TableCell>{sevBadge(feed.severity)}</TableCell>
                          <TableCell>
                            {feed.matched_targets?.length > 0 ? (
                              <Badge className="bg-primary/20 text-primary border-primary/30 text-xs">{feed.matched_targets.length} target(s)</Badge>
                            ) : (
                              <span className="text-muted-foreground text-xs">—</span>
                            )}
                          </TableCell>
                          <TableCell>
                            <div className="flex gap-1" onClick={(e) => e.stopPropagation()}>
                              {/* Rescan button for matched targets */}
                              {feed.matched_targets?.length > 0 && feed.matched_targets.map((mt: any) => (
                                <Button
                                  key={mt.id} variant="outline" size="sm"
                                  className="text-primary border-primary/30 hover:bg-primary/10 text-[9px] gap-0.5"
                                  disabled={rescanning === `${feed.id}-${mt.id}`}
                                  onClick={() => handleRescan(feed.id, mt.id, feed.vulnerability_class)}
                                  title={`Rescan ${mt.name}`}
                                >
                                  <Crosshair className="h-3 w-3" />
                                  {rescanning === `${feed.id}-${mt.id}` ? "..." : mt.name?.slice(0, 10)}
                                </Button>
                              ))}
                              {/* Scan any target button */}
                              {completedTargets.length > 0 && !feed.matched_targets?.length && (
                                <Button
                                  variant="outline" size="sm"
                                  className="text-primary border-primary/30 hover:bg-primary/10 text-[9px] gap-0.5"
                                  onClick={() => setSelectedFeed(feed)}
                                  title="Select target to scan"
                                >
                                  <Play className="h-3 w-3" /> Test
                                </Button>
                              )}
                              {feed.source_url && (
                                <Button variant="ghost" size="sm" onClick={() => window.open(feed.source_url, "_blank")}>
                                  <ExternalLink className="h-3 w-3" />
                                </Button>
                              )}
                              <Button variant="ghost" size="sm" onClick={() => handleDeleteFeed(feed.id)}>
                                <Trash2 className="h-3 w-3 text-destructive" />
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </ScrollArea>
            </CardContent>
          </Card>

          {/* Feed Detail Panel */}
          {selectedFeed && (
            <Card className="bg-card border-border mt-4">
              <CardHeader className="pb-2 flex flex-row items-center justify-between">
                <CardTitle className="text-sm">📋 Feed Detail: {selectedFeed.title}</CardTitle>
                <Button variant="ghost" size="sm" onClick={() => setSelectedFeed(null)}>✕</Button>
              </CardHeader>
              <CardContent className="space-y-3 text-sm">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  <div><span className="text-muted-foreground">Source:</span> <span className="text-foreground">{selectedFeed.source}</span></div>
                  <div><span className="text-muted-foreground">Vuln Class:</span> <span className="text-foreground">{selectedFeed.vulnerability_class || "—"}</span></div>
                  <div><span className="text-muted-foreground">Signal:</span> {signalBadge(selectedFeed.signal_strength)}</div>
                  <div><span className="text-muted-foreground">Severity:</span> {sevBadge(selectedFeed.severity)}</div>
                </div>

                {/* Rescan Actions */}
                {completedTargets.length > 0 && (
                  <div className="border border-primary/20 rounded-lg p-3 bg-primary/5">
                    <p className="text-xs text-muted-foreground mb-2 flex items-center gap-1">
                      <Crosshair className="h-3 w-3 text-primary" /> Test this intel against targets:
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {completedTargets.map((t) => (
                        <Button
                          key={t.id} size="sm" variant="outline"
                          className="text-xs gap-1 border-primary/30 text-primary hover:bg-primary/10"
                          disabled={rescanning === `${selectedFeed.id}-${t.id}`}
                          onClick={() => handleRescan(selectedFeed.id, t.id, selectedFeed.vulnerability_class)}
                        >
                          <Crosshair className="h-3 w-3" />
                          {rescanning === `${selectedFeed.id}-${t.id}` ? "Scanning..." : `Scan ${t.name}`}
                        </Button>
                      ))}
                    </div>
                  </div>
                )}

                {selectedFeed.raw_summary && (
                  <div>
                    <p className="text-muted-foreground mb-1">Summary:</p>
                    <p className="text-foreground bg-muted p-3 rounded text-xs">{selectedFeed.raw_summary}</p>
                  </div>
                )}

                {selectedFeed.extracted_payloads?.length > 0 && (
                  <div>
                    <p className="text-muted-foreground mb-1">Extracted Payloads:</p>
                    <div className="space-y-1">
                      {selectedFeed.extracted_payloads.map((p: string, i: number) => (
                        <code key={i} className="block bg-muted text-primary px-2 py-1 rounded text-xs font-mono">{p}</code>
                      ))}
                    </div>
                  </div>
                )}

                {selectedFeed.bypass_techniques?.length > 0 && (
                  <div>
                    <p className="text-muted-foreground mb-1">Bypass Techniques:</p>
                    <div className="flex flex-wrap gap-1">
                      {selectedFeed.bypass_techniques.map((b: string, i: number) => (
                        <Badge key={i} variant="outline" className="text-xs">{b}</Badge>
                      ))}
                    </div>
                  </div>
                )}

                {selectedFeed.template_script && (
                  <div>
                    <p className="text-muted-foreground mb-1 flex items-center gap-1"><FileCode className="h-3 w-3" /> Generated Test Script:</p>
                    <pre className="bg-muted p-3 rounded text-xs overflow-x-auto max-h-[200px] text-foreground font-mono">
                      {selectedFeed.template_script}
                    </pre>
                  </div>
                )}

                {selectedFeed.matched_targets?.length > 0 && (
                  <div>
                    <p className="text-muted-foreground mb-1">Matched Targets:</p>
                    <div className="flex flex-wrap gap-2">
                      {selectedFeed.matched_targets.map((t: any, i: number) => (
                        <div key={i} className="flex items-center gap-1">
                          <Badge className="bg-primary/20 text-primary border-primary/30">{t.name || t.id}</Badge>
                          <Button
                            size="sm" variant="outline"
                            className="text-[9px] gap-0.5 h-6 border-primary/30 text-primary"
                            disabled={rescanning === `${selectedFeed.id}-${t.id}`}
                            onClick={() => handleRescan(selectedFeed.id, t.id, selectedFeed.vulnerability_class)}
                          >
                            <Crosshair className="h-2.5 w-2.5" />
                            {rescanning === `${selectedFeed.id}-${t.id}` ? "..." : "Rescan"}
                          </Button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Notifications Tab */}
        <TabsContent value="notifications">
          <Card className="bg-card border-border">
            <CardHeader className="pb-2 flex flex-row items-center justify-between">
              <CardTitle className="text-sm text-muted-foreground">Intel Notifications</CardTitle>
              {notifications.length > 0 && (
                <Button variant="outline" size="sm" onClick={handleMarkAllRead}>
                  <BellOff className="h-3 w-3 mr-1" /> Mark All Read
                </Button>
              )}
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[400px]">
                {notifications.length === 0 ? (
                  <div className="text-center py-12 text-muted-foreground">
                    <Bell className="h-12 w-12 mx-auto mb-4 opacity-30" />
                    <p>No unread notifications.</p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {notifications.map((n) => (
                      <div key={n.id} className="p-3 border border-border rounded-lg bg-muted/30">
                        <div className="flex items-start justify-between">
                          <div>
                            <p className="text-sm font-medium text-foreground">{n.title}</p>
                            <p className="text-xs text-muted-foreground mt-1">{n.message}</p>
                          </div>
                          <div className="flex gap-1">
                            {n.target_id && (
                              <Button variant="outline" size="sm" className="text-[9px] gap-0.5 text-primary border-primary/30"
                                onClick={() => handleRescan(n.intel_feed_id, n.target_id)}
                                disabled={rescanning === `${n.intel_feed_id}-${n.target_id}`}
                              >
                                <Crosshair className="h-3 w-3" />
                                {rescanning === `${n.intel_feed_id}-${n.target_id}` ? "..." : "Rescan"}
                              </Button>
                            )}
                            {n.action_url && (
                              <Button variant="ghost" size="sm" onClick={() => window.open(n.action_url, "_blank")}>
                                <ExternalLink className="h-3 w-3" />
                              </Button>
                            )}
                          </div>
                        </div>
                        <p className="text-xs text-muted-foreground mt-2">
                          <Clock className="h-3 w-3 inline mr-1" />
                          {new Date(n.created_at).toLocaleString()}
                        </p>
                      </div>
                    ))}
                  </div>
                )}
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Sync History Tab */}
        <TabsContent value="history">
          <Card className="bg-card border-border">
            <CardHeader className="pb-2 flex flex-row items-center justify-between">
              <CardTitle className="text-sm text-muted-foreground">Sync Run History</CardTitle>
              {syncHistory.length > 0 && (
                <Button variant="outline" size="sm" onClick={handleClearHistory}>
                  <Trash2 className="h-3 w-3 mr-1" /> Clear History
                </Button>
              )}
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[400px]">
                {syncHistory.length === 0 ? (
                  <div className="text-center py-12 text-muted-foreground">
                    <Clock className="h-12 w-12 mx-auto mb-4 opacity-30" />
                    <p>No sync runs yet. Click "Sync Now" to start.</p>
                  </div>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow className="border-border">
                        <TableHead>Started</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Fetched</TableHead>
                        <TableHead>Processed</TableHead>
                        <TableHead>Templates</TableHead>
                        <TableHead>Rescans</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {syncHistory.map((run) => (
                        <TableRow key={run.id} className="border-border">
                          <TableCell className="text-xs">{new Date(run.startedAt).toLocaleString()}</TableCell>
                          <TableCell>
                            <Badge className={run.status === "completed" ? "bg-green-500/20 text-green-400" : run.status === "running" ? "bg-blue-500/20 text-blue-400" : "bg-red-500/20 text-red-400"}>
                              {run.status}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-xs">{run.reportsFetched}</TableCell>
                          <TableCell className="text-xs">{run.reportsProcessed}</TableCell>
                          <TableCell className="text-xs">{run.templatesGenerated}</TableCell>
                          <TableCell className="text-xs">{run.rescansTriggered}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
