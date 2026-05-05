import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Upload, Package, RefreshCw, FileCode } from "lucide-react";
import { toast } from "sonner";
import { useAuth } from "@/hooks/useAuth";

const TYPE_FROM_NAME = (name: string): string => {
  const ext = name.split(".").pop()?.toLowerCase() || "";
  if (["apk","ipa","exe","zip","jar","aab","dmg","app"].includes(ext)) return ext;
  return "other";
};

const sevColor: Record<string, string> = {
  critical: "bg-cyber-red/20 text-cyber-red border-cyber-red/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-cyber-amber/20 text-cyber-amber border-cyber-amber/30",
  low: "bg-cyber-green/20 text-cyber-green border-cyber-green/30",
};

export default function AppPackages() {
  const qc = useQueryClient();
  const { user } = useAuth();
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [selectedPkg, setSelectedPkg] = useState<string | null>(null);

  const { data: pkgs } = useQuery({
    queryKey: ["app_packages"],
    queryFn: async () => {
      const { data } = await supabase.from("app_packages").select("*").order("created_at", { ascending: false });
      return data || [];
    },
    refetchInterval: 5000,
  });

  const { data: findings } = useQuery({
    queryKey: ["app_package_findings", selectedPkg],
    enabled: !!selectedPkg,
    queryFn: async () => {
      const { data } = await supabase.from("app_package_findings")
        .select("*").eq("package_id", selectedPkg).order("created_at", { ascending: false });
      return data || [];
    },
  });

  const upload = async () => {
    if (!file || !user) return;
    setUploading(true);
    try {
      const path = `${user.id}/${Date.now()}-${file.name}`;
      const { error: upErr } = await supabase.storage.from("app-packages").upload(path, file);
      if (upErr) throw upErr;
      const { data: pkg, error } = await supabase.from("app_packages").insert({
        user_id: user.id, filename: file.name, storage_path: path,
        package_type: TYPE_FROM_NAME(file.name), size_bytes: file.size,
      }).select().single();
      if (error) throw error;
      toast.success("Package uploaded — starting scan");
      supabase.functions.invoke("app-package-scan", { body: { packageId: pkg.id } })
        .then(() => qc.invalidateQueries({ queryKey: ["app_packages"] }));
      setFile(null);
    } catch (e: any) { toast.error(e.message); }
    finally { setUploading(false); }
  };

  const rescan = (id: string) => {
    supabase.functions.invoke("app-package-scan", { body: { packageId: id } });
    toast.message("Re-scanning package...");
  };

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-bold font-mono text-glow-green flex items-center gap-2">
          <Package className="h-5 w-5" /> APPLICATION PACKAGE SCANNER
        </h1>
        <p className="text-xs text-muted-foreground font-mono mt-1">
          Upload .apk / .exe / .ipa / .zip / .jar — AI audits the package contents for vulnerabilities, secrets, and misconfigurations.
        </p>
      </div>

      <Card className="border-primary/30">
        <CardHeader><CardTitle className="font-mono text-sm flex items-center gap-2"><Upload className="h-4 w-4" />Upload Package</CardTitle></CardHeader>
        <CardContent className="flex gap-2">
          <Input type="file" accept=".apk,.exe,.ipa,.zip,.jar,.aab,.dmg,.app"
            onChange={(e) => setFile(e.target.files?.[0] || null)} className="font-mono text-xs" />
          <Button onClick={upload} disabled={!file || uploading} className="font-mono text-xs">
            {uploading ? "Uploading..." : "Upload & Scan"}
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle className="font-mono text-sm">Packages</CardTitle></CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="font-mono text-[10px]">File</TableHead>
                <TableHead className="font-mono text-[10px]">Type</TableHead>
                <TableHead className="font-mono text-[10px]">Status</TableHead>
                <TableHead className="font-mono text-[10px]">Size</TableHead>
                <TableHead className="font-mono text-[10px]">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {pkgs?.map((p: any) => (
                <TableRow key={p.id} className={selectedPkg === p.id ? "bg-primary/10" : ""}>
                  <TableCell className="font-mono text-xs">{p.filename}</TableCell>
                  <TableCell><Badge variant="outline" className="font-mono text-[10px]">{p.package_type}</Badge></TableCell>
                  <TableCell><Badge variant="outline" className="font-mono text-[10px]">{p.status}</Badge></TableCell>
                  <TableCell className="font-mono text-[10px]">{(p.size_bytes / 1024).toFixed(1)} KB</TableCell>
                  <TableCell className="flex gap-1">
                    <Button size="sm" variant="outline" onClick={() => setSelectedPkg(p.id)} className="font-mono text-[10px]">
                      <FileCode className="h-3 w-3 mr-1" />View
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => rescan(p.id)} className="font-mono text-[10px]">
                      <RefreshCw className="h-3 w-3" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
              {!pkgs?.length && (
                <TableRow><TableCell colSpan={5} className="text-center font-mono text-xs text-muted-foreground py-6">No packages uploaded</TableCell></TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {selectedPkg && (
        <Card>
          <CardHeader><CardTitle className="font-mono text-sm">Findings ({findings?.length || 0})</CardTitle></CardHeader>
          <CardContent>
            {findings?.length ? (
              <div className="space-y-2">
                {findings.map((f: any) => (
                  <div key={f.id} className="border border-border rounded p-3">
                    <div className="flex items-center gap-2 mb-1">
                      <Badge variant="outline" className={`font-mono text-[10px] ${sevColor[f.severity] || ""}`}>{f.severity}</Badge>
                      <Badge variant="outline" className="font-mono text-[10px]">{f.vuln_class}</Badge>
                      <span className="font-mono text-xs font-bold">{f.title}</span>
                    </div>
                    {f.file_path && <p className="font-mono text-[10px] text-muted-foreground">📁 {f.file_path}</p>}
                    {f.description && <p className="font-mono text-[11px] mt-1">{f.description}</p>}
                    {f.snippet && <pre className="font-mono text-[10px] bg-muted/30 p-2 rounded mt-1 overflow-auto">{f.snippet}</pre>}
                    {f.remediation && <p className="font-mono text-[11px] text-cyber-green mt-1">✓ {f.remediation}</p>}
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs font-mono text-muted-foreground">No findings yet.</p>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
