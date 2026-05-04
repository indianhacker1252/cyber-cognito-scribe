import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";
import { supabase } from "@/integrations/supabase/client";

const sevColors: Record<string, [number, number, number]> = {
  critical: [220, 38, 38],
  high: [234, 88, 12],
  medium: [217, 119, 6],
  low: [22, 163, 74],
  info: [14, 165, 233],
};

interface Finding {
  id: string;
  title: string;
  severity: string;
  description?: string | null;
  payload?: string | null;
  poc?: string | null;
  remediation?: string | null;
  cvss_score?: number | null;
  confidence_score?: number | null;
  validation_status?: string | null;
  triage_reasoning?: string | null;
  endpoint_id?: string | null;
  created_at: string;
  target_workspaces?: { name?: string; domain?: string };
}

async function fetchEndpoint(id?: string | null) {
  if (!id) return null;
  const { data } = await supabase.from("discovered_endpoints").select("url,method").eq("id", id).maybeSingle();
  return data;
}

function addHeader(doc: jsPDF, target: string) {
  doc.setFillColor(10, 12, 16);
  doc.rect(0, 0, doc.internal.pageSize.getWidth(), 22, "F");
  doc.setTextColor(34, 197, 94);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(14);
  doc.text("CYBERSCOPE — VAPT REPORT", 14, 14);
  doc.setTextColor(180, 180, 180);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  doc.text(target, doc.internal.pageSize.getWidth() - 14, 14, { align: "right" });
}

function addFooter(doc: jsPDF) {
  const pages = doc.getNumberOfPages();
  for (let i = 1; i <= pages; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(120, 120, 120);
    doc.text(
      `CyberScope Confidential  •  Page ${i}/${pages}  •  Generated ${new Date().toISOString().slice(0, 10)}`,
      doc.internal.pageSize.getWidth() / 2,
      doc.internal.pageSize.getHeight() - 8,
      { align: "center" }
    );
  }
}

function severityBox(doc: jsPDF, sev: string, x: number, y: number) {
  const c = sevColors[sev] || [100, 100, 100];
  doc.setFillColor(c[0], c[1], c[2]);
  doc.roundedRect(x, y - 5, 22, 6, 1, 1, "F");
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(8);
  doc.setFont("helvetica", "bold");
  doc.text(sev.toUpperCase(), x + 11, y - 1, { align: "center" });
}

export async function generateFindingPdf(f: Finding) {
  const ep = await fetchEndpoint(f.endpoint_id);
  const doc = new jsPDF({ unit: "mm", format: "a4" });
  const target = f.target_workspaces?.name || f.target_workspaces?.domain || "Target";
  addHeader(doc, target);

  let y = 32;
  doc.setTextColor(20, 20, 20);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(16);
  doc.text(f.title, 14, y);
  y += 8;

  severityBox(doc, f.severity || "info", 14, y);
  doc.setTextColor(60, 60, 60);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  doc.text(`CVSS: ${f.cvss_score ?? "—"}`, 40, y - 1);
  doc.text(`Confidence: ${f.confidence_score ?? 0}%`, 70, y - 1);
  doc.text(`Status: ${f.validation_status ?? "unverified"}`, 110, y - 1);
  y += 8;

  autoTable(doc, {
    startY: y,
    theme: "grid",
    headStyles: { fillColor: [22, 22, 26], textColor: [34, 197, 94] },
    styles: { fontSize: 9, cellPadding: 2 },
    body: [
      ["Finding ID", f.id],
      ["Target", target],
      ["Affected Endpoint", ep ? `${ep.method} ${ep.url}` : "—"],
      ["Discovered", new Date(f.created_at).toLocaleString()],
    ],
  });
  y = (doc as any).lastAutoTable.finalY + 6;

  const section = (title: string, body: string) => {
    if (y > 260) { doc.addPage(); addHeader(doc, target); y = 32; }
    doc.setFont("helvetica", "bold");
    doc.setFontSize(11);
    doc.setTextColor(34, 197, 94);
    doc.text(title, 14, y);
    y += 5;
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    doc.setTextColor(40, 40, 40);
    const lines = doc.splitTextToSize(body || "—", 180);
    doc.text(lines, 14, y);
    y += lines.length * 4 + 4;
  };

  section("DESCRIPTION", f.description || "No description provided.");
  section("PROOF OF CONCEPT", f.poc || f.payload || "No PoC recorded.");
  section("AI TRIAGE REASONING", f.triage_reasoning || "—");
  section("REMEDIATION", f.remediation || "Apply input validation, parameterized queries, output encoding, and follow OWASP guidelines for this vulnerability class. Validate the patch with regression tests before deploying to production.");
  section("IMPACT", `A successful exploit of "${f.title}" could lead to data exposure, account takeover, or complete compromise depending on the affected component. Severity has been rated ${f.severity?.toUpperCase()} based on CVSS analysis.`);

  addFooter(doc);
  doc.save(`cyberscope-${f.id.slice(0, 8)}-${(f.title || "finding").replace(/[^a-z0-9]+/gi, "-").slice(0, 40)}.pdf`);
}

export async function generateBulkPdf(findings: Finding[], targetName: string) {
  const doc = new jsPDF({ unit: "mm", format: "a4" });
  addHeader(doc, targetName);
  doc.setTextColor(20, 20, 20);
  doc.setFontSize(20);
  doc.setFont("helvetica", "bold");
  doc.text("VAPT Assessment Report", 14, 40);
  doc.setFontSize(11);
  doc.setFont("helvetica", "normal");
  doc.setTextColor(80, 80, 80);
  doc.text(`Target: ${targetName}`, 14, 50);
  doc.text(`Findings: ${findings.length}`, 14, 56);
  doc.text(`Generated: ${new Date().toLocaleString()}`, 14, 62);

  const counts = findings.reduce<Record<string, number>>((a, f) => { a[f.severity] = (a[f.severity] || 0) + 1; return a; }, {});
  autoTable(doc, {
    startY: 72,
    head: [["Severity", "Count"]],
    body: ["critical", "high", "medium", "low", "info"].map(s => [s.toUpperCase(), counts[s] || 0]),
    headStyles: { fillColor: [22, 22, 26], textColor: [34, 197, 94] },
  });

  for (const f of findings) {
    doc.addPage();
    addHeader(doc, targetName);
    let y = 32;
    doc.setTextColor(20, 20, 20);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(14);
    doc.text(f.title, 14, y);
    y += 7;
    severityBox(doc, f.severity || "info", 14, y);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    doc.setTextColor(60, 60, 60);
    doc.text(`CVSS ${f.cvss_score ?? "—"}  •  Confidence ${f.confidence_score ?? 0}%  •  ${f.validation_status ?? "unverified"}`, 40, y - 1);
    y += 6;

    const ep = await fetchEndpoint(f.endpoint_id);
    const block = (label: string, txt: string) => {
      if (y > 260) { doc.addPage(); addHeader(doc, targetName); y = 32; }
      doc.setFont("helvetica", "bold"); doc.setFontSize(10); doc.setTextColor(34, 197, 94);
      doc.text(label, 14, y); y += 4;
      doc.setFont("helvetica", "normal"); doc.setFontSize(9); doc.setTextColor(40, 40, 40);
      const lines = doc.splitTextToSize(txt || "—", 180);
      doc.text(lines, 14, y); y += lines.length * 4 + 3;
    };
    block("Endpoint", ep ? `${ep.method} ${ep.url}` : "—");
    block("Description", f.description || "—");
    block("Proof of Concept", f.poc || f.payload || "—");
    block("Remediation", f.remediation || "Apply standard OWASP remediation guidance for this vulnerability class.");
  }

  addFooter(doc);
  doc.save(`cyberscope-vapt-${targetName.replace(/[^a-z0-9]+/gi, "-")}-${Date.now()}.pdf`);
}
