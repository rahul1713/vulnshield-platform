import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';

export interface ExecutiveFinding {
  title: string;
  severity: string;
  category?: string;
  description?: string;
  remediation?: string;
  recommended_fix?: string;
  owasp_category?: string;
  cwe_id?: string;
  cvss_score?: number;
  file_path?: string;
  line_start?: number;
  line_end?: number;
  location?: string;
  proof?: string;
  root_cause?: string;
}

export interface ExecutiveReportInput {
  reportTitle: string;
  assessmentType: string;
  target: string;
  executiveSummary: string;
  methodology: string;
  findings: ExecutiveFinding[];
  severityCounts?: Record<string, number>;
  metadata?: Record<string, string>;
}

const SEVERITY_COLORS: Record<string, [number, number, number]> = {
  critical: [220, 38, 38],
  high: [234, 88, 12],
  medium: [202, 138, 4],
  low: [37, 99, 235],
  info: [107, 114, 128],
};

export function generateExecutivePdf(input: ExecutiveReportInput): Blob {
  const doc = new jsPDF({ unit: 'pt', format: 'letter' });
  const margin = 48;
  let y = margin;

  doc.setFontSize(10);
  doc.setTextColor(107, 114, 128);
  doc.text('VulnShield — Confidential', margin, y);
  y += 24;

  doc.setFontSize(20);
  doc.setTextColor(14, 116, 144);
  doc.text(input.reportTitle, margin, y);
  y += 22;

  doc.setFontSize(12);
  doc.setTextColor(55, 65, 81);
  doc.text(`${input.assessmentType} — Executive Report`, margin, y);
  y += 18;

  doc.setFontSize(10);
  doc.text(`Target: ${input.target}`, margin, y);
  y += 14;
  doc.text(`Generated: ${new Date().toUTCString()}`, margin, y);
  y += 20;

  doc.setFontSize(13);
  doc.setTextColor(17, 24, 39);
  doc.text('Executive Summary', margin, y);
  y += 14;
  doc.setFontSize(9);
  const summaryLines = doc.splitTextToSize(input.executiveSummary, 520);
  doc.text(summaryLines, margin, y);
  y += summaryLines.length * 12 + 16;

  const counts = input.severityCounts ?? {};
  if (Object.keys(counts).length) {
    doc.setFontSize(13);
    doc.text('Risk Overview', margin, y);
    y += 8;
    autoTable(doc, {
      startY: y,
      head: [['Severity', 'Count']],
      body: Object.entries(counts).map(([k, v]) => [k.toUpperCase(), String(v)]),
      margin: { left: margin },
      styles: { fontSize: 9 },
      headStyles: { fillColor: [14, 116, 144] },
    });
    y = (doc as jsPDF & { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 20;
  }

  doc.setFontSize(13);
  doc.text('Methodology', margin, y);
  y += 14;
  doc.setFontSize(9);
  const methodLines = doc.splitTextToSize(input.methodology, 520);
  doc.text(methodLines, margin, y);
  y += methodLines.length * 12 + 24;

  doc.addPage();
  y = margin;
  doc.setFontSize(13);
  doc.text('Detailed Findings & Remediation', margin, y);
  y += 18;

  input.findings.forEach((f, i) => {
    if (y > 680) {
      doc.addPage();
      y = margin;
    }
    const sev = (f.severity || 'medium').toLowerCase();
    const [r, g, b] = SEVERITY_COLORS[sev] ?? SEVERITY_COLORS.medium;
    doc.setTextColor(r, g, b);
    doc.setFontSize(10);
    doc.text(`${i + 1}. [${sev.toUpperCase()}] ${f.title}`, margin, y);
    y += 14;
    doc.setTextColor(31, 41, 55);
    doc.setFontSize(8);

    const details: string[] = [];
    if (f.category) details.push(`Category: ${f.category}`);
    if (f.owasp_category) details.push(`OWASP: ${f.owasp_category}`);
    if (f.cwe_id) details.push(`CWE: ${f.cwe_id}`);
    if (f.file_path) details.push(`File: ${f.file_path}`);
    if (f.line_start) details.push(`Lines: ${f.line_start}-${f.line_end ?? f.line_start}`);
    if (f.description) details.push(`Description: ${f.description}`);
    if (f.root_cause) details.push(`Root Cause: ${f.root_cause}`);
    if (f.proof) details.push(`Proof: ${f.proof}`);
    const rem = f.remediation || f.recommended_fix;
    if (rem) details.push(`Remediation: ${rem}`);

    details.forEach((line) => {
      const wrapped = doc.splitTextToSize(line, 520);
      if (y + wrapped.length * 10 > 720) {
        doc.addPage();
        y = margin;
      }
      doc.text(wrapped, margin + 8, y);
      y += wrapped.length * 10 + 2;
    });
    y += 8;
  });

  const pages = doc.getNumberOfPages();
  for (let p = 1; p <= pages; p++) {
    doc.setPage(p);
    doc.setFontSize(7);
    doc.setTextColor(156, 163, 175);
    doc.text(
      'CONFIDENTIAL — Authorized distribution only | VulnShield Platform',
      margin,
      760
    );
  }

  return doc.output('blob');
}

export function downloadPdfBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
