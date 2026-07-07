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
