export type Severity = "critical" | "high" | "medium" | "low";

export interface Anomaly {
  title: string;
  severity: Severity;
  tactic: string;
  description: string;
  source_ip: string | null;
  affected_user: string | null;
  time_window: string | null;
  evidence: string[];
}

export interface AnalysisResult {
  summary: string;
  risk_score: number;
  anomalies: Anomaly[];
}
