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

export interface PredictionStep {
  step: number;
  tactic: string;
  technique: string;
  technique_id: string;
  likelihood: number;
  description: string;
  indicators: string[];
  defense: string;
}

export interface PredictionResult {
  current_stage: string;
  attacker_objective: string;
  predictions: PredictionStep[];
}
