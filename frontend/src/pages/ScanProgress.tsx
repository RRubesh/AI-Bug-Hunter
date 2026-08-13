import React, { useEffect, useState, useRef, useCallback } from "react";
import { api } from "../services/api";
import type { Scan } from "../services/api";
import { PageHeader } from "../components/ui/PageHeader";
import { GlassCard } from "../components/ui/GlassCard";
import { StatusBadge } from "../components/ui/StatusBadge";
import { Button } from "../components/ui/Button";
import { CyberRadarLoader } from "../components/CyberRadarLoader";
import { 
  Terminal, AlertTriangle, Activity, ArrowLeft, Download, FileText, Globe, Code
} from "lucide-react";


interface ScanProgressProps {
  scanId: number;
  onScanComplete: (scanId: number) => void;
  onCancel: () => void;
}

export const ScanProgress: React.FC<ScanProgressProps> = ({ scanId, onScanComplete, onCancel }) => {
  const [scan, setScan] = useState<Scan | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [error, setError] = useState("");
  const terminalEndRef = useRef<HTMLDivElement>(null);

  const updateLogs = useCallback((progress: number, status: string) => {
    const generatedLogs: string[] = ["[SYSTEM]: Initializing security scanner engine pipeline..."];
    
    if (progress >= 10) {
      generatedLogs.push("[INGESTION]: Repository file indexing and primary language detection complete.");
    }
    if (progress >= 25) {
      generatedLogs.push("[GITLEAKS]: Scanning files for hardcoded secrets, tokens, API keys, and credentials...");
      generatedLogs.push("[GITLEAKS]: Applied AWS, GitHub, Stripe, and JWT key signature patterns.");
    }
    if (progress >= 50) {
      generatedLogs.push("[BANDIT/AST]: Walking AST nodes for SQL concatenations and raw eval/exec statements...");
      generatedLogs.push("[BANDIT/AST]: Checked Python subprocess invocations and command injections.");
    }
    if (progress >= 70) {
      generatedLogs.push("[SEMGREP]: Scanning JS/TS, Java, and PHP code against OWASP Top 10 security rules...");
      generatedLogs.push("[SEMGREP]: Checking for unsafe DOM operations (XSS) and broken access control ciphers.");
    }
    if (progress >= 85) {
      generatedLogs.push("[DEPENDENCY]: Scanning requirements.txt and package.json configuration files...");
      generatedLogs.push("[DEPENDENCY]: Queried offline CVE vulnerability database for vulnerable libraries.");
    }
    if (progress >= 95) {
      generatedLogs.push("[AI ASSISTANT]: Communicating with Ollama service for defensive remediation rewrites...");
      generatedLogs.push("[AI ASSISTANT]: Synthesizing fix recommendations for critical findings.");
    }
    if (status === "completed") {
      generatedLogs.push("[SYSTEM]: All security analyzers finished cleanly.");
      generatedLogs.push("[SYSTEM]: Scan completed! Compiling dashboard findings...");
    } else if (status === "failed") {
      generatedLogs.push("[SYSTEM]: ERROR: Scanner runtime terminated unexpectedly.");
    }

    setLogs(generatedLogs);
  }, []);

  const getStageStatus = (triggerProgress: number) => {
    if (!scan) return "pending";
    if (scan.status === "failed") return "failed";
    if (scan.progress >= triggerProgress) {
      return scan.progress > triggerProgress || scan.status === "completed" ? "completed" : "running";
    }
    return "pending";
  };

  useEffect(() => {
    const timer: { id: ReturnType<typeof setInterval> | null } = { id: null };
    
    const checkProgress = async () => {
      try {
        const data = await api.getScan(scanId);
        setScan(data);
        updateLogs(data.progress, data.status);

        if (data.status === "completed") {
          if (timer.id) clearInterval(timer.id);
          setTimeout(() => {
            onScanComplete(scanId);
          }, 1500);
        } else if (data.status === "failed") {
          if (timer.id) clearInterval(timer.id);
          setError("Scan operation failed. Please check backend logs or try again.");
        }
      } catch (err: unknown) {
        if (timer.id) clearInterval(timer.id);
        const errMsg = err instanceof Error ? err.message : String(err);
        setError("Error tracking progress: " + errMsg);
      }
    };

    checkProgress();
    timer.id = setInterval(checkProgress, 1200);

    return () => {
      if (timer.id) clearInterval(timer.id);
    };
  }, [scanId, onScanComplete, updateLogs]);

  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs]);

  const pipelineStages = [
    { label: "Code Ingestion & Indexing", threshold: 10, engine: "SYSTEM" },
    { label: "Secret Detection & API Keys", threshold: 25, engine: "GITLEAKS" },
    { label: "Python Security AST Analysis", threshold: 50, engine: "BANDIT" },
    { label: "Multi-Language SAST Rules", threshold: 70, engine: "SEMGREP" },
    { label: "Dependency Audit & CVEs", threshold: 85, engine: "OWASP" },
    { label: "AI Reasoning & Remediation", threshold: 95, engine: "OLLAMA" },
    { label: "Security Report Generation", threshold: 100, engine: "REPORT" },
  ];

  return (
    <div className="max-w-5xl mx-auto space-y-8 animate-fade-in">
      
      {/* Header */}
      <PageHeader
        title={`Scanning Pipeline Run #${scanId}`}
        subtitle="Real-time multi-engine SAST static analysis execution"
        badge={
          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge status={scan?.status || "scanning"} pulse={scan?.status !== "completed"} />
            {scan?.status === "completed" && (
              <div className="flex items-center gap-1 bg-slate-900/90 p-1 border border-slate-800 rounded-xl shadow-inner">
                <span className="text-[10px] uppercase font-mono font-bold text-slate-400 px-2 flex items-center gap-1">
                  <Download className="w-3 h-3 text-cyan-400" /> Export:
                </span>
                <button
                  type="button"
                  onClick={() => window.open(api.getReportDownloadUrl(scanId, "pdf"), "_blank")}
                  className="px-2.5 py-1 text-xs font-mono font-bold text-slate-200 bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/30 rounded-lg transition-all flex items-center gap-1.5 hover:scale-105 active:scale-95 cursor-pointer"
                  title="Download Executive PDF Document"
                >
                  <FileText className="w-3.5 h-3.5 text-rose-400" /> PDF
                </button>
                <button
                  type="button"
                  onClick={() => window.open(api.getReportDownloadUrl(scanId, "html"), "_blank")}
                  className="px-2.5 py-1 text-xs font-mono font-bold text-slate-200 bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/30 rounded-lg transition-all flex items-center gap-1.5 hover:scale-105 active:scale-95 cursor-pointer"
                  title="Download Interactive HTML Web Report"
                >
                  <Globe className="w-3.5 h-3.5 text-cyan-400" /> HTML
                </button>
                <button
                  type="button"
                  onClick={() => window.open(api.getReportDownloadUrl(scanId, "json"), "_blank")}
                  className="px-2.5 py-1 text-xs font-mono font-bold text-slate-200 bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/30 rounded-lg transition-all flex items-center gap-1.5 hover:scale-105 active:scale-95 cursor-pointer"
                  title="Download Machine-Readable JSON SAST Data"
                >
                  <Code className="w-3.5 h-3.5 text-amber-400" /> JSON
                </button>
              </div>
            )}
          </div>
        }
        action={
          <Button variant="secondary" size="sm" icon={ArrowLeft} onClick={onCancel}>
            Return to Dashboard
          </Button>
        }
      />

      {error && (
        <div className="p-4 bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs rounded-2xl flex items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 shrink-0 text-rose-500" />
            <span>{error}</span>
          </div>
          {scan?.project_id && (
            <button
              type="button"
              onClick={async () => {
                setError("");
                try {
                  const newScan = await api.triggerScan(scan.project_id);
                  setScan(newScan);
                } catch (e: unknown) {
                  const errMsg = e instanceof Error ? e.message : String(e);
                  setError("Retry failed: " + errMsg);
                }
              }}
              className="px-3 py-1.5 bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/40 text-rose-200 rounded-lg font-mono font-bold text-xs cursor-pointer transition-all shrink-0 hover:scale-105 active:scale-95"
            >
              Retry Scan Run
            </button>
          )}
        </div>
      )}


      {/* Progress Bar & Stage Status */}

      <GlassCard className="p-6 space-y-6" topBarGradient={true}>
        <div className="flex flex-col md:flex-row items-center justify-between gap-6">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 flex items-center justify-center">
              <Activity className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400">
                Pipeline Execution Status
              </span>
              <h3 className="text-lg font-bold text-slate-100">
                {scan?.status === "completed" ? "Analysis Finished Cleanly" : "Executing Scanner Rules"}
              </h3>
            </div>
          </div>

          {/* Minimal Cyber Radar Animation */}
          {scan?.status !== "completed" && (
            <CyberRadarLoader size="sm" text="SCANNING CODE" className="p-0" />
          )}

          <span className="text-3xl font-black font-mono text-cyan-400">
            {scan?.progress || 0}%
          </span>
        </div>


        {/* Animated Progress Bar */}
        <div className="h-3 w-full bg-slate-950 border border-slate-800 rounded-full overflow-hidden p-0.5">
          <div
            className="h-full bg-gradient-to-r from-cyan-500 via-blue-500 to-violet-500 rounded-full transition-all duration-500 shadow-[0_0_15px_rgba(6,182,212,0.5)]"
            style={{ width: `${scan?.progress || 0}%` }}
          />
        </div>

        {/* Pipeline Stage Steps Grid */}
        <div className="grid grid-cols-1 md:grid-cols-7 gap-2 pt-4 border-t border-slate-800">
          {pipelineStages.map((st, i) => {
            const stStatus = getStageStatus(st.threshold);
            const isDone = stStatus.includes("completed");
            const isRunning = stStatus === "running";

            return (
              <div
                key={i}
                className={`p-3 rounded-xl border text-center transition-all ${
                  isDone
                    ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
                    : isRunning
                    ? "bg-cyan-500/15 border-cyan-400 text-cyan-300 shadow-[0_0_10px_rgba(6,182,212,0.2)] animate-pulse"
                    : "bg-slate-900/40 border-slate-800 text-slate-500 opacity-60"
                }`}
              >
                <div className="text-[9px] font-mono font-bold uppercase mb-1">{st.engine}</div>
                <div className="text-[11px] font-bold truncate">{st.label}</div>
                <div className="mt-2 text-[10px] font-mono">
                  {isDone ? "DONE" : isRunning ? "RUNNING" : "PENDING"}
                </div>
              </div>
            );
          })}
        </div>
      </GlassCard>

      {/* Terminal Logging Output Console */}
      <GlassCard className="p-0 overflow-hidden" glowColor="cyan">
        <div className="bg-slate-950 px-6 py-3 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-emerald-400" />
            <span className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
              Live Terminal Scanner Logs
            </span>
          </div>
          <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
            STREAM ACTIVE
          </span>
        </div>

        <div className="bg-slate-950 p-6 h-64 overflow-y-auto font-mono text-xs text-emerald-400/90 space-y-2 leading-relaxed">
          {logs.map((log, index) => (
            <div key={index} className="flex items-start gap-2">
              <span className="text-slate-600 shrink-0">{`>`}</span>
              <span>{log}</span>
            </div>
          ))}
          <div ref={terminalEndRef} />
        </div>
      </GlassCard>

    </div>
  );
};

export default ScanProgress;
