import React, { useEffect, useState, useRef, useCallback } from "react";
import { api } from "../services/api";
import type { Scan } from "../services/api";
import { 
  Terminal, ShieldAlert, RefreshCw, ArrowLeft, Download, FileText, Globe, Code,
  CheckCircle2, AlertTriangle, Play, Sparkles, Activity, ShieldCheck
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
    const generatedLogs: string[] = ["[SYSTEM]: Initializing scanner engines..."];
    
    if (progress >= 10) {
      generatedLogs.push("[SYSTEM]: Running repository indexing...");
      generatedLogs.push("[SYSTEM]: Primary programming language detected.");
    }
    if (progress >= 25) {
      generatedLogs.push("[GITLEAKS]: Scanning files for hardcoded secrets, tokens, API keys, and credentials...");
      generatedLogs.push("[GITLEAKS]: Applying AWS/GitHub/Stripe signature patterns...");
    }
    if (progress >= 50) {
      generatedLogs.push("[BANDIT/AST]: Scanning python source structures for SQL concatenations and code injections...");
      generatedLogs.push("[BANDIT/AST]: Walking AST nodes to detect eval/exec and dangerous os subprocesses...");
    }
    if (progress >= 70) {
      generatedLogs.push("[SEMGREP]: Scanning JS/TS, Java, and PHP code against security rule libraries...");
      generatedLogs.push("[SEMGREP]: Checking for unsafe DOM operations (XSS), buffer overflows, and cryptography ciphers...");
    }
    if (progress >= 85) {
      generatedLogs.push("[DEPENDENCY]: Scanning requirements.txt and package.json configuration files...");
      generatedLogs.push("[DEPENDENCY]: Querying offline CVE vulnerability database for vulnerable libraries...");
    }
    if (progress >= 95) {
      generatedLogs.push("[AI ASSISTANT]: Communicating with local Ollama service...");
      generatedLogs.push("[AI ASSISTANT]: Creating defensive code remediation rewrites for critical findings...");
    }
    if (status === "completed") {
      generatedLogs.push("[SYSTEM]: All security analyzers finished.");
      generatedLogs.push("[SYSTEM]: Scan completed! Compiling dashboard findings...");
    } else if (status === "failed") {
      generatedLogs.push("[SYSTEM]: ERROR: Scanner runtime terminated unexpectedly.");
    }

    setLogs(generatedLogs);
  }, []);

  const getStepStatus = (stepProgress: number) => {
    if (!scan) return "pending";
    if (scan.status === "failed") return "failed";
    if (scan.progress >= stepProgress) {
      return scan.progress > stepProgress || scan.status === "completed" ? "completed" : "running";
    }
    return "pending";
  };
  
  // Polling loop
  useEffect(() => {
    const timer: { id: ReturnType<typeof setInterval> | null } = { id: null };
    let consecutiveErrors = 0;

    const checkProgress = async () => {
      try {
        const data = await api.getScan(scanId);
        consecutiveErrors = 0;
        setScan(data);
        
        // Add log messages based on progress
        updateLogs(data.progress, data.status);

        if (data.status === "completed") {
          if (timer.id) clearInterval(timer.id);
          setTimeout(() => {
            onScanComplete(scanId);
          }, 1400);
        } else if (data.status === "failed") {
          if (timer.id) clearInterval(timer.id);
          setError("Scan operation failed. Please check backend logs or try again.");
        }
      } catch (err: unknown) {
        consecutiveErrors++;
        if (consecutiveErrors >= 4) {
          if (timer.id) clearInterval(timer.id);
          const errMsg = err instanceof Error ? err.message : String(err);
          setError("Error tracking progress: " + errMsg);
        }
      }
    };

    // First check immediately
    checkProgress();
    timer.id = setInterval(checkProgress, 1200);

    return () => {
      if (timer.id) clearInterval(timer.id);
    };
  }, [scanId, onScanComplete, updateLogs]);

  // Scroll terminal logs to bottom
  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs]);

  const renderStep = (title: string, triggerProgress: number, engineLabel: string) => {
    const status = getStepStatus(triggerProgress);
    return (
      <div className={`flex items-center justify-between p-3 rounded-xl border transition-all ${
        status === "running"
          ? "bg-amber-500/10 border-amber-500/30 shadow-[0_0_12px_rgba(245,158,11,0.15)]"
          : status === "completed"
          ? "bg-slate-900/60 border-emerald-500/20"
          : "bg-slate-950/40 border-slate-900/80 opacity-60"
      }`}>
        <div className="flex items-center gap-3">
          {status === "completed" && (
            <div className="w-5 h-5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 flex items-center justify-center font-bold text-xs">
              ✓
            </div>
          )}
          {status === "running" && (
            <div className="w-5 h-5 rounded-full border-2 border-amber-400 border-t-transparent animate-spin flex items-center justify-center" />
          )}
          {status === "pending" && (
            <div className="w-5 h-5 rounded-full bg-slate-900 border border-slate-800 flex items-center justify-center text-xs text-slate-600 font-mono">
              •
            </div>
          )}
          {status === "failed" && (
            <div className="w-5 h-5 rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/30 flex items-center justify-center font-bold text-xs">
              !
            </div>
          )}
          <span className={`text-xs font-bold font-mono tracking-wide ${
            status === "running"
              ? "text-amber-300"
              : status === "completed"
              ? "text-slate-200"
              : "text-slate-500"
          }`}>
            {title}
          </span>
        </div>

        <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold ${
          status === "running"
            ? "bg-amber-500/20 text-amber-300 border-amber-500/40 animate-pulse"
            : status === "completed"
            ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
            : "bg-slate-900 text-slate-600 border-slate-800"
        }`}>
          {engineLabel}
        </span>
      </div>
    );
  };

  const currentPercent = scan?.progress || 0;

  return (
    <div className="max-w-3xl mx-auto space-y-6 animate-fade-in pb-12">
      
      {/* Header Banner */}
      <div className="text-center space-y-2 relative">
        <div className="inline-flex items-center gap-2 px-3 py-1 bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 rounded-full text-xs font-mono font-bold mb-2">
          <Activity className="w-3.5 h-3.5 animate-pulse text-cyan-400" />
          RUNNING SAST RUN #{scanId}
        </div>
        <h1 className="text-2xl md:text-3xl font-black text-slate-100 tracking-tight">
          Security Analysis In Progress
        </h1>
        <p className="text-xs text-slate-400 max-w-lg mx-auto font-mono">
          Executing multi-engine static application security testing & deep AI reasoning.
        </p>
      </div>

      {error && (
        <div className="p-4 bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs rounded-2xl flex items-center justify-between gap-3 shadow-lg shadow-rose-500/5">
          <div className="flex items-center gap-2.5">
            <ShieldAlert className="w-5 h-5 shrink-0 text-rose-500" />
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
              className="px-3 py-1.5 bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/40 text-rose-200 rounded-xl font-mono font-bold text-xs cursor-pointer transition-all shrink-0 hover:scale-105 active:scale-95"
            >
              Retry Scan
            </button>
          )}
        </div>
      )}

      {/* Primary Scanning Card */}
      <div className="p-6 md:p-8 glass-panel rounded-2xl border border-slate-800 space-y-6 shadow-2xl relative overflow-hidden bg-slate-950/80">
        
        {/* Ambient background glow */}
        <div className="absolute top-0 right-0 w-64 h-64 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />

        {/* Progress Header & Percentage */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5 text-xs font-bold text-slate-200 font-mono">
            <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
            <span>PIPELINE EXECUTION MONITOR</span>
          </div>
          <div className="flex items-baseline gap-1 font-mono">
            <span className="text-2xl font-black text-cyan-400">{currentPercent}</span>
            <span className="text-xs font-bold text-slate-500">%</span>
          </div>
        </div>
        
        {/* Gradient Progress Bar */}
        <div className="h-3 w-full bg-slate-900 border border-slate-800 rounded-full overflow-hidden p-0.5">
          <div
            className="h-full bg-gradient-to-r from-cyan-500 via-violet-500 to-emerald-400 transition-all duration-500 rounded-full shadow-[0_0_12px_rgba(6,182,212,0.4)]"
            style={{ width: `${Math.max(5, currentPercent)}%` }}
          />
        </div>

        {/* Step-by-Step Checklist */}
        <div className="space-y-2.5 pt-2">
          {renderStep("Project Indexing & Language Detection", 10, "INGEST")}
          {renderStep("Gitleaks Signature Secret Scanning", 25, "GITLEAKS")}
          {renderStep("Python Bandit AST Analysis", 50, "BANDIT")}
          {renderStep("Multi-Language Semgrep Rules", 70, "SEMGREP")}
          {renderStep("Dependency Audit & CVE Database", 85, "DEPENDENCY")}
          {renderStep("Ollama LLM Defensive Remediation", 95, "AI-LLM")}
        </div>

        {/* Export shortcuts if completed */}
        {scan?.status === "completed" && (
          <div className="pt-4 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-3">
            <span className="text-xs font-mono font-bold text-emerald-400 flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4" /> Scan Finished Successfully!
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => window.open(api.getReportDownloadUrl(scanId, "pdf"), "_blank")}
                className="px-3 py-1.5 text-xs font-mono font-bold text-slate-200 bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/30 rounded-xl transition-all flex items-center gap-1.5 hover:scale-105 active:scale-95 cursor-pointer"
              >
                <FileText className="w-3.5 h-3.5 text-rose-400" /> Export PDF
              </button>
              <button
                type="button"
                onClick={() => window.open(api.getReportDownloadUrl(scanId, "html"), "_blank")}
                className="px-3 py-1.5 text-xs font-mono font-bold text-slate-200 bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/30 rounded-xl transition-all flex items-center gap-1.5 hover:scale-105 active:scale-95 cursor-pointer"
              >
                <Globe className="w-3.5 h-3.5 text-cyan-400" /> HTML
              </button>
              <button
                type="button"
                onClick={() => window.open(api.getReportDownloadUrl(scanId, "json"), "_blank")}
                className="px-3 py-1.5 text-xs font-mono font-bold text-slate-200 bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/30 rounded-xl transition-all flex items-center gap-1.5 hover:scale-105 active:scale-95 cursor-pointer"
              >
                <Code className="w-3.5 h-3.5 text-amber-400" /> JSON
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Classic Cyber Terminal Logging Panel */}
      <div className="glass-panel border border-slate-800 rounded-2xl overflow-hidden shadow-2xl bg-slate-950/95">
        <div className="bg-slate-900/90 px-4 py-2.5 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-emerald-400" />
            <span className="text-[11px] font-bold text-slate-300 uppercase tracking-wider font-mono">
              Live Scanner Terminal Output
            </span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-2.5 h-2.5 rounded-full bg-rose-500/60" />
            <div className="w-2.5 h-2.5 rounded-full bg-amber-500/60" />
            <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/60" />
          </div>
        </div>
        <div className="p-4 h-52 overflow-y-auto font-mono text-xs text-emerald-400/90 space-y-1.5 leading-relaxed bg-[#020617]/90 select-text">
          {logs.map((log, i) => (
            <div key={i} className="flex items-start gap-2">
              <span className="text-emerald-600 select-none">&gt;</span>
              <span>{log}</span>
            </div>
          ))}
          <div ref={terminalEndRef} />
        </div>
      </div>

      {/* Actions Footer */}
      <button
        type="button"
        onClick={onCancel}
        className="w-full py-3 px-4 bg-slate-950/80 hover:bg-slate-900 text-slate-300 hover:text-emerald-400 border border-slate-800 hover:border-emerald-500/40 text-xs font-mono font-bold rounded-2xl cursor-pointer transition-all shadow-md flex items-center justify-center gap-2 hover:scale-[1.01]"
      >
        <ArrowLeft className="w-4 h-4" />
        Return to Dashboard
      </button>
    </div>
  );
};
