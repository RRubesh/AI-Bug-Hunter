import React, { useEffect, useState, useRef } from "react";
import { api } from "../services/api";
import type { Scan } from "../services/api";
import { Terminal, ShieldAlert, RefreshCw } from "lucide-react";

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

  const updateLogs = (progress: number, status: string) => {
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
  };

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
    
    const checkProgress = async () => {
      try {
        const data = await api.getScan(scanId);
        setScan(data);
        
        // Add log messages based on progress
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

    // First check immediately
    checkProgress();
    
    timer.id = setInterval(checkProgress, 1200);

    return () => {
      if (timer.id) clearInterval(timer.id);
    };
  }, [scanId, onScanComplete]);

  // Scroll terminal logs to bottom
  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs]);

  const renderStep = (title: string, triggerProgress: number) => {
    const status = getStepStatus(triggerProgress);
    return (
      <div className="flex items-center gap-3.5 text-xs">
        {status === "completed" && (
          <div className="w-4 h-4 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 flex items-center justify-center font-bold">✓</div>
        )}
        {status === "running" && (
          <div className="w-4 h-4 rounded-full border border-t-amber-500 border-slate-700 animate-spin flex items-center justify-center"></div>
        )}
        {status === "pending" && (
          <div className="w-4 h-4 rounded-full bg-slate-900 border border-slate-800 flex items-center justify-center text-[10px] text-slate-600">•</div>
        )}
        {status === "failed" && (
          <div className="w-4 h-4 rounded-full bg-rose-500/20 text-rose-500 border border-rose-500/30 flex items-center justify-center font-bold text-[10px]">!</div>
        )}
        <span className={`font-semibold ${status === "running" ? "text-amber-400" : status === "completed" ? "text-slate-300" : "text-slate-500"}`}>
          {title}
        </span>
      </div>
    );
  };

  return (
    <div className="max-w-2xl mx-auto space-y-8 animate-fade-in">
      <div className="text-center space-y-2">
        <h1 className="text-2xl font-black text-slate-100 tracking-tight">Security Analysis In Progress</h1>
        <p className="text-xs text-slate-400">
          Running static analyzers and secret detectors. Please do not close the browser tab.
        </p>
      </div>

      {error && (
        <div className="p-3 bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs rounded-lg flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Progress Circular/Linear Indicator */}
      <div className="p-6 glass-panel rounded-xl border-slate-800 space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-bold text-slate-300">
            <RefreshCw className="w-3.5 h-3.5 animate-spin" /> Tracking Scan Execution Run
          </div>
          <span className="text-xs font-bold text-slate-400 font-mono">{scan?.progress || 0}%</span>
        </div>
        
        {/* Progress Bar */}
        <div className="h-2 w-full bg-slate-950 border border-slate-900 rounded-full overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-rose-500 via-amber-500 to-emerald-500 transition-all duration-500 rounded-full"
            style={{ width: `${scan?.progress || 0}%` }}
          ></div>
        </div>

        {/* Steps List */}
        <div className="space-y-3 pt-4 border-t border-slate-900">
          {renderStep("Project Indexing & Language Detection", 10)}
          {renderStep("Gitleaks Signature Secret Scanning", 25)}
          {renderStep("Python Bandit Abstract Syntax Tree Analysis", 50)}
          {renderStep("Multi-language Semgrep Rule Scanning", 70)}
          {renderStep("Outdated & Vulnerable Dependencies Audit", 85)}
          {renderStep("Ollama LLM secure remediation generation", 95)}
        </div>
      </div>

      {/* Terminal Logging Panel */}
      <div className="glass-panel border-slate-800 rounded-xl overflow-hidden shadow-2xl">
        <div className="bg-slate-950 px-4 py-2 border-b border-slate-850 flex items-center gap-2">
          <Terminal className="w-4 h-4 text-emerald-400" />
          <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider font-mono">Terminal Output Logs</span>
        </div>
        <div className="bg-slate-950 p-4 h-48 overflow-y-auto font-mono text-[10px] text-emerald-500/90 space-y-1.5 leading-relaxed">
          {logs.map((log, i) => (
            <div key={i}>{log}</div>
          ))}
          <div ref={terminalEndRef} />
        </div>
      </div>
 
      {/* Actions */}
      <button
        onClick={onCancel}
        className="w-full py-2.5 px-4 bg-slate-950 border border-slate-900 hover:bg-slate-900 text-emerald-400 border border-emerald-500/30 text-xs font-bold rounded cursor-pointer transition-colors shadow-[0_0_8px_rgba(0,255,102,0.05)] hover:border-emerald-500/65"
      >
        Return to Dashboard
      </button>
    </div>
  );
};
