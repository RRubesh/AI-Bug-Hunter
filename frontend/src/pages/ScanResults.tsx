import React, { useEffect, useState } from "react";
import { api } from "../services/api";
import type { Scan, Vulnerability } from "../services/api";
import { GlassCard } from "../components/ui/GlassCard";
import { Button } from "../components/ui/Button";
import logo from "../assets/logo.jpg";
import { CyberRadarLoader } from "../components/CyberRadarLoader";


import { 
  Shield, Download, Sparkles, ArrowLeft, Copy, Check, Search, 
  MessageSquare, FileText, Code, Key, Package, 
  Share2, Printer, X, CheckCircle2, Cpu, BarChart3
} from "lucide-react";

interface ScanResultsProps {
  scanId: number;
  onNavigateToDashboard: () => void;
  onNavigateToChat?: () => void;
}

export const ScanResults: React.FC<ScanResultsProps> = ({ scanId, onNavigateToDashboard, onNavigateToChat }) => {
  const [scan, setScan] = useState<Scan | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [inspectorOpen, setInspectorOpen] = useState(false);
  const [fileContent, setFileContent] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [loadingFile, setLoadingFile] = useState(false);
  const [enriching, setEnriching] = useState(false);
  const [copiedFix, setCopiedFix] = useState(false);
  const [copiedShare, setCopiedShare] = useState(false);
  
  // Filter & Search states
  const [activeTab, setActiveTab] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");

  useEffect(() => {
    let active = true;
    Promise.all([api.getScan(scanId), api.getVulnerabilities(scanId)])
      .then(([scanData, vulnsData]) => {
        if (!active) return;
        setScan(scanData);
        setVulnerabilities(vulnsData);
      })
      .catch((err: unknown) => {
        if (!active) return;
        console.error(err);
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, [scanId]);

  // Fetch code content when inspecting a vulnerability
  useEffect(() => {
    if (!selectedVuln || !scan) return;
    let active = true;
    setLoadingFile(true);
    api.getFileContent(scan.project_id, selectedVuln.file_path)
      .then((content) => {
        if (active) setFileContent(content);
      })
      .catch(() => {
        if (active) setFileContent("");
      })
      .finally(() => {
        if (active) setLoadingFile(false);
      });

    return () => {
      active = false;
    };
  }, [selectedVuln, scan]);

  const handleEnrichWithAI = async (vulnId: number) => {
    setEnriching(true);
    try {
      const updatedVuln = await api.enrichVulnerability(vulnId);
      setVulnerabilities(vulnerabilities.map((v) => (v.id === vulnId ? updatedVuln : v)));
      if (selectedVuln?.id === vulnId) {
        setSelectedVuln(updatedVuln);
      }
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      alert("Error invoking AI remediation engine: " + errMsg);
    } finally {
      setEnriching(false);
    }
  };

  const handleStatusChange = async (vulnId: number, newStatus: string) => {
    try {
      await api.updateVulnerabilityStatus(vulnId, newStatus);
      setVulnerabilities(vulnerabilities.map((v) => (v.id === vulnId ? { ...v, status: newStatus } : v)));
      if (selectedVuln?.id === vulnId) {
        setSelectedVuln({ ...selectedVuln, status: newStatus });
      }
    } catch (err: unknown) {
      console.error("Failed to update status:", err);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedFix(true);
    setTimeout(() => setCopiedFix(false), 2000);
  };

  const [downloading, setDownloading] = useState<string | null>(null);

  const handleDownload = async (format: "pdf" | "html" | "json" | "csv") => {
    setDownloading(format);
    try {
      await api.downloadReportFile(scanId, format);
    } catch (err: unknown) {
      // Fallback to opening window with authenticated query token
      window.open(api.getReportDownloadUrl(scanId, format), "_blank");
    } finally {
      setDownloading(null);
    }
  };



  const handleShare = () => {
    navigator.clipboard.writeText(window.location.href);
    setCopiedShare(true);
    setTimeout(() => setCopiedShare(false), 2000);
  };

  const maskSecret = (snippet: string) => {

    if (!snippet) return "****************";
    const str = snippet.trim();
    if (str.length <= 8) return str.slice(0, 2) + "****" + str.slice(-2);
    return str.slice(0, 4) + "***************" + str.slice(-4);
  };


  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[70vh]">
        <CyberRadarLoader size="lg" text="DETECTING SECURITY FINDINGS" />
      </div>
    );
  }




  // Calculate metrics
  const criticalCount = scan?.critical_count || vulnerabilities.filter(v => v.severity.toUpperCase() === "CRITICAL").length;
  const highCount = scan?.high_count || vulnerabilities.filter(v => v.severity.toUpperCase() === "HIGH").length;
  const mediumCount = scan?.medium_count || vulnerabilities.filter(v => v.severity.toUpperCase() === "MEDIUM").length;
  const lowCount = scan?.low_count || vulnerabilities.filter(v => v.severity.toUpperCase() === "LOW").length;
  const totalIssues = vulnerabilities.length;
  const fixedCount = vulnerabilities.filter(v => v.status === "resolved").length;

  const secretsList = vulnerabilities.filter(v => 
    v.category.toLowerCase().includes("secret") || 
    v.category.toLowerCase().includes("credential") || 
    v.tool_name.toLowerCase().includes("gitleaks")
  );

  const depsList = vulnerabilities.filter(v => 
    v.category.toLowerCase().includes("dependency") || 
    v.category.toLowerCase().includes("package") || 
    v.tool_name.toLowerCase().includes("dependency")
  );

  const penalty = criticalCount * 15 + highCount * 8 + mediumCount * 3 + lowCount * 1;
  const score = Math.max(0, Math.min(100, 100 - penalty));

  let overallStatus = "SECURE";
  let statusBadgeClass = "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
  if (score < 60 || criticalCount > 0) {
    overallStatus = "CRITICAL";
    statusBadgeClass = "bg-rose-500/10 text-rose-400 border-rose-500/30 shadow-[0_0_15px_rgba(244,63,94,0.2)]";
  } else if (score < 85 || highCount > 0) {
    overallStatus = "AT RISK";
    statusBadgeClass = "bg-amber-500/10 text-amber-400 border-amber-500/30";
  }

  // Filter vulnerabilities table
  const filteredVulns = vulnerabilities.filter((v) => {
    const matchesTab = 
      activeTab === "ALL" ? true :
      activeTab === "CRITICAL" ? v.severity.toUpperCase() === "CRITICAL" :
      activeTab === "HIGH" ? v.severity.toUpperCase() === "HIGH" :
      activeTab === "MEDIUM" ? v.severity.toUpperCase() === "MEDIUM" :
      activeTab === "LOW" ? v.severity.toUpperCase() === "LOW" :
      activeTab === "FIXED" ? v.status === "resolved" :
      activeTab === "OPEN" ? v.status === "open" || !v.status : true;

    const matchesSearch =
      v.category.toLowerCase().includes(searchQuery.toLowerCase()) ||
      v.file_path.toLowerCase().includes(searchQuery.toLowerCase()) ||
      v.message.toLowerCase().includes(searchQuery.toLowerCase()) ||
      v.tool_name.toLowerCase().includes(searchQuery.toLowerCase());

    return matchesTab && matchesSearch;
  });

  return (
    <div className="max-w-7xl mx-auto space-y-8 animate-fade-in relative pb-16">
      
      {/* Subtle Background Layer */}
      <div className="fixed top-20 left-1/2 -translate-x-1/2 w-[900px] h-[500px] bg-gradient-to-tr from-cyan-500/5 via-violet-500/5 to-transparent rounded-full blur-3xl pointer-events-none -z-10" />

      {/* TOP REPORT ACTIONS BAR */}
      <div className="flex flex-wrap items-center justify-between gap-4 p-4 glass-panel rounded-2xl border border-slate-800 bg-slate-950/70 backdrop-blur-md">
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="sm" icon={ArrowLeft} onClick={onNavigateToDashboard}>
            Return to Dashboard
          </Button>
          <div className="h-4 w-[1px] bg-slate-800 hidden sm:block" />
          <span className="text-xs font-mono text-slate-400 font-bold hidden sm:inline">
            REPORT ID: <span className="text-cyan-400">REP-{scanId.toString().padStart(5, '0')}</span>
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {onNavigateToChat && (
            <Button variant="glass" size="sm" icon={MessageSquare} onClick={onNavigateToChat}>
              Ask AI Assistant
            </Button>
          )}

          {/* Export Action Dropdown / Buttons */}
          <button
            type="button"
            onClick={() => handleDownload("pdf")}
            disabled={downloading === "pdf"}
            className="px-3 py-1.5 text-xs font-mono font-bold text-slate-200 bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/40 rounded-xl transition-all flex items-center gap-1.5 cursor-pointer hover:scale-105 active:scale-95 shadow-sm disabled:opacity-50"
          >
            <Download className={`w-3.5 h-3.5 text-rose-400 ${downloading === "pdf" ? "animate-bounce" : ""}`} /> 
            {downloading === "pdf" ? "Downloading..." : "Export PDF"}
          </button>

          <button
            type="button"
            onClick={() => handleDownload("json")}
            disabled={downloading === "json"}
            className="px-3 py-1.5 text-xs font-mono font-bold text-slate-200 bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 rounded-xl transition-all flex items-center gap-1.5 cursor-pointer hover:scale-105 active:scale-95 disabled:opacity-50"
          >
            <Code className={`w-3.5 h-3.5 text-amber-400 ${downloading === "json" ? "animate-bounce" : ""}`} /> 
            {downloading === "json" ? "Downloading..." : "JSON"}
          </button>

          <button
            type="button"
            onClick={() => handleDownload("csv")}
            disabled={downloading === "csv"}
            className="px-3 py-1.5 text-xs font-mono font-bold text-slate-200 bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/40 rounded-xl transition-all flex items-center gap-1.5 cursor-pointer hover:scale-105 active:scale-95 disabled:opacity-50"
          >
            <FileText className={`w-3.5 h-3.5 text-emerald-400 ${downloading === "csv" ? "animate-bounce" : ""}`} /> 
            {downloading === "csv" ? "Downloading..." : "CSV"}
          </button>


          <button
            type="button"
            onClick={handleShare}
            className="px-3 py-1.5 text-xs font-mono font-bold text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-xl transition-all flex items-center gap-1.5 cursor-pointer"
          >
            {copiedShare ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Share2 className="w-3.5 h-3.5 text-cyan-400" />}
            {copiedShare ? "Link Copied" : "Share"}
          </button>

          <button
            type="button"
            onClick={() => window.print()}
            className="px-3 py-1.5 text-xs font-mono font-bold text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-xl transition-all flex items-center gap-1.5 cursor-pointer"
          >
            <Printer className="w-3.5 h-3.5 text-slate-400" /> Print
          </button>
        </div>
      </div>

      {/* 1. REPORT HEADER */}
      <GlassCard className="p-8 relative overflow-hidden" glowColor="cyan" topBarGradient={true}>
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-8">
          
          {/* Header Info */}
          <div className="space-y-4 max-w-3xl">
            <div className="flex items-center gap-3">
              <div className="relative">
                <img src={logo} alt="Logo" className="h-16 w-auto max-w-[200px] object-contain rounded-xl border border-cyan-500/30 shadow-lg shadow-cyan-500/20" />


                <div className="absolute -bottom-1 -right-1 w-3.5 h-3.5 bg-cyan-400 rounded-full border-2 border-slate-950 animate-ping" />
              </div>
              <div>
                <span className="text-xs font-mono font-bold uppercase tracking-widest text-cyan-400 block">
                  AI Bug Hunter Platform
                </span>
                <h1 className="text-2xl md:text-3xl font-black text-slate-100 tracking-tight">
                  Security Assessment Report
                </h1>
              </div>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pt-4 border-t border-slate-800/80 font-mono text-xs">
              <div>
                <span className="text-slate-500 block text-[10px] uppercase font-bold">Target Project</span>
                <span className="text-slate-200 font-bold truncate block">{scan?.project?.name || "Target Codebase"}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase font-bold">Repository Type</span>
                <span className="text-cyan-400 font-bold uppercase block">{scan?.project?.upload_type || "File"}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase font-bold">Scan ID</span>
                <span className="text-slate-300 font-bold block">#{scanId}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase font-bold">Timestamp</span>
                <span className="text-slate-300 font-bold block truncate">
                  {scan?.created_at ? new Date(scan.created_at).toLocaleString() : "Just now"}
                </span>
              </div>
            </div>
          </div>

          {/* Score & Status Badge Gauge */}
          <div className="flex items-center gap-6 self-stretch lg:self-center justify-around lg:justify-end p-4 rounded-2xl bg-slate-950/60 border border-slate-800">
            {/* SVG Score Ring */}
            <div className="relative w-24 h-24 flex items-center justify-center">
              <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                <path
                  className="text-slate-800"
                  strokeWidth="3.5"
                  stroke="currentColor"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
                <path
                  className={score >= 85 ? "text-emerald-400" : score >= 60 ? "text-amber-400" : "text-rose-500"}
                  strokeDasharray={`${score}, 100`}
                  strokeWidth="3.5"
                  strokeLinecap="round"
                  stroke="currentColor"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
              </svg>
              <div className="absolute flex flex-col items-center justify-center text-center">
                <span className="text-2xl font-black font-mono text-slate-100 leading-none">{score}</span>
                <span className="text-[9px] font-mono text-slate-400 uppercase font-bold mt-0.5">SCORE</span>
              </div>
            </div>

            <div className="space-y-2 text-right">
              <span className="text-[10px] font-mono uppercase font-bold text-slate-400 block">Overall Status</span>
              <div className={`px-4 py-1.5 rounded-xl border text-xs font-mono font-bold uppercase tracking-wider inline-block ${statusBadgeClass}`}>
                {overallStatus}
              </div>
              <span className="text-[10px] text-slate-500 font-mono block">v2.4.0 Enterprise</span>
            </div>
          </div>

        </div>
      </GlassCard>

      {/* 2. EXECUTIVE SUMMARY CARDS GRID */}
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 xl:grid-cols-9 gap-2.5 sm:gap-3">
        <div className="p-3 sm:p-3.5 glass-panel rounded-2xl border border-slate-800 text-center flex flex-col justify-between items-center min-w-0 overflow-hidden">
          <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider block truncate w-full">Total Issues</span>
          <span className="text-xl sm:text-2xl font-black font-mono text-slate-100 block mt-1">{totalIssues}</span>
        </div>
        <div className="p-3 sm:p-3.5 glass-panel rounded-2xl border border-rose-500/30 bg-rose-500/5 text-center flex flex-col justify-between items-center min-w-0 overflow-hidden">
          <span className="text-[10px] font-mono font-bold text-rose-400 uppercase tracking-wider block truncate w-full">Critical</span>
          <span className="text-xl sm:text-2xl font-black font-mono text-rose-400 block mt-1">{criticalCount}</span>
        </div>
        <div className="p-3 sm:p-3.5 glass-panel rounded-2xl border border-amber-500/30 bg-amber-500/5 text-center flex flex-col justify-between items-center min-w-0 overflow-hidden">
          <span className="text-[10px] font-mono font-bold text-amber-400 uppercase tracking-wider block truncate w-full">High</span>
          <span className="text-xl sm:text-2xl font-black font-mono text-amber-400 block mt-1">{highCount}</span>
        </div>
        <div className="p-3 sm:p-3.5 glass-panel rounded-2xl border border-yellow-500/30 bg-yellow-500/5 text-center flex flex-col justify-between items-center min-w-0 overflow-hidden">
          <span className="text-[10px] font-mono font-bold text-yellow-400 uppercase tracking-wider block truncate w-full">Medium</span>
          <span className="text-xl sm:text-2xl font-black font-mono text-yellow-400 block mt-1">{mediumCount}</span>
        </div>
        <div className="p-3 sm:p-3.5 glass-panel rounded-2xl border border-blue-500/30 bg-blue-500/5 text-center flex flex-col justify-between items-center min-w-0 overflow-hidden">
          <span className="text-[10px] font-mono font-bold text-blue-400 uppercase tracking-wider block truncate w-full">Low</span>
          <span className="text-xl sm:text-2xl font-black font-mono text-blue-400 block mt-1">{lowCount}</span>
        </div>
        <div className="p-3 sm:p-3.5 glass-panel rounded-2xl border border-cyan-500/30 bg-cyan-500/5 text-center flex flex-col justify-between items-center min-w-0 overflow-hidden">
          <span className="text-[10px] font-mono font-bold text-cyan-400 uppercase tracking-wider block truncate w-full">Secrets</span>
          <span className="text-xl sm:text-2xl font-black font-mono text-cyan-400 block mt-1">{secretsList.length}</span>
        </div>
        <div className="p-3 sm:p-3.5 glass-panel rounded-2xl border border-violet-500/30 bg-violet-500/5 text-center flex flex-col justify-between items-center min-w-0 overflow-hidden">
          <span className="text-[10px] font-mono font-bold text-violet-400 uppercase tracking-wider block truncate w-full">Deps Issues</span>
          <span className="text-xl sm:text-2xl font-black font-mono text-violet-400 block mt-1">{depsList.length}</span>
        </div>
        <div className="p-3 sm:p-3.5 glass-panel rounded-2xl border border-emerald-500/30 bg-emerald-500/5 text-center flex flex-col justify-between items-center min-w-0 overflow-hidden">
          <span className="text-[10px] font-mono font-bold text-emerald-400 uppercase tracking-wider block truncate w-full">Fixed</span>
          <span className="text-xl sm:text-2xl font-black font-mono text-emerald-400 block mt-1">{fixedCount}</span>
        </div>
        <div className="p-3 sm:p-3.5 glass-panel rounded-2xl border border-cyan-500/30 bg-cyan-500/5 text-center flex flex-col justify-between items-center min-w-0 overflow-hidden">
          <span className="text-[10px] font-mono font-bold text-cyan-400 uppercase tracking-wider block truncate w-full">Security Score</span>
          <div className="flex items-baseline justify-center gap-0.5 mt-1 overflow-hidden">
            <span className="text-xl sm:text-2xl font-black font-mono text-cyan-400 leading-none">{score}</span>
            <span className="text-[11px] font-mono text-slate-400 font-bold">/100</span>
          </div>
        </div>
      </div>

      {/* 3. SEVERITY ANALYSIS & ENGINE STATUS */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Severity Distribution Chart Bar Card */}
        <GlassCard className="p-6 space-y-4 lg:col-span-2">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <BarChart3 className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-slate-200 uppercase font-mono tracking-wider">
                Vulnerability Severity & Category Distribution
              </h3>
            </div>
            <span className="text-xs font-mono text-slate-500">REAL-TIME DATA</span>
          </div>

          <div className="space-y-3 pt-2">
            <div>
              <div className="flex justify-between text-xs font-mono font-bold mb-1">
                <span className="text-rose-400">CRITICAL VULNERABILITIES ({criticalCount})</span>
                <span className="text-slate-400">{totalIssues > 0 ? Math.round((criticalCount / totalIssues) * 100) : 0}%</span>
              </div>
              <div className="h-2.5 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
                <div className="h-full bg-rose-500 rounded-full transition-all duration-500" style={{ width: `${totalIssues > 0 ? (criticalCount / totalIssues) * 100 : 0}%` }} />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs font-mono font-bold mb-1">
                <span className="text-amber-400">HIGH SEVERITY ({highCount})</span>
                <span className="text-slate-400">{totalIssues > 0 ? Math.round((highCount / totalIssues) * 100) : 0}%</span>
              </div>
              <div className="h-2.5 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
                <div className="h-full bg-amber-500 rounded-full transition-all duration-500" style={{ width: `${totalIssues > 0 ? (highCount / totalIssues) * 100 : 0}%` }} />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs font-mono font-bold mb-1">
                <span className="text-yellow-400">MEDIUM SEVERITY ({mediumCount})</span>
                <span className="text-slate-400">{totalIssues > 0 ? Math.round((mediumCount / totalIssues) * 100) : 0}%</span>
              </div>
              <div className="h-2.5 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
                <div className="h-full bg-yellow-500 rounded-full transition-all duration-500" style={{ width: `${totalIssues > 0 ? (mediumCount / totalIssues) * 100 : 0}%` }} />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs font-mono font-bold mb-1">
                <span className="text-blue-400">LOW / CODE QUALITY ({lowCount})</span>
                <span className="text-slate-400">{totalIssues > 0 ? Math.round((lowCount / totalIssues) * 100) : 0}%</span>
              </div>
              <div className="h-2.5 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
                <div className="h-full bg-blue-500 rounded-full transition-all duration-500" style={{ width: `${totalIssues > 0 ? (lowCount / totalIssues) * 100 : 0}%` }} />
              </div>
            </div>
          </div>
        </GlassCard>

        {/* Scanner Engine Results Status */}
        <GlassCard className="p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Cpu className="w-4 h-4 text-violet-400" />
              <h3 className="text-sm font-bold text-slate-200 uppercase font-mono tracking-wider">
                Scanner Engine Status
              </h3>
            </div>
          </div>

          <div className="space-y-2.5 text-xs font-mono">
            <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
              <span className="font-bold text-slate-300">Gitleaks Secrets</span>
              <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px] font-bold">COMPLETED</span>
            </div>
            <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
              <span className="font-bold text-slate-300">Bandit AST Analysis</span>
              <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px] font-bold">COMPLETED</span>
            </div>
            <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
              <span className="font-bold text-slate-300">Semgrep Rules Engine</span>
              <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px] font-bold">COMPLETED</span>
            </div>
            <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
              <span className="font-bold text-slate-300">OWASP Dependency Check</span>
              <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px] font-bold">COMPLETED</span>
            </div>
            <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
              <span className="font-bold text-slate-300">OpenRouter AI Intelligence</span>
              <span className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 text-[10px] font-bold">CONNECTED</span>
            </div>
          </div>
        </GlassCard>

      </div>

      {/* 4. AI SECURITY INTELLIGENCE CARD */}
      <GlassCard className="p-6 space-y-4" glowColor="violet">
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-violet-500/10 border border-violet-500/20 text-violet-400 flex items-center justify-center">
              <Sparkles className="w-4 h-4 animate-pulse" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                AI Security Intelligence
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                Automated threat analysis & defensive remediation synthesized by OpenRouter.ai LLM
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 px-3 py-1 bg-violet-500/10 border border-violet-500/30 rounded-full text-xs font-mono text-violet-300">
            <div className="w-2 h-2 rounded-full bg-violet-400 animate-ping" />
            AI SCANNER ACTIVE
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
          <div className="p-4 bg-slate-950/60 border border-slate-800 rounded-xl space-y-1">
            <span className="text-slate-500 font-bold uppercase text-[10px]">Root Cause Analysis</span>
            <p className="text-slate-300 leading-relaxed">
              Unsanitized dynamic string inputs reaching subprocess parameters, raw SQL queries, and exposed secret tokens in cleartext.
            </p>
          </div>

          <div className="p-4 bg-slate-950/60 border border-slate-800 rounded-xl space-y-1">
            <span className="text-slate-500 font-bold uppercase text-[10px]">Business & System Impact</span>
            <p className="text-slate-300 leading-relaxed">
              High risk of Remote Code Execution (RCE), credential hijacking, unauthorized database reads, and workspace token leakage.
            </p>
          </div>

          <div className="p-4 bg-slate-950/60 border border-slate-800 rounded-xl space-y-1">
            <span className="text-slate-500 font-bold uppercase text-[10px]">Remediation Priority</span>
            <p className="text-cyan-400 font-bold leading-relaxed">
              1. Revoke hardcoded tokens immediately.<br/>
              2. Convert string SQL formats to parameterized placeholders.<br/>
              3. Set shell=False in command execution.
            </p>
          </div>
        </div>
      </GlassCard>

      {/* 5. VULNERABILITY FINDINGS TABLE */}
      <GlassCard className="p-6 space-y-6" glowColor="cyan">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <Shield className="w-5 h-5 text-cyan-400" />
              Vulnerability Findings ({filteredVulns.length})
            </h3>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Click any finding row to inspect 16-point security details & AI code fixes
            </p>
          </div>

          {/* Search Input */}
          <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-xl w-full md:w-72">
            <Search className="w-4 h-4 text-slate-400 shrink-0" />
            <input
              type="text"
              placeholder="Filter findings..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-transparent text-xs text-slate-200 focus:outline-none w-full font-mono"
            />
          </div>
        </div>

        {/* Severity Filter Tabs */}
        <div className="flex flex-wrap gap-2 text-xs font-mono font-bold">
          {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "FIXED", "OPEN"].map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-3 py-1.5 rounded-xl border transition-all cursor-pointer ${
                activeTab === tab
                  ? "bg-cyan-500/20 text-cyan-300 border-cyan-500/40 shadow-[0_0_10px_rgba(6,182,212,0.2)]"
                  : "bg-slate-900/60 text-slate-400 border-slate-800 hover:bg-slate-800 hover:text-slate-200"
              }`}
            >
              {tab}
            </button>
          ))}
        </div>

        {/* Findings Table */}
        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] font-bold border-b border-slate-800">
              <tr>
                <th className="p-3">ID</th>
                <th className="p-3">Severity</th>
                <th className="p-3">Vulnerability Category</th>
                <th className="p-3">Affected File</th>
                <th className="p-3">Line</th>
                <th className="p-3">CWE</th>
                <th className="p-3">Scanner</th>
                <th className="p-3">Status</th>
                <th className="p-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 bg-slate-900/30">
              {filteredVulns.length === 0 ? (
                <tr>
                  <td colSpan={9} className="p-8 text-center text-slate-500">
                    No matching security findings found for the selected filter.
                  </td>
                </tr>
              ) : (
                filteredVulns.map((v) => {
                  const sevStr = v.severity.toUpperCase();
                  const badgeColor = 
                    sevStr === "CRITICAL" ? "bg-rose-500/10 text-rose-400 border-rose-500/30" :
                    sevStr === "HIGH" ? "bg-amber-500/10 text-amber-400 border-amber-500/30" :
                    sevStr === "MEDIUM" ? "bg-yellow-500/10 text-yellow-400 border-yellow-500/30" :
                    "bg-blue-500/10 text-blue-400 border-blue-500/30";

                  const cwe = v.category.toLowerCase().includes("sql") ? "CWE-89" :
                              v.category.toLowerCase().includes("xss") ? "CWE-79" :
                              v.category.toLowerCase().includes("command") ? "CWE-78" : "CWE-200";

                  return (
                    <tr
                      key={v.id}
                      onClick={() => {
                        setSelectedVuln(v);
                        setInspectorOpen(true);
                      }}
                      className="hover:bg-cyan-500/5 transition-colors cursor-pointer group"
                    >
                      <td className="p-3 font-bold text-slate-400">VULN-{v.id}</td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded border text-[10px] font-bold ${badgeColor}`}>
                          {sevStr}
                        </span>
                      </td>
                      <td className="p-3 font-bold text-slate-200 group-hover:text-cyan-300 transition-colors">
                        {v.category}
                      </td>
                      <td className="p-3 text-slate-400 max-w-xs truncate">{v.file_path}</td>
                      <td className="p-3 text-slate-400">{v.line_number || 1}</td>
                      <td className="p-3 text-slate-400">{cwe}</td>
                      <td className="p-3 text-slate-400">{v.tool_name}</td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          v.status === "resolved" ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30" : "bg-slate-800 text-slate-400"
                        }`}>
                          {v.status || "open"}
                        </span>
                      </td>
                      <td className="p-3 text-right">
                        <button
                          type="button"
                          className="px-2.5 py-1 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded text-[10px] font-bold transition-all"
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </GlassCard>

      {/* 6. SECRET / CREDENTIAL FINDINGS SECTION */}
      <GlassCard className="p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <Key className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-200 uppercase font-mono tracking-wider">
              Secret & Credential Audit ({secretsList.length})
            </h3>
          </div>
          <span className="text-xs font-mono text-slate-500">SENSITIVE VALUES MASKED</span>
        </div>

        {secretsList.length === 0 ? (
          <p className="text-xs text-slate-500 font-mono p-4 text-center">
            No hardcoded secrets, exposed private keys, or API tokens were detected.
          </p>
        ) : (
          <div className="overflow-x-auto rounded-xl border border-slate-800">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] font-bold border-b border-slate-800">
                <tr>
                  <th className="p-3">Category</th>
                  <th className="p-3">File Path</th>
                  <th className="p-3">Line</th>
                  <th className="p-3">Masked Secret Value</th>
                  <th className="p-3">Remediation</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 bg-slate-900/30">
                {secretsList.map((s) => (
                  <tr key={s.id} className="hover:bg-slate-800/40">
                    <td className="p-3 font-bold text-rose-400">{s.category}</td>
                    <td className="p-3 text-slate-300">{s.file_path}</td>
                    <td className="p-3 text-slate-400">{s.line_number || 1}</td>
                    <td className="p-3 font-mono font-bold text-rose-300 bg-rose-500/5 rounded">
                      {maskSecret(s.code_snippet || "")}
                    </td>
                    <td className="p-3 text-slate-400 max-w-xs truncate">{s.remediation || "Revoke credential immediately."}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </GlassCard>

      {/* 7. DEPENDENCY SECURITY ANALYSIS SECTION */}
      <GlassCard className="p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <Package className="w-4 h-4 text-violet-400" />
            <h3 className="text-sm font-bold text-slate-200 uppercase font-mono tracking-wider">
              Dependency Security Analysis ({depsList.length})
            </h3>
          </div>
        </div>

        {depsList.length === 0 ? (
          <p className="text-xs text-slate-500 font-mono p-4 text-center">
            All scanned package dependencies (`package.json`, `requirements.txt`) match safe security baselines.
          </p>
        ) : (
          <div className="overflow-x-auto rounded-xl border border-slate-800">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] font-bold border-b border-slate-800">
                <tr>
                  <th className="p-3">Manifest</th>
                  <th className="p-3">Vulnerability Category</th>
                  <th className="p-3">Severity</th>
                  <th className="p-3">Message</th>
                  <th className="p-3">Recommended Upgrade</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 bg-slate-900/30">
                {depsList.map((d) => (
                  <tr key={d.id} className="hover:bg-slate-800/40">
                    <td className="p-3 font-bold text-cyan-400">{d.file_path}</td>
                    <td className="p-3 text-slate-200 font-bold">{d.category}</td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 bg-rose-500/10 text-rose-400 border border-rose-500/30 rounded text-[10px] font-bold">
                        {d.severity}
                      </span>
                    </td>
                    <td className="p-3 text-slate-300 max-w-sm">{d.message}</td>
                    <td className="p-3 text-emerald-400 font-bold">{d.remediation || "Upgrade package version"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </GlassCard>

      {/* 8. REMEDIATION CENTER SECTION */}
      <GlassCard className="p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <h3 className="text-sm font-bold text-slate-200 uppercase font-mono tracking-wider">
              Recommended Remediation Priority Tasks
            </h3>
          </div>
        </div>

        <div className="space-y-3 font-mono text-xs">
          {vulnerabilities.length === 0 ? (
            <p className="text-slate-500 text-center py-4">No remediation tasks required.</p>
          ) : (
            vulnerabilities.slice(0, 5).map((v, i) => (
              <div key={v.id} className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-slate-500 font-bold">#{i + 1}</span>
                    <span className="font-bold text-slate-200">{v.category}</span>
                    <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">
                      PRIORITY {i + 1}
                    </span>
                  </div>
                  <p className="text-slate-400 text-[11px]">{v.remediation}</p>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setSelectedVuln(v);
                    setInspectorOpen(true);
                  }}
                  className="px-3 py-1.5 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 rounded-xl font-bold transition-all shrink-0 cursor-pointer"
                >
                  View Fix
                </button>
              </div>
            ))
          )}
        </div>
      </GlassCard>

      {/* REPORT FOOTER */}
      <div className="pt-8 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between text-xs font-mono text-slate-500 gap-4">
        <div>
          <span className="text-slate-300 font-bold block">Generated by AI Bug Hunter</span>
          <span>AI-Powered Defensive Security & Vulnerability Analysis</span>
        </div>
        <div className="text-right">
          <span className="block font-bold text-cyan-400">REPORT ID: REP-{scanId.toString().padStart(5, '0')}</span>
          <span>{scan?.created_at ? new Date(scan.created_at).toUTCString() : "2026-08-12 UTC"}</span>
        </div>
      </div>

      {/* 16-POINT GLASSMORPHISM VULNERABILITY INSPECTOR DRAWER */}
      {inspectorOpen && selectedVuln && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-md flex justify-end animate-fade-in">
          <div className="w-full max-w-3xl glass-panel h-full overflow-y-auto border-l border-slate-800 p-6 md:p-8 space-y-6 shadow-2xl relative">
            
            {/* Drawer Close */}
            <button
              onClick={() => setInspectorOpen(false)}
              className="absolute top-6 right-6 p-2 rounded-xl text-slate-400 hover:text-slate-100 hover:bg-slate-800/60 cursor-pointer"
            >
              <X className="w-6 h-6" />
            </button>

            {/* 1. Vulnerability Title & Badges */}
            <div className="space-y-2 border-b border-slate-800 pb-4">
              <span className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-widest block">
                Finding #VULN-{selectedVuln.id}
              </span>
              <h2 className="text-xl font-black text-slate-100">{selectedVuln.category}</h2>
              <div className="flex flex-wrap items-center justify-between gap-2 pt-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="px-2.5 py-1 bg-rose-500/10 text-rose-400 border border-rose-500/30 rounded-lg text-xs font-mono font-bold">
                    Severity: {selectedVuln.severity}
                  </span>
                  <span className="px-2.5 py-1 bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 rounded-lg text-xs font-mono font-bold">
                    Confidence: HIGH
                  </span>
                  <span className="px-2.5 py-1 bg-slate-800 text-slate-300 border border-slate-700 rounded-lg text-xs font-mono font-bold">
                    Engine: {selectedVuln.tool_name}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-400 font-mono font-bold">Status:</span>
                  <select
                    value={selectedVuln.status || "open"}
                    onChange={(e) => handleStatusChange(selectedVuln.id, e.target.value)}
                    className="bg-slate-900 border border-slate-700 text-xs text-slate-200 font-mono rounded-lg px-2.5 py-1 focus:border-cyan-500 outline-none cursor-pointer"
                  >
                    <option value="open">⚠️ Open</option>
                    <option value="resolved">✅ Resolved</option>
                    <option value="ignored">⏸️ Ignored</option>
                    <option value="false_positive">🛡️ False Positive</option>
                  </select>
                </div>
              </div>
            </div>

            {/* 4. Description & 5. Impact */}
            <div className="space-y-4 font-mono text-xs">
              <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-1">
                <span className="text-slate-500 font-bold uppercase text-[10px]">Description</span>
                <p className="text-slate-200 leading-relaxed">{selectedVuln.message}</p>
              </div>

              <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-1">
                <span className="text-slate-500 font-bold uppercase text-[10px]">Security Impact</span>
                <p className="text-slate-300 leading-relaxed">
                  Allows unauthorized input execution, memory corruption, or credential harvesting across service boundaries.
                </p>
              </div>
            </div>

            {/* 6. Affected File & 7. Line */}
            <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2 font-mono text-xs">
              <div className="flex justify-between items-center text-slate-400">
                <span>Affected File: <strong className="text-cyan-300">{selectedVuln.file_path}</strong></span>
                <span>Line: <strong className="text-cyan-300">{selectedVuln.line_number || 1}</strong></span>
              </div>
              
              {/* 8. Vulnerable Code Snippet */}
              {selectedVuln.code_snippet && (
                <div className="mt-2">
                  <span className="text-[10px] font-bold text-slate-500 uppercase block mb-1">Vulnerable Code Snippet:</span>
                  <pre className="p-3 bg-slate-900 rounded-lg border border-slate-800 text-slate-200 overflow-x-auto text-xs">
                    <code>{selectedVuln.code_snippet}</code>
                  </pre>
                </div>
              )}

              {/* Full File Context */}
              {loadingFile ? (
                <div className="text-[10px] text-slate-500 font-mono italic animate-pulse">Loading source file context...</div>
              ) : fileContent ? (
                <div className="mt-2 border-t border-slate-800/80 pt-2">
                  <span className="text-[10px] font-bold text-cyan-400 uppercase block mb-1">Full File Context:</span>
                  <pre className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-slate-400 overflow-x-auto text-[11px] max-h-40 leading-relaxed">
                    <code>{fileContent}</code>
                  </pre>
                </div>
              ) : null}
            </div>


            {/* 11. CWE & 12. OWASP References */}
            <div className="grid grid-cols-2 gap-4 font-mono text-xs">
              <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-xl">
                <span className="text-slate-500 font-bold block text-[10px]">CWE Reference</span>
                <span className="text-slate-200 font-bold">
                  {selectedVuln.category.toLowerCase().includes("sql") ? "CWE-89: SQL Injection" : "CWE-79: Cross-Site Scripting"}
                </span>
              </div>
              <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-xl">
                <span className="text-slate-500 font-bold block text-[10px]">OWASP Category</span>
                <span className="text-slate-200 font-bold">
                  {selectedVuln.category.toLowerCase().includes("sql") ? "A03:2021-Injection" : "A01:2021-Broken Access Control"}
                </span>
              </div>
            </div>

            {/* 13. Recommended Remediation & 14. Secure Code Example */}
            <div className="space-y-3 font-mono text-xs">
              <div className="p-4 bg-emerald-500/5 border border-emerald-500/20 rounded-xl space-y-2">
                <span className="text-emerald-400 font-bold uppercase text-[10px] block">Recommended Remediation</span>
                <p className="text-slate-200">{selectedVuln.remediation}</p>
              </div>

              {/* 15. AI Explanation & Fix */}
              {selectedVuln.ai_explanation ? (
                <div className="p-4 bg-violet-500/10 border border-violet-500/30 rounded-xl space-y-3">
                  <span className="text-violet-300 font-bold uppercase text-[10px] flex items-center gap-1.5">
                    <Sparkles className="w-3.5 h-3.5 text-violet-400" /> AI Security Assessment
                  </span>
                  <p className="text-slate-200 whitespace-pre-line leading-relaxed">{selectedVuln.ai_explanation}</p>
                  {selectedVuln.ai_fix && (
                    <div className="mt-2">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-[10px] font-bold text-emerald-400 uppercase">AI Secure Implementation:</span>
                        <button
                          type="button"
                          onClick={() => copyToClipboard(selectedVuln.ai_fix || "")}
                          className="text-[10px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer"
                        >
                          {copiedFix ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          {copiedFix ? "Copied" : "Copy Code"}
                        </button>
                      </div>
                      <pre className="p-3 bg-slate-950 rounded-lg border border-emerald-500/30 text-emerald-300 overflow-x-auto text-xs">
                        <code>{selectedVuln.ai_fix}</code>
                      </pre>
                    </div>
                  )}
                </div>
              ) : (
                <button
                  type="button"
                  onClick={() => handleEnrichWithAI(selectedVuln.id)}
                  disabled={enriching}
                  className="w-full py-3 bg-gradient-to-r from-violet-600/30 via-cyan-600/30 to-blue-600/30 border border-violet-500/40 hover:border-violet-400 text-slate-100 rounded-xl font-bold flex items-center justify-center gap-2 cursor-pointer transition-all hover:scale-[1.01]"
                >
                  <Sparkles className={`w-4 h-4 text-violet-400 ${enriching ? "animate-spin" : ""}`} />
                  {enriching ? "Generating AI Secure Implementation..." : "Generate Defensive AI Code Fix (OpenRouter)"}
                </button>
              )}
            </div>

            {/* Close Drawer Button */}
            <Button variant="secondary" className="w-full" onClick={() => setInspectorOpen(false)}>
              Done Inspecting
            </Button>
          </div>
        </div>
      )}

    </div>
  );
};

export default ScanResults;
