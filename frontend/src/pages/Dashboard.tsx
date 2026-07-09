import React, { useEffect, useState } from "react";
import { api } from "../services/api";
import type { ScanStats, Project } from "../services/api";
import { ShieldAlert, ShieldX, Play, Trash2, CheckCircle2, AlertTriangle, Eye } from "lucide-react";

interface DashboardProps {
  onNavigateToUpload: () => void;
  onNavigateToScanProgress: (scanId: number) => void;
  onNavigateToScanResults: (scanId: number) => void;
}

export const Dashboard: React.FC<DashboardProps> = ({
  onNavigateToUpload,
  onNavigateToScanProgress,
  onNavigateToScanResults,
}) => {
  const [stats, setStats] = useState<ScanStats | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [scaningProject, setScanningProject] = useState<number | null>(null);

  const fetchDashboardData = async () => {
    try {
      const statsData = await api.getDashboardStats();
      setStats(statsData);
      const projectsData = await api.getProjects();
      setProjects(projectsData);
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : "Failed to load dashboard data.";
      setError(errMsg);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    let active = true;
    (async () => {
      await Promise.resolve();
      if (active) {
        fetchDashboardData();
      }
    })();
    return () => {
      active = false;
    };
  }, []);

  const handleStartScan = async (projectId: number) => {
    setScanningProject(projectId);
    try {
      const newScan = await api.triggerScan(projectId);
      onNavigateToScanProgress(newScan.id);
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      alert("Error starting scan: " + errMsg);
    } finally {
      setScanningProject(null);
    }
  };

  const handleDeleteProject = async (id: number) => {
    if (!confirm("Are you sure you want to delete this project and all its scans?")) return;
    try {
      await api.deleteProject(id);
      setProjects(projects.filter((p) => p.id !== id));
      // Refresh stats
      const statsData = await api.getDashboardStats();
      setStats(statsData);
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      alert("Failed to delete project: " + errMsg);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="w-10 h-10 border-4 border-slate-800 border-t-rose-500 rounded-full animate-spin"></div>
      </div>
    );
  }

  // Calculate percentages for SVG donut chart
  const severityDistribution = stats?.severity_distribution || { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const totalVulns = stats?.total_vulnerabilities || 0;

  const donutSegments = () => {
    const values = [
      { key: "Critical", val: severityDistribution.critical, color: "#f43f5e" },
      { key: "High", val: severityDistribution.high, color: "#f97316" },
      { key: "Medium", val: severityDistribution.medium, color: "#eab308" },
      { key: "Low", val: severityDistribution.low, color: "#3b82f6" },
    ];
    const filtered = values.filter((v) => v.val > 0);
    if (filtered.length === 0) return [];
    
    const sum = filtered.reduce((acc, curr) => acc + curr.val, 0);
    let cumulativePercent = 0;
    
    return filtered.map((item) => {
      const percentage = (item.val / sum) * 100;
      const startPercent = cumulativePercent;
      cumulativePercent += percentage;
      return {
        ...item,
        startPercent,
        endPercent: cumulativePercent,
      };
    });
  };

  const renderDonutChart = () => {
    const segments = donutSegments();
    if (segments.length === 0) {
      return (
        <div className="flex items-center justify-center h-48 border border-dashed border-slate-800 rounded-xl text-xs text-slate-500 font-mono">
          No vulnerabilities to display chart
        </div>
      );
    }

    return (
      <div className="flex flex-col md:flex-row items-center justify-around gap-6 py-4">
        {/* SVG Circle */}
        <div className="relative w-40 h-40">
          <svg viewBox="0 0 36 36" className="w-full h-full transform -rotate-90">
            {/* Background hole */}
            <circle cx="18" cy="18" r="15.915" fill="none" stroke="#151a30" strokeWidth="3" />
            
            {segments.map((seg, i) => {
              const sliceVal = seg.endPercent - seg.startPercent;
              const strokeDasharray = `${sliceVal} ${100 - sliceVal}`;
              const strokeDashoffset = 100 - seg.startPercent;
              
              return (
                <circle
                  key={i}
                  cx="18"
                  cy="18"
                  r="15.915"
                  fill="none"
                  stroke={seg.color}
                  strokeWidth="3.2"
                  strokeDasharray={strokeDasharray}
                  strokeDashoffset={strokeDashoffset}
                  className="transition-all duration-300"
                />
              );
            })}
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-2xl font-black text-slate-100">{totalVulns}</span>
            <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Warnings</span>
          </div>
        </div>
        {/* Legend */}
        <div className="space-y-2">
          {segments.map((seg, i) => (
            <div key={i} className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full" style={{ backgroundColor: seg.color }}></div>
              <span className="text-xs font-semibold text-slate-300">{seg.key}:</span>
              <span className="text-xs font-bold text-slate-400 font-mono">{seg.val} ({Math.round((seg.val / totalVulns) * 100)}%)</span>
            </div>
          ))}
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Page Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-black text-slate-100 tracking-tight">Security Dashboard</h1>
          <p className="text-xs text-slate-400 mt-1">
            Overview of repositories, scans, and system risk profile.
          </p>
        </div>
        <button
          onClick={onNavigateToUpload}
          className="px-4 py-2 bg-gradient-to-r from-rose-500 to-amber-500 text-white text-xs font-bold rounded-lg shadow-md hover:from-rose-600 hover:to-amber-600 cursor-pointer transition-all"
        >
          New Project Scan +
        </button>
      </div>

      {error && (
        <div className="p-3 bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs rounded-lg">
          {error}
        </div>
      )}

      {/* KPI Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-5">
        <div className="p-5 glass-panel rounded-xl border-slate-800 glow-rose">
          <div className="flex justify-between items-start">
            <div>
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Critical Risks</span>
              <span className="text-3xl font-black text-rose-500 mt-1 block">{severityDistribution.critical}</span>
            </div>
            <div className="w-8 h-8 rounded-lg bg-rose-500/10 flex items-center justify-center text-rose-500 border border-rose-500/20">
              <ShieldX className="w-4 h-4" />
            </div>
          </div>
        </div>

        <div className="p-5 glass-panel rounded-xl border-slate-800 glow-orange">
          <div className="flex justify-between items-start">
            <div>
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">High Severity</span>
              <span className="text-3xl font-black text-orange-500 mt-1 block">{severityDistribution.high}</span>
            </div>
            <div className="w-8 h-8 rounded-lg bg-orange-500/10 flex items-center justify-center text-orange-500 border border-orange-500/20">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
        </div>

        <div className="p-5 glass-panel rounded-xl border-slate-800 glow-orange">
          <div className="flex justify-between items-start">
            <div>
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Medium Severity</span>
              <span className="text-3xl font-black text-amber-500 mt-1 block">{severityDistribution.medium}</span>
            </div>
            <div className="w-8 h-8 rounded-lg bg-amber-500/10 flex items-center justify-center text-amber-500 border border-amber-500/20">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
        </div>

        <div className="p-5 glass-panel rounded-xl border-slate-800 glow-blue">
          <div className="flex justify-between items-start">
            <div>
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Total Scans Run</span>
              <span className="text-3xl font-black text-slate-200 mt-1 block">{stats?.total_scans || 0}</span>
            </div>
            <div className="w-8 h-8 rounded-lg bg-blue-500/10 flex items-center justify-center text-blue-500 border border-blue-500/20">
              <CheckCircle2 className="w-4 h-4" />
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution Donut Chart */}
        <div className="lg:col-span-1 p-5 glass-panel rounded-xl border-slate-800">
          <h2 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-4 border-b border-slate-800/80 pb-2">Severity Breakdown</h2>
          {renderDonutChart()}
        </div>

        {/* Scan History Table */}
        <div className="lg:col-span-2 p-5 glass-panel rounded-xl border-slate-800">
          <h2 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-4 border-b border-slate-800/80 pb-2">Recent Scans Queue</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="text-slate-500 border-b border-slate-800/60">
                  <th className="pb-2 font-bold uppercase">Project</th>
                  <th className="pb-2 font-bold uppercase">Status</th>
                  <th className="pb-2 font-bold uppercase">Criticals</th>
                  <th className="pb-2 font-bold uppercase">Highs</th>
                  <th className="pb-2 font-bold uppercase">Date</th>
                  <th className="pb-2 font-bold uppercase text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {stats?.scans_history && stats.scans_history.length > 0 ? (
                  stats.scans_history.map((scan) => {
                    const proj = projects.find((p) => p.id === scan.project_id);
                    const isRunning = scan.status === "running" || scan.status === "pending";
                    return (
                      <tr key={scan.id} className="border-b border-slate-900 hover:bg-slate-900/30 transition-colors">
                        <td className="py-2.5 font-semibold text-slate-300">
                          {proj ? proj.name : `Project #${scan.project_id}`}
                        </td>
                        <td className="py-2.5">
                          {isRunning ? (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/10 text-amber-500 border border-amber-500/20 flex items-center gap-1.5 w-fit">
                              <span className="w-1.5 h-1.5 rounded-full bg-amber-500 animate-ping"></span>
                              {scan.status.toUpperCase()} ({scan.progress}%)
                            </span>
                          ) : scan.status === "completed" ? (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 w-fit">
                              COMPLETED
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-500 border border-rose-500/20 w-fit">
                              FAILED
                            </span>
                          )}
                        </td>
                        <td className="py-2.5 font-bold text-rose-500 font-mono">{scan.critical_count}</td>
                        <td className="py-2.5 font-bold text-orange-500 font-mono">{scan.high_count}</td>
                        <td className="py-2.5 text-slate-500 font-mono">
                          {new Date(scan.created_at).toLocaleDateString()}
                        </td>
                        <td className="py-2.5 text-right">
                          {isRunning ? (
                            <button
                              onClick={() => onNavigateToScanProgress(scan.id)}
                              className="text-[10px] font-bold text-amber-500 hover:underline flex items-center gap-1 ml-auto cursor-pointer"
                            >
                              <Eye className="w-3.5 h-3.5" /> Track
                            </button>
                          ) : scan.status === "completed" ? (
                            <button
                              onClick={() => onNavigateToScanResults(scan.id)}
                              className="text-[10px] font-bold text-emerald-400 hover:underline flex items-center gap-1 ml-auto cursor-pointer"
                            >
                              <Eye className="w-3.5 h-3.5" /> View Results
                            </button>
                          ) : (
                            <span className="text-slate-600">-</span>
                          )}
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan={6} className="py-4 text-center text-slate-500 font-mono">
                      No scan operations triggered yet
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Projects Management Card */}
      <div className="p-5 glass-panel rounded-xl border-slate-800">
        <h2 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-4 border-b border-slate-800/80 pb-2">Configured Projects</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="text-slate-500 border-b border-slate-800/60">
                <th className="pb-2 font-bold uppercase">Name</th>
                <th className="pb-2 font-bold uppercase">Source Type</th>
                <th className="pb-2 font-bold uppercase">Primary Language</th>
                <th className="pb-2 font-bold uppercase">Uploaded At</th>
                <th className="pb-2 font-bold uppercase text-right">Scan Commands</th>
              </tr>
            </thead>
            <tbody>
              {projects.length > 0 ? (
                projects.map((proj) => (
                  <tr key={proj.id} className="border-b border-slate-900 hover:bg-slate-900/30 transition-colors">
                    <td className="py-3 font-semibold text-slate-300">
                      <div>
                        <span>{proj.name}</span>
                        {proj.description && <span className="block text-[10px] font-normal text-slate-500 mt-0.5">{proj.description}</span>}
                      </div>
                    </td>
                    <td className="py-3">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-900 text-slate-400 border border-slate-800 uppercase">
                        {proj.upload_type}
                      </span>
                    </td>
                    <td className="py-3 font-semibold text-slate-400">{proj.language_detected || "Detecting..."}</td>
                    <td className="py-3 text-slate-500 font-mono">
                      {new Date(proj.created_at).toLocaleString()}
                    </td>
                    <td className="py-3 text-right">
                      <div className="flex items-center gap-3 justify-end">
                        <button
                          onClick={() => handleStartScan(proj.id)}
                          disabled={scaningProject === proj.id}
                          className="px-2.5 py-1 bg-gradient-to-r from-emerald-500 to-teal-500 text-white rounded text-[10px] font-bold shadow hover:from-emerald-600 cursor-pointer flex items-center gap-1 disabled:opacity-50"
                        >
                          <Play className="w-3 h-3 fill-white" /> Scan
                        </button>
                        <button
                          onClick={() => handleDeleteProject(proj.id)}
                          className="p-1 text-rose-500 hover:bg-rose-500/10 rounded cursor-pointer transition-colors"
                          title="Delete Project"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={5} className="py-6 text-center text-slate-500 font-mono">
                    No projects uploaded. Click "New Project Scan" to upload code!
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
