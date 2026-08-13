import React, { useEffect, useState } from "react";
import logo from "../assets/logo.jpg";
import { Shield, Cpu, Activity, Lock, Terminal, Sparkles, Server } from "lucide-react";


interface SystemBootLoaderProps {
  onComplete: () => void;
}

interface ModuleStatus {
  id: string;
  name: string;
  icon: React.ElementType;
  connected: boolean;
  connectAt: number;
}

export const SystemBootLoader: React.FC<SystemBootLoaderProps> = ({ onComplete }) => {
  const [progress, setProgress] = useState(0);
  const [statusText, setStatusText] = useState("Initializing Security Engine...");
  const [isDone, setIsDone] = useState(false);
  const [fadingOut, setFadingOut] = useState(false);

  const [modules, setModules] = useState<ModuleStatus[]>([
    { id: "ai", name: "AI Engine", icon: Cpu, connected: false, connectAt: 25 },
    { id: "sast", name: "SAST Scanner", icon: Terminal, connected: false, connectAt: 50 },
    { id: "secret", name: "Secret Scanner", icon: Lock, connected: false, connectAt: 70 },
    { id: "dep", name: "Dependency Scanner", icon: Server, connected: false, connectAt: 85 },
    { id: "intel", name: "Security Intelligence", icon: Sparkles, connected: false, connectAt: 100 },
  ]);

  useEffect(() => {
    let currentProgress = 0;
    const interval = setInterval(() => {
      // Smoothly increment progress
      currentProgress += Math.floor(Math.random() * 4) + 2;
      if (currentProgress > 100) currentProgress = 100;

      setProgress(currentProgress);

      // Update loading message based on progress thresholds
      if (currentProgress < 20) {
        setStatusText("Initializing Security Engine...");
      } else if (currentProgress < 40) {
        setStatusText("Loading Security Modules...");
      } else if (currentProgress < 60) {
        setStatusText("Connecting Scanner Engines...");
      } else if (currentProgress < 80) {
        setStatusText("Initializing AI Analysis...");
      } else if (currentProgress < 95) {
        setStatusText("Loading Vulnerability Intelligence...");
      } else if (currentProgress < 100) {
        setStatusText("Preparing Security Environment...");
      } else {
        setStatusText("SECURITY ENGINE READY");
        setIsDone(true);
      }

      // Update module statuses
      setModules((prev) =>
        prev.map((mod) => ({
          ...mod,
          connected: currentProgress >= mod.connectAt,
        }))
      );

      if (currentProgress >= 100) {
        clearInterval(interval);
        // Hold at 100% briefly, then trigger fade out and complete
        setTimeout(() => {
          setFadingOut(true);
          setTimeout(() => {
            onComplete();
          }, 600);
        }, 500);
      }
    }, 45);

    return () => clearInterval(interval);
  }, [onComplete]);

  // SVG ring stroke math (r=45, circumference ≈ 283)
  const circumference = 283;
  const strokeDashoffset = circumference - (circumference * progress) / 100;

  return (
    <div
      className={`fixed inset-0 z-50 flex flex-col items-center justify-between p-6 md:p-12 bg-[#030712] text-slate-100 overflow-hidden font-sans select-none cyber-grid transition-opacity duration-700 ${
        fadingOut ? "opacity-0 pointer-events-none" : "opacity-100"
      }`}
    >
      {/* Ambient Background Radial Glows */}
      <div className="absolute top-1/4 left-1/4 w-[500px] h-[500px] bg-cyan-500/10 rounded-full blur-[120px] pointer-events-none -z-10 animate-pulse" />
      <div className="absolute bottom-1/4 right-1/4 w-[500px] h-[500px] bg-violet-500/10 rounded-full blur-[120px] pointer-events-none -z-10 animate-pulse" />

      {/* Floating Holographic Grid Particles */}
      <div className="absolute inset-0 opacity-20 pointer-events-none bg-[radial-gradient(#06b6d4_1px,transparent_1px)] [background-size:32px_32px]" />

      {/* TOP BRAND BAR */}
      <div className="w-full max-w-5xl flex items-center justify-between pt-2 border-b border-slate-800/60 pb-4 z-10">
        <div className="flex items-center gap-2 font-mono text-xs text-slate-400">
          <Shield className="w-4 h-4 text-cyan-400 animate-pulse" />
          <span className="font-bold text-slate-200 tracking-wider uppercase">AI BUG HUNTER OS</span>
          <span className="text-slate-600">/</span>
          <span className="text-cyan-400">BOOT SEQUENCE</span>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs">
          <div className={`w-2 h-2 rounded-full ${isDone ? "bg-emerald-400 status-dot-active" : "bg-amber-400 animate-ping"}`} />
          <span className={isDone ? "text-emerald-400 font-bold" : "text-amber-400 font-bold"}>
            {isDone ? "SYSTEM ONLINE" : "BOOTING ENGINES"}
          </span>
        </div>
      </div>

      {/* CENTERPIECE LOGO & RADAR SCANNER */}
      <div className="relative flex flex-col items-center justify-center my-auto z-10">
        
        {/* Rotating Concentric Outer Ring 1 */}
        <div className="absolute w-72 h-72 rounded-full border border-cyan-500/20 border-dashed animate-spin-slow pointer-events-none" />
        
        {/* Rotating Concentric Outer Ring 2 (Opposing) */}
        <div className="absolute w-80 h-80 rounded-full border border-violet-500/15 border-dotted animate-spin-reverse pointer-events-none" />

        {/* Dynamic Scanning Radar Line */}
        <div className="absolute w-72 h-72 rounded-full pointer-events-none opacity-40 animate-spin-slow">
          <div className="w-1/2 h-1/2 bg-gradient-to-br from-cyan-400/30 to-transparent rounded-tl-full origin-bottom-right" />
        </div>

        {/* Center Circular Progress SVG Ring */}
        <div className="relative w-64 h-64 flex items-center justify-center">
          <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
            {/* Track Ring */}
            <circle
              cx="50"
              cy="50"
              r="45"
              className="text-slate-900"
              strokeWidth="4"
              stroke="currentColor"
              fill="none"
            />
            {/* Active Progress Ring */}
            <circle
              cx="50"
              cy="50"
              r="45"
              className={isDone ? "text-emerald-400" : "text-cyan-400"}
              strokeWidth="4"
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              stroke="currentColor"
              fill="none"
              style={{ transition: "stroke-dashoffset 0.1s linear, color 0.3s ease" }}
            />
          </svg>

          {/* Logo Center Frame */}
          <div className="absolute inset-4 rounded-full glass-panel flex flex-col items-center justify-center p-4 border border-cyan-500/30 shadow-[0_0_40px_rgba(6,182,212,0.25)] animate-pulse-glow overflow-hidden">
            <img
              src={logo}
              alt="AI Bug Hunter"
              className="w-24 h-24 object-contain rounded-xl drop-shadow-[0_0_15px_rgba(6,182,212,0.5)]"
            />
          </div>
        </div>

        {/* Percentage Indicator & Dynamic Status Text */}
        <div className="mt-8 text-center space-y-2 font-mono">
          <div className="text-3xl font-black tracking-tight text-gradient">
            {progress}%
          </div>

          <h2 className="text-xl font-bold tracking-widest text-slate-100 uppercase">
            AI BUG HUNTER
          </h2>

          <p className={`text-xs font-bold uppercase tracking-wider transition-colors duration-300 ${
            isDone ? "text-emerald-400" : "text-cyan-400"
          }`}>
            {statusText}
          </p>
        </div>

      </div>

      {/* BOTTOM SYSTEM MODULE STATUS PANEL */}
      <div className="w-full max-w-4xl glass-panel rounded-2xl p-4 md:p-6 border border-slate-800/80 shadow-2xl z-10 space-y-3">
        <div className="flex items-center justify-between border-b border-slate-800 pb-2 text-xs font-mono">
          <span className="text-slate-400 font-bold uppercase tracking-widest flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" /> SYSTEM MODULE STATUS
          </span>
          <span className="text-slate-500 font-mono text-[10px]">VERIFYING ENGINE INTEGRITY</span>
        </div>

        {/* Module Status Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 pt-1">
          {modules.map((mod) => {
            const Icon = mod.icon;
            return (
              <div
                key={mod.id}
                className={`p-3 rounded-xl border transition-all duration-300 flex flex-col justify-between space-y-2 ${
                  mod.connected
                    ? "bg-slate-900/80 border-emerald-500/40 text-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.1)]"
                    : "bg-slate-950/60 border-slate-800/80 text-slate-500"
                }`}
              >
                <div className="flex items-center justify-between">
                  <Icon className={`w-4 h-4 ${mod.connected ? "text-emerald-400" : "text-slate-500"}`} />
                  <div
                    className={`w-2 h-2 rounded-full ${
                      mod.connected ? "bg-emerald-400 status-dot-active" : "bg-amber-400/60 animate-pulse"
                    }`}
                  />
                </div>

                <div>
                  <span className="text-[11px] font-bold text-slate-200 block truncate font-mono">
                    {mod.name}
                  </span>
                  <span
                    className={`text-[9px] font-mono font-bold uppercase block mt-0.5 ${
                      mod.connected ? "text-emerald-400" : "text-amber-400/80"
                    }`}
                  >
                    {mod.connected ? "CONNECTED" : "INITIALIZING"}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

    </div>
  );
};

export default SystemBootLoader;
