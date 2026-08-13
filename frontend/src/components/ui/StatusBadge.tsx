import React from "react";

export type SeverityType = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "SUCCESS";
export type ScanStatusType = "completed" | "scanning" | "queued" | "failed" | "pending";

interface StatusBadgeProps {
  status?: ScanStatusType | string;
  severity?: SeverityType | string;
  label?: string;
  size?: "sm" | "md" | "lg";
  pulse?: boolean;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({
  status,
  severity,
  label,
  size = "md",
  pulse = false,
}) => {
  const normalizedSeverity = (severity || status || "").toUpperCase();

  let styles = "bg-slate-800/80 text-slate-300 border-slate-700/50";
  let dotColor = "bg-slate-400";

  switch (normalizedSeverity) {
    case "CRITICAL":
      styles = "bg-rose-500/10 text-rose-400 border-rose-500/30 shadow-[0_0_10px_rgba(239,68,68,0.15)]";
      dotColor = "bg-rose-500";
      break;
    case "HIGH":
      styles = "bg-orange-500/10 text-orange-400 border-orange-500/30 shadow-[0_0_10px_rgba(249,115,22,0.15)]";
      dotColor = "bg-orange-500";
      break;
    case "MEDIUM":
      styles = "bg-amber-500/10 text-amber-400 border-amber-500/30 shadow-[0_0_10px_rgba(245,158,11,0.15)]";
      dotColor = "bg-amber-500";
      break;
    case "LOW":
      styles = "bg-blue-500/10 text-blue-400 border-blue-500/30 shadow-[0_0_10px_rgba(59,130,246,0.15)]";
      dotColor = "bg-blue-500";
      break;
    case "COMPLETED":
    case "SUCCESS":
      styles = "bg-emerald-500/10 text-emerald-400 border-emerald-500/30 shadow-[0_0_10px_rgba(16,185,129,0.15)]";
      dotColor = "bg-emerald-500";
      break;
    case "SCANNING":
    case "RUNNING":
      styles = "bg-cyan-500/10 text-cyan-400 border-cyan-500/30 shadow-[0_0_10px_rgba(6,182,212,0.15)]";
      dotColor = "bg-cyan-400";
      break;
    case "QUEUED":
    case "PENDING":
      styles = "bg-violet-500/10 text-violet-400 border-violet-500/30";
      dotColor = "bg-violet-400";
      break;
    case "FAILED":
      styles = "bg-rose-500/15 text-rose-300 border-rose-500/40";
      dotColor = "bg-rose-500";
      break;
    default:
      break;
  }

  const sizeClasses = {
    sm: "px-2 py-0.5 text-[10px] gap-1",
    md: "px-2.5 py-1 text-xs gap-1.5",
    lg: "px-3.5 py-1.5 text-sm gap-2 font-bold",
  };

  const displayText = label || (severity ? severity : status ? status.toUpperCase() : "");

  return (
    <span
      className={`inline-flex items-center font-mono font-semibold rounded-full border backdrop-blur-md uppercase tracking-wider ${sizeClasses[size]} ${styles}`}
    >
      <span
        className={`w-1.5 h-1.5 rounded-full ${dotColor} ${
          pulse || status === "scanning" ? "animate-ping" : ""
        }`}
      />
      <span>{displayText}</span>
    </span>
  );
};
