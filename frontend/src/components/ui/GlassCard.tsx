import React from "react";

interface GlassCardProps {
  children: React.ReactNode;
  className?: string;
  hoverEffect?: boolean;
  glowColor?: "cyan" | "violet" | "rose" | "emerald" | "none";
  topBarGradient?: boolean;
  onClick?: () => void;
}

export const GlassCard: React.FC<GlassCardProps> = ({
  children,
  className = "",
  hoverEffect = true,
  glowColor = "none",
  topBarGradient = false,
  onClick,
}) => {
  const glowMap = {
    cyan: "hover:border-cyan-500/40 hover:shadow-[0_0_20px_rgba(6,182,212,0.15)]",
    violet: "hover:border-violet-500/40 hover:shadow-[0_0_20px_rgba(139,92,246,0.15)]",
    rose: "hover:border-rose-500/40 hover:shadow-[0_0_20px_rgba(239,68,68,0.15)]",
    emerald: "hover:border-emerald-500/40 hover:shadow-[0_0_20px_rgba(16,185,129,0.15)]",
    none: "hover:border-slate-700/60",
  };

  return (
    <div
      onClick={onClick}
      className={`glass-panel rounded-2xl relative overflow-hidden transition-all duration-300 ${
        hoverEffect ? `glass-panel-hover ${glowMap[glowColor]}` : ""
      } ${onClick ? "cursor-pointer" : ""} ${className}`}
    >
      {topBarGradient && (
        <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-cyan-500 via-blue-500 to-violet-500 rounded-t-2xl" />
      )}
      {children}
    </div>
  );
};
