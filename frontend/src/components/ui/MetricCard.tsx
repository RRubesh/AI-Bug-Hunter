import React, { useEffect, useState } from "react";
import { GlassCard } from "./GlassCard";
import type { LucideIcon } from "lucide-react";

interface MetricCardProps {
  title: string;
  value: number | string;
  icon: LucideIcon;
  trend?: string;
  trendUp?: boolean;
  accentColor?: "rose" | "orange" | "amber" | "cyan" | "emerald" | "violet" | "blue";
  description?: string;
  badge?: string;
}

export const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  icon: Icon,
  trend,
  trendUp,
  accentColor = "cyan",
  description,
  badge,
}) => {
  const [displayValue, setDisplayValue] = useState<number>(0);
  const isNumeric = typeof value === "number";

  useEffect(() => {
    if (!isNumeric) return;
    const target = value as number;
    if (target === 0) {
      setDisplayValue(0);
      return;
    }

    let start = 0;
    const duration = 800; // ms
    const steps = 25;
    const increment = target / steps;
    const stepTime = duration / steps;

    const timer = setInterval(() => {
      start += increment;
      if (start >= target) {
        setDisplayValue(target);
        clearInterval(timer);
      } else {
        setDisplayValue(Math.floor(start));
      }
    }, stepTime);

    return () => clearInterval(timer);
  }, [value, isNumeric]);

  const colorStyles = {
    rose: {
      border: "hover:border-rose-500/40",
      iconBg: "bg-rose-500/10 text-rose-400 border-rose-500/20",
      glow: "hover:shadow-[0_0_20px_rgba(239,68,68,0.15)]",
    },
    orange: {
      border: "hover:border-orange-500/40",
      iconBg: "bg-orange-500/10 text-orange-400 border-orange-500/20",
      glow: "hover:shadow-[0_0_20px_rgba(249,115,22,0.15)]",
    },
    amber: {
      border: "hover:border-amber-500/40",
      iconBg: "bg-amber-500/10 text-amber-400 border-amber-500/20",
      glow: "hover:shadow-[0_0_20px_rgba(245,158,11,0.15)]",
    },
    cyan: {
      border: "hover:border-cyan-500/40",
      iconBg: "bg-cyan-500/10 text-cyan-400 border-cyan-500/20",
      glow: "hover:shadow-[0_0_20px_rgba(6,182,212,0.15)]",
    },
    emerald: {
      border: "hover:border-emerald-500/40",
      iconBg: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
      glow: "hover:shadow-[0_0_20px_rgba(16,185,129,0.15)]",
    },
    violet: {
      border: "hover:border-violet-500/40",
      iconBg: "bg-violet-500/10 text-violet-400 border-violet-500/20",
      glow: "hover:shadow-[0_0_20px_rgba(139,92,246,0.15)]",
    },
    blue: {
      border: "hover:border-blue-500/40",
      iconBg: "bg-blue-500/10 text-blue-400 border-blue-500/20",
      glow: "hover:shadow-[0_0_20px_rgba(59,130,246,0.15)]",
    },
  };

  const style = colorStyles[accentColor];

  return (
    <GlassCard className={`p-5 group transition-all duration-300 ${style.border} ${style.glow}`}>
      <div className="flex items-start justify-between">
        <div>
          <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 block font-mono">
            {title}
          </span>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-3xl font-black tracking-tight text-slate-100 font-sans">
              {isNumeric ? displayValue : value}
            </span>
            {badge && (
              <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
                {badge}
              </span>
            )}
          </div>
        </div>
        <div className={`p-3 rounded-xl border ${style.iconBg} transition-transform group-hover:scale-110 duration-300`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>

      {(trend || description) && (
        <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs">
          {trend && (
            <span className={`font-semibold flex items-center gap-1 ${trendUp ? "text-emerald-400" : "text-rose-400"}`}>
              {trendUp ? "↑" : "↓"} {trend}
            </span>
          )}
          {description && <span className="text-slate-400 text-[11px] truncate">{description}</span>}
        </div>
      )}
    </GlassCard>
  );
};
