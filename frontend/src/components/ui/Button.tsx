import React from "react";
import type { LucideIcon } from "lucide-react";

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "glass" | "danger" | "ghost";
  size?: "sm" | "md" | "lg";
  icon?: LucideIcon;
  loading?: boolean;
  children: React.ReactNode;
}

export const Button: React.FC<ButtonProps> = ({
  variant = "primary",
  size = "md",
  icon: Icon,
  loading = false,
  children,
  className = "",
  disabled,
  ...props
}) => {
  const variantStyles = {
    primary:
      "bg-gradient-to-r from-cyan-500 via-blue-600 to-violet-600 hover:from-cyan-400 hover:to-violet-500 text-white font-bold shadow-lg shadow-cyan-500/20 border border-cyan-400/30 hover:border-cyan-400/60",
    secondary:
      "bg-slate-850 hover:bg-slate-800 text-slate-200 border border-slate-700/80 hover:border-slate-600 shadow-md",
    glass:
      "bg-slate-900/60 hover:bg-slate-800/80 text-cyan-400 border border-cyan-500/30 hover:border-cyan-400/60 backdrop-blur-md shadow-sm",
    danger:
      "bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 hover:border-rose-500/60 shadow-sm",
    ghost: "bg-transparent hover:bg-slate-850 text-slate-400 hover:text-slate-100",
  };

  const sizeStyles = {
    sm: "px-3 py-1.5 text-xs gap-1.5 rounded-lg",
    md: "px-4 py-2.5 text-xs font-bold gap-2 rounded-xl",
    lg: "px-6 py-3.5 text-sm font-bold gap-2.5 rounded-xl",
  };

  return (
    <button
      disabled={disabled || loading}
      className={`inline-flex items-center justify-center font-sans tracking-wide transition-all duration-200 cursor-pointer hover:-translate-y-0.5 active:translate-y-0 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed ${variantStyles[variant]} ${sizeStyles[size]} ${className}`}
      {...props}
    >
      {loading ? (
        <span className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin shrink-0" />
      ) : Icon ? (
        <Icon className="w-4 h-4 shrink-0" />
      ) : null}
      <span>{children}</span>
    </button>
  );
};
