import React, { useState } from "react";
import { api } from "../services/api";
import logo from "../assets/logo.jpg";

import { Lock, User, AlertCircle, Eye, EyeOff, ArrowRight } from "lucide-react";

import { GlassCard } from "../components/ui/GlassCard";
import { Button } from "../components/ui/Button";

interface LoginProps {
  onLoginSuccess: (role: string, username: string) => void;
  onNavigateToRegister: () => void;
  onNavigateToForgotPassword: () => void;
}

export const Login: React.FC<LoginProps> = ({ onLoginSuccess, onNavigateToRegister, onNavigateToForgotPassword }) => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username || !password) {
      setError("Please enter your username and password credentials.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const data = await api.login(username, password);
      onLoginSuccess(data.role, data.username);
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : "Invalid credentials. Please try again.";
      setError(errMsg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#030712] px-4 relative overflow-hidden font-sans cyber-grid">
      <video
        className="auth-video-background"
        autoPlay
        loop
        muted
        playsInline
        aria-hidden="true"
      >
        <source src="/auth-background.mp4" type="video/mp4" />
      </video>
      <div className="auth-video-overlay" aria-hidden="true" />
      
      {/* Soft Ambient Radial Lights */}
      <div className="absolute top-1/4 left-1/3 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none -z-10" />
      <div className="absolute bottom-1/4 right-1/3 w-96 h-96 bg-violet-500/5 rounded-full blur-3xl pointer-events-none -z-10" />

      <div className="w-full max-w-md relative z-10">
        <GlassCard className="p-8 shadow-2xl relative" topBarGradient={true}>
          
          {/* Header */}
          <div className="flex flex-col items-center mb-8 text-center">
            <div className="relative mb-3">
              <img
                src={logo}
                alt="AI Bug Hunter Logo"
                className="h-20 w-auto max-w-[220px] object-contain rounded-xl shadow-xl shadow-cyan-500/20 border border-slate-800/80"
              />


              <div className="absolute -bottom-1 -right-1 w-4 h-4 bg-emerald-500 rounded-full border-2 border-slate-950 status-dot-active" />
            </div>
            <h1 className="text-2xl font-black tracking-wider text-gradient font-sans">
              AI BUG HUNTER
            </h1>
            <p className="text-slate-400 text-xs mt-1 font-mono uppercase tracking-widest">
              Enterprise SAST & Vulnerability Suite
            </p>
          </div>

          {error && (
            <div className="mb-6 p-3 bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs rounded-xl flex items-center gap-2.5">
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1.5 font-mono">
                Username or Email
              </label>
              <div className="relative">
                <User className="w-4 h-4 text-slate-500 absolute left-3.5 top-3.5 pointer-events-none" />
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full pl-10 pr-4 py-3 glass-input rounded-xl text-sm focus:outline-none placeholder-slate-600"
                  placeholder="e.g. auditor@company.com or username"
                  required
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1.5 font-mono">
                Password
              </label>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-3.5 pointer-events-none" />
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-10 pr-10 py-3 glass-input rounded-xl text-sm focus:outline-none placeholder-slate-600"
                  placeholder="••••••••"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3.5 top-3.5 text-slate-500 hover:text-slate-300 transition-colors cursor-pointer"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <Button
              type="submit"
              variant="primary"
              size="lg"
              loading={loading}
              className="w-full justify-center"
              icon={ArrowRight}
            >
              Access Security Suite
            </Button>
          </form>

          <div className="mt-8 pt-5 border-t border-slate-800/80 flex items-center justify-between text-xs">
            <button
              type="button"
              onClick={onNavigateToRegister}
              className="text-cyan-400 hover:underline font-semibold cursor-pointer"
            >
              Create New Account
            </button>
            <button
              type="button"
              onClick={onNavigateToForgotPassword}
              className="text-slate-400 hover:text-slate-200 cursor-pointer"
            >
              Forgot Password?
            </button>
          </div>
        </GlassCard>
      </div>
    </div>
  );
};

export default Login;
