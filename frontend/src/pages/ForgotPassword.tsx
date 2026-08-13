import React, { useState } from "react";
import { api } from "../services/api";
import logo from "../assets/logo.jpg";


import { Lock, User, Key, AlertCircle, CheckCircle2, RefreshCw } from "lucide-react";
import { GlassCard } from "../components/ui/GlassCard";
import { Button } from "../components/ui/Button";

interface ForgotPasswordProps {
  onCancel: () => void;
  onResetSuccess: () => void;
}

export const ForgotPassword: React.FC<ForgotPasswordProps> = ({ onCancel, onResetSuccess }) => {
  const [username, setUsername] = useState("");
  const [recoveryKey, setRecoveryKey] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username || !recoveryKey || !newPassword) {
      setError("Please fill in all recovery fields.");
      return;
    }
    if (newPassword.length < 6) {
      setError("Password must be at least 6 characters long.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      await api.forgotPassword(username, recoveryKey, newPassword);
      setSuccess(true);
      setTimeout(() => {
        onResetSuccess();
      }, 1800);
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : "Password reset failed. Verify your username and recovery token.";
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
      
      <div className="absolute top-1/4 left-1/3 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none -z-10" />
      <div className="absolute bottom-1/4 right-1/3 w-96 h-96 bg-violet-500/5 rounded-full blur-3xl pointer-events-none -z-10" />

      <div className="w-full max-w-md relative z-10">
        <GlassCard className="p-8 shadow-2xl relative" topBarGradient={true}>
          
          <div className="flex flex-col items-center mb-8 text-center">
            <img
              src={logo}
              alt="AI Bug Hunter Logo"
              className="h-20 w-auto max-w-[220px] object-contain rounded-xl shadow-xl shadow-cyan-500/20 border border-slate-800/80 mb-3"
            />


            <h1 className="text-2xl font-black tracking-wider text-gradient font-sans">
              Account Recovery
            </h1>
            <p className="text-slate-400 text-xs mt-1 font-mono uppercase tracking-widest">
              Deploy Recovery Token To Reset Credentials
            </p>
          </div>

          {error && (
            <div className="mb-6 p-3 bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs rounded-xl flex items-center gap-2.5">
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
              <span>{error}</span>
            </div>
          )}

          {success && (
            <div className="mb-6 p-3 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs rounded-xl flex items-center gap-2.5">
              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
              <span>Password reset successful! Redirecting to login...</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1.5 font-mono">
                Username
              </label>
              <div className="relative">
                <User className="w-4 h-4 text-slate-500 absolute left-3.5 top-3.5 pointer-events-none" />
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full pl-10 pr-4 py-3 glass-input rounded-xl text-sm focus:outline-none placeholder-slate-600"
                  placeholder="john_doe"
                  required
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between items-center mb-1.5">
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">
                  Recovery Token
                </label>
                <span className="text-[10px] text-slate-500 font-mono">Default: HUNTER_RECOVERY_2026</span>
              </div>
              <div className="relative">
                <Key className="w-4 h-4 text-slate-500 absolute left-3.5 top-3.5 pointer-events-none" />
                <input
                  type="text"
                  value={recoveryKey}
                  onChange={(e) => setRecoveryKey(e.target.value)}
                  className="w-full pl-10 pr-4 py-3 glass-input rounded-xl text-sm focus:outline-none placeholder-slate-600 font-mono"
                  placeholder="HUNTER_RECOVERY_2026"
                  required
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1.5 font-mono">
                New Password
              </label>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-3.5 pointer-events-none" />
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="w-full pl-10 pr-4 py-3 glass-input rounded-xl text-sm focus:outline-none placeholder-slate-600"
                  placeholder="••••••••"
                  required
                />
              </div>
            </div>

            <Button
              type="submit"
              variant="primary"
              size="lg"
              loading={loading || success}
              className="w-full justify-center mt-2"
              icon={RefreshCw}
            >
              Reset Credentials
            </Button>
          </form>

          <div className="mt-8 pt-5 border-t border-slate-800/80 text-center">
            <button
              type="button"
              onClick={onCancel}
              className="text-xs text-cyan-400 hover:underline font-semibold cursor-pointer"
            >
              Return to Sign In
            </button>
          </div>
        </GlassCard>
      </div>
    </div>
  );
};

export default ForgotPassword;
