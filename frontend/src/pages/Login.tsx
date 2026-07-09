import React, { useState } from "react";
import { api } from "../services/api";
import logo from "../assets/logo.jpg";
import { Lock, User, AlertCircle } from "lucide-react";

interface LoginProps {
  onLoginSuccess: (role: string, username: string) => void;
  onNavigateToRegister: () => void;
  onNavigateToForgotPassword: () => void;
}

export const Login: React.FC<LoginProps> = ({ onLoginSuccess, onNavigateToRegister, onNavigateToForgotPassword }) => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username || !password) {
      setError("Please fill in all fields.");
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
    <div className="min-h-screen flex items-center justify-center bg-[#040712] px-4 relative overflow-hidden font-sans cyber-grid">
      
      {/* Background Neon Glowing Elements */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pulsing-dot -z-10"></div>
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-blue-500/5 rounded-full blur-3xl pulsing-dot -z-10"></div>
 
      <div className="w-full max-w-md glass-panel rounded-2xl border-slate-800/80 p-8 shadow-2xl relative">
        {/* Decorative Top Glow Bar */}
        <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-cyan-500 to-emerald-400 rounded-t-2xl"></div>
 
        <div className="flex flex-col items-center mb-8">
          <img src={logo} alt="AI Bug Hunter Logo" className="w-16 h-16 rounded-2xl object-cover shadow-lg shadow-cyan-500/20 border border-slate-800 mb-4" />
          <h1 className="text-2xl font-bold tracking-tight text-slate-100 flex items-center gap-1.5">
            AI Bug Hunter
          </h1>
          <p className="text-slate-400 text-xs mt-1 text-center">
            Defensive Security & AI-Powered Vulnerability Analysis
          </p>
        </div>
 
        {error && (
          <div className="mb-6 p-3 bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs rounded-lg flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}
 
        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1.5">
              Username
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                <User className="w-4 h-4" />
              </div>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full pl-10 pr-4 py-2.5 bg-slate-950/60 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-600 text-sm focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors"
                placeholder="developer"
                required
              />
            </div>
          </div>
 
          <div>
            <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1.5">
              Password
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                <Lock className="w-4 h-4" />
              </div>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full pl-10 pr-4 py-2.5 bg-slate-950/60 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-600 text-sm focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors"
                placeholder="••••••••"
                required
              />
            </div>
          </div>
 
          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 px-4 bg-gradient-to-r from-cyan-500 to-emerald-500 hover:from-cyan-600 hover:to-emerald-600 text-slate-950 font-bold text-sm rounded-lg shadow-lg shadow-cyan-500/10 focus:outline-none transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
          >
            {loading ? (
              <span className="w-4 h-4 border-2 border-slate-950/30 border-t-slate-950 rounded-full animate-spin"></span>
            ) : (
              "Access Platform"
            )}
          </button>
        </form>
 
        <div className="mt-8 text-center border-t border-slate-800/80 pt-5 flex justify-between items-center px-1">
          <p className="text-xs text-slate-500">
            Don't have an account?{" "}
            <button
              type="button"
              onClick={onNavigateToRegister}
              className="text-cyan-400 hover:underline font-semibold focus:outline-none cursor-pointer"
            >
              Register here
            </button>
          </p>
          <button
            type="button"
            onClick={onNavigateToForgotPassword}
            className="text-xs text-cyan-400 hover:underline font-semibold focus:outline-none cursor-pointer"
          >
            Forgot password?
          </button>
        </div>
      </div>
    </div>
  );
};
