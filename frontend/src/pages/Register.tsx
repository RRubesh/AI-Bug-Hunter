import React, { useState } from "react";
import { api } from "../services/api";
import logo from "../assets/logo.jpg";
import { Lock, User, Mail, AlertCircle, CheckCircle2, Eye, EyeOff, UserPlus } from "lucide-react";
import { GlassCard } from "../components/ui/GlassCard";
import { Button } from "../components/ui/Button";

interface RegisterProps {
  onRegisterSuccess: () => void;
  onNavigateToLogin: () => void;
}

export const Register: React.FC<RegisterProps> = ({ onRegisterSuccess, onNavigateToLogin }) => {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);

  const getPasswordStrength = (pass: string) => {
    if (!pass) return { score: 0, label: "", color: "" };
    let score = 0;
    if (pass.length >= 8) score++;
    if (/[A-Z]/.test(pass) && /[a-z]/.test(pass)) score++;
    if (/[0-9]/.test(pass)) score++;
    if (/[!@#$%^&*(),.?":{}|<>]/.test(pass)) score++;

    if (score <= 1) return { score: 1, label: "Weak", color: "bg-rose-500 text-rose-400" };
    if (score === 2 || score === 3) return { score: 2, label: "Medium", color: "bg-amber-500 text-amber-400" };
    return { score: 3, label: "Strong", color: "bg-emerald-500 text-emerald-400" };
  };

  const strength = getPasswordStrength(password);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanUsername = username.trim();
    const cleanEmail = email.trim().toLowerCase();

    if (!cleanUsername || !cleanEmail || !password || !confirmPassword) {
      setError("Please fill in all required fields.");
      return;
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(cleanEmail)) {
      setError("Please enter a valid email address.");
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters long.");
      return;
    }
    if (!/[A-Za-z]/.test(password) || !/[0-9!@#$%^&*(),.?":{}|<>]/.test(password)) {
      setError("Password must contain letters and at least one number or special character.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      await api.register(cleanUsername, cleanEmail, password);
      setSuccess(true);
      setTimeout(() => {
        onRegisterSuccess();
      }, 1500);
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : "Registration failed. Username or email may already be registered.";
      setError(errMsg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#030712] px-4 py-8 relative overflow-hidden font-sans cyber-grid">
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

      <div className="w-full max-w-md relative z-10 my-auto">
        <GlassCard className="p-8 shadow-2xl relative" topBarGradient={true}>
          
          <div className="flex flex-col items-center mb-6 text-center">
            <img
              src={logo}
              alt="AI Bug Hunter Logo"
              className="h-16 w-auto max-w-[200px] object-contain rounded-xl shadow-xl shadow-cyan-500/20 border border-slate-800/80 mb-3"
            />

            <h1 className="text-2xl font-black tracking-wider text-gradient font-sans">
              Create Account
            </h1>
            <p className="text-slate-400 text-xs mt-1 font-mono uppercase tracking-widest">
              Secure Code Analysis Platform
            </p>
          </div>

          {error && (
            <div className="mb-5 p-3 bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs rounded-xl flex items-center gap-2.5">
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
              <span>{error}</span>
            </div>
          )}

          {success && (
            <div className="mb-5 p-3 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs rounded-xl flex items-center gap-2.5">
              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
              <span>Account registered! Redirecting to login...</span>
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
                  className="w-full pl-10 pr-4 py-2.5 glass-input rounded-xl text-sm focus:outline-none placeholder-slate-600"
                  placeholder="e.g. security_auditor"
                  required
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1.5 font-mono">
                Email Address
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 text-slate-500 absolute left-3.5 top-3.5 pointer-events-none" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 glass-input rounded-xl text-sm focus:outline-none placeholder-slate-600"
                  placeholder="auditor@company.com"
                  required
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between items-center mb-1.5">
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">
                  Password
                </label>
                {password && (
                  <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${strength.color.split(" ")[1]}`}>
                    {strength.label}
                  </span>
                )}
              </div>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-3.5 pointer-events-none" />
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-10 pr-10 py-2.5 glass-input rounded-xl text-sm focus:outline-none placeholder-slate-600"
                  placeholder="Min 8 chars, letters & numbers"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3.5 top-3 text-slate-500 hover:text-slate-300 transition-colors cursor-pointer"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              {password && (
                <div className="grid grid-cols-3 gap-1 mt-1.5">
                  <div className={`h-1 rounded-full ${strength.score >= 1 ? (strength.score === 1 ? 'bg-rose-500' : strength.score === 2 ? 'bg-amber-500' : 'bg-emerald-500') : 'bg-slate-800'}`} />
                  <div className={`h-1 rounded-full ${strength.score >= 2 ? (strength.score === 2 ? 'bg-amber-500' : 'bg-emerald-500') : 'bg-slate-800'}`} />
                  <div className={`h-1 rounded-full ${strength.score >= 3 ? 'bg-emerald-500' : 'bg-slate-800'}`} />
                </div>
              )}
            </div>

            <div>
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1.5 font-mono">
                Confirm Password
              </label>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-3.5 pointer-events-none" />
                <input
                  type={showPassword ? "text" : "password"}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 glass-input rounded-xl text-sm focus:outline-none placeholder-slate-600"
                  placeholder="Repeat password"
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
              icon={UserPlus}
            >
              Create Account
            </Button>
          </form>

          <div className="mt-6 pt-4 border-t border-slate-800/80 text-center text-xs">
            <span className="text-slate-500">Already have an account? </span>
            <button
              type="button"
              onClick={onNavigateToLogin}
              className="text-cyan-400 hover:underline font-semibold cursor-pointer"
            >
              Sign In Here
            </button>
          </div>
        </GlassCard>
      </div>
    </div>
  );
};

export default Register;
