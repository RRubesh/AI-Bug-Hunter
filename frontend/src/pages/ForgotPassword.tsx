import React, { useState, useEffect } from "react";
import { api } from "../services/api";
import logo from "../assets/logo.jpg";
import { Lock, Mail, Key, AlertCircle, CheckCircle2, RefreshCw, Send, ArrowLeft, Eye, EyeOff, Inbox } from "lucide-react";
import { GlassCard } from "../components/ui/GlassCard";
import { Button } from "../components/ui/Button";

interface ForgotPasswordProps {
  onCancel: () => void;
  onResetSuccess: () => void;
  initialToken?: string;
}

export const ForgotPassword: React.FC<ForgotPasswordProps> = ({ onCancel, onResetSuccess, initialToken }) => {
  const [step, setStep] = useState<"request" | "reset">(initialToken ? "reset" : "request");
  const [email, setEmail] = useState("");
  const [token, setToken] = useState(initialToken || "");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [devToken, setDevToken] = useState<string | null>(null);
  const [requestSent, setRequestSent] = useState(false);
  
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [successMsg, setSuccessMsg] = useState("");

  useEffect(() => {
    if (initialToken) {
      setToken(initialToken);
      setStep("reset");
    }
  }, [initialToken]);

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

  const strength = getPasswordStrength(newPassword);

  const handleRequestSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanEmail = email.trim().toLowerCase();
    if (!cleanEmail) {
      setError("Please enter your account email address.");
      return;
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(cleanEmail)) {
      setError("Please enter a valid email address.");
      return;
    }

    setLoading(true);
    setError("");
    setSuccessMsg("");
    setDevToken(null);

    try {
      const res = await api.forgotPassword(cleanEmail);
      setRequestSent(true);
      setSuccessMsg(res.message || "If an account exists for this email, a password reset link has been sent.");
      if (res.dev_token) {
        setDevToken(res.dev_token);
      }
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : "Failed to process request. Please try again.";
      setError(errMsg);
    } finally {
      setLoading(false);
    }
  };

  const handleResetSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanToken = token.trim();
    if (!cleanToken || !newPassword || !confirmPassword) {
      setError("Please fill in all required fields.");
      return;
    }
    if (newPassword !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    if (newPassword.length < 8) {
      setError("Password must be at least 8 characters long.");
      return;
    }
    if (!/[A-Za-z]/.test(newPassword) || !/[0-9!@#$%^&*(),.?":{}|<>]/.test(newPassword)) {
      setError("Password must contain letters and at least one number or special character.");
      return;
    }

    setLoading(true);
    setError("");
    setSuccessMsg("");

    try {
      const res = await api.resetPassword(cleanToken, newPassword);
      setSuccessMsg(res.message || "Password reset completed successfully!");
      setTimeout(() => {
        onResetSuccess();
      }, 1600);
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : "Password reset failed. Invalid or expired token.";
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
              Account Recovery
            </h1>
            <p className="text-slate-400 text-xs mt-1 font-mono uppercase tracking-widest">
              {step === "request" ? "Request Password Reset Link" : "Set New Secure Password"}
            </p>
          </div>

          {error && (
            <div className="mb-5 p-3.5 bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs rounded-xl flex items-center gap-2.5 animate-fadeIn">
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
              <span className="leading-relaxed">{error}</span>
            </div>
          )}

          {/* Request Sent Confirmation State */}
          {step === "request" && requestSent && successMsg && (
            <div className="mb-5 p-5 bg-cyan-950/40 border border-cyan-500/30 text-slate-200 text-xs rounded-xl flex flex-col gap-3.5 animate-fadeIn">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center shrink-0">
                  <Inbox className="w-4 h-4 text-cyan-400" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white font-sans">Check Your Email</h3>
                  <p className="text-[11px] text-cyan-300 font-mono">Authorization Link Dispatched</p>
                </div>
              </div>

              <p className="text-xs text-slate-300 leading-relaxed">
                {successMsg}
              </p>

              <div className="text-[11px] text-slate-400 bg-slate-900/60 p-2.5 rounded-lg border border-slate-800 space-y-1 font-mono">
                <p>&bull; The link is single-use and expires in 15 minutes.</p>
                <p>&bull; Be sure to check your spam/junk folder if needed.</p>
              </div>

              {devToken && (
                <div className="pt-2 border-t border-cyan-500/20 text-[11px] font-mono text-slate-300">
                  <span className="text-cyan-300 font-bold block mb-1">Development Reset Token:</span>
                  <div className="bg-slate-900/90 p-2 rounded border border-cyan-500/30 break-all select-all text-cyan-400 text-[10px]">
                    {devToken}
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      setToken(devToken);
                      setStep("reset");
                    }}
                    className="mt-2 text-cyan-400 hover:underline font-sans cursor-pointer font-semibold block text-xs"
                  >
                    Proceed with this token &rarr;
                  </button>
                </div>
              )}

              <div className="pt-2 flex flex-col gap-2">
                <Button
                  type="button"
                  variant="secondary"
                  size="md"
                  onClick={() => {
                    setError("");
                    setSuccessMsg("");
                    setStep("reset");
                  }}
                  className="w-full justify-center text-xs font-mono"
                  icon={Key}
                >
                  Enter Reset Token
                </Button>
                
                <button
                  type="button"
                  onClick={() => {
                    setRequestSent(false);
                    setError("");
                    setSuccessMsg("");
                  }}
                  className="text-xs text-slate-400 hover:text-cyan-400 transition-colors font-mono cursor-pointer py-1 text-center"
                >
                  Need another link? Try again
                </button>
              </div>
            </div>
          )}

          {/* Reset Step Success Message */}
          {step === "reset" && successMsg && (
            <div className="mb-5 p-4 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs rounded-xl flex items-center gap-3 animate-fadeIn">
              <CheckCircle2 className="w-5 h-5 shrink-0 text-emerald-400" />
              <div>
                <p className="font-bold text-sm text-white">Password Reset Successful!</p>
                <p className="text-emerald-300 mt-0.5">{successMsg}</p>
                <p className="text-[10px] text-slate-400 font-mono mt-1">Redirecting to login...</p>
              </div>
            </div>
          )}

          {step === "request" && !requestSent ? (
            <form onSubmit={handleRequestSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1.5 font-mono">
                  Account Email Address
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
                <p className="text-[11px] text-slate-500 mt-1.5 leading-relaxed">
                  Enter your registered email. We will dispatch a secure single-use recovery link.
                </p>
              </div>

              <Button
                type="submit"
                variant="primary"
                size="lg"
                loading={loading}
                className="w-full justify-center mt-2"
                icon={Send}
              >
                Send Reset Link
              </Button>

              <div className="pt-2 text-center">
                <button
                  type="button"
                  onClick={() => {
                    setError("");
                    setSuccessMsg("");
                    setStep("reset");
                  }}
                  className="text-xs text-slate-400 hover:text-cyan-400 transition-colors font-mono cursor-pointer"
                >
                  Already have a reset token? Enter it here &rarr;
                </button>
              </div>
            </form>
          ) : step === "reset" ? (
            <form onSubmit={handleResetSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1.5 font-mono">
                  Reset Authorization Token
                </label>
                <div className="relative">
                  <Key className="w-4 h-4 text-slate-500 absolute left-3.5 top-3.5 pointer-events-none" />
                  <input
                    type="text"
                    value={token}
                    onChange={(e) => setToken(e.target.value)}
                    className="w-full pl-10 pr-4 py-2.5 glass-input rounded-xl text-sm focus:outline-none placeholder-slate-600 font-mono"
                    placeholder="Paste 32-char reset token from email"
                    required
                  />
                </div>
              </div>

              <div>
                <div className="flex justify-between items-center mb-1.5">
                  <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">
                    New Password
                  </label>
                  {newPassword && (
                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${strength.color.split(" ")[1]}`}>
                      {strength.label}
                    </span>
                  )}
                </div>
                <div className="relative">
                  <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-3.5 pointer-events-none" />
                  <input
                    type={showPassword ? "text" : "password"}
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
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
                {newPassword && (
                  <div className="grid grid-cols-3 gap-1 mt-1.5">
                    <div className={`h-1 rounded-full ${strength.score >= 1 ? (strength.score === 1 ? 'bg-rose-500' : strength.score === 2 ? 'bg-amber-500' : 'bg-emerald-500') : 'bg-slate-800'}`} />
                    <div className={`h-1 rounded-full ${strength.score >= 2 ? (strength.score === 2 ? 'bg-amber-500' : 'bg-emerald-500') : 'bg-slate-800'}`} />
                    <div className={`h-1 rounded-full ${strength.score >= 3 ? 'bg-emerald-500' : 'bg-slate-800'}`} />
                  </div>
                )}
              </div>

              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1.5 font-mono">
                  Confirm New Password
                </label>
                <div className="relative">
                  <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-3.5 pointer-events-none" />
                  <input
                    type={showPassword ? "text" : "password"}
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className="w-full pl-10 pr-4 py-2.5 glass-input rounded-xl text-sm focus:outline-none placeholder-slate-600"
                    placeholder="Repeat new password"
                    required
                  />
                </div>
              </div>

              <Button
                type="submit"
                variant="primary"
                size="lg"
                loading={loading}
                className="w-full justify-center mt-2"
                icon={RefreshCw}
              >
                Update Password
              </Button>

              <div className="pt-2 text-center">
                <button
                  type="button"
                  onClick={() => {
                    setError("");
                    setSuccessMsg("");
                    setRequestSent(false);
                    setStep("request");
                  }}
                  className="text-xs text-slate-400 hover:text-cyan-400 transition-colors font-mono cursor-pointer"
                >
                  &larr; Request a new reset link
                </button>
              </div>
            </form>
          ) : null}

          <div className="mt-6 pt-4 border-t border-slate-800/80 text-center">
            <button
              type="button"
              onClick={onCancel}
              className="text-xs text-cyan-400 hover:underline font-semibold cursor-pointer inline-flex items-center gap-1.5"
            >
              <ArrowLeft className="w-3.5 h-3.5" /> Return to Sign In
            </button>
          </div>
        </GlassCard>
      </div>
    </div>
  );
};

export default ForgotPassword;
