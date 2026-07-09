import React, { useState, useEffect } from "react";
import { Login } from "./pages/Login";
import logo from "./assets/logo.jpg";
import { Register } from "./pages/Register";
import { ForgotPassword } from "./pages/ForgotPassword";
import { Dashboard } from "./pages/Dashboard";
import { UploadProject } from "./pages/UploadProject";
import { ScanProgress } from "./pages/ScanProgress";
import { ScanResults } from "./pages/ScanResults";
import { SettingsPage } from "./pages/SettingsPage";
import { AdminPanel } from "./pages/AdminPanel";
import { api } from "./services/api";
import { 
  LayoutDashboard, PlusCircle, Settings, Users, LogOut, User 
} from "lucide-react";

type PageType = "dashboard" | "upload" | "scan-progress" | "scan-results" | "settings" | "admin";

export const App: React.FC = () => {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem("token"));
  const [role, setRole] = useState<string | null>(() => localStorage.getItem("role"));
  const [username, setUsername] = useState<string | null>(() => localStorage.getItem("username"));
  const [activePage, setActivePage] = useState<PageType>("dashboard");
  const [activeScanId, setActiveScanId] = useState<number | null>(null);
  const [authView, setAuthView] = useState<"login" | "register" | "forgot-password">("login");

  const handleLogout = () => {
    localStorage.clear();
    setToken(null);
    setRole(null);
    setUsername(null);
    setAuthView("login");
  };

  useEffect(() => {
    if (token) {
      api.getMe().catch(() => {
        handleLogout();
      });
    }
  }, [token]);

  const handleLoginSuccess = (userRole: string, userName: string) => {
    setToken(localStorage.getItem("token"));
    setRole(userRole);
    setUsername(userName);
    setActivePage("dashboard");
  };

  if (!token) {
    if (authView === "login") {
      return (
        <Login
          onLoginSuccess={handleLoginSuccess}
          onNavigateToRegister={() => setAuthView("register")}
          onNavigateToForgotPassword={() => setAuthView("forgot-password")}
        />
      );
    } else if (authView === "register") {
      return (
        <Register
          onRegisterSuccess={() => setAuthView("login")}
          onNavigateToLogin={() => setAuthView("login")}
        />
      );
    } else {
      return (
        <ForgotPassword
          onCancel={() => setAuthView("login")}
          onResetSuccess={() => setAuthView("login")}
        />
      );
    }
  }

  const navigateToScanProgress = (scanId: number) => {
    setActiveScanId(scanId);
    setActivePage("scan-progress");
  };

  const navigateToScanResults = (scanId: number) => {
    setActiveScanId(scanId);
    setActivePage("scan-results");
  };

  return (
    <div className="flex min-h-screen bg-[#040712] text-slate-100 font-sans cyber-grid relative">
      
      {/* Sidebar Layout */}
      <aside className="w-64 bg-slate-950 border-r border-slate-900 flex flex-col justify-between shrink-0 z-10">
        <div>
          {/* Logo badge */}
          <div className="h-16 flex items-center gap-2.5 px-6 border-b border-slate-900">
            <img src={logo} alt="AI Bug Hunter Logo" className="w-8 h-8 rounded object-cover shadow-lg shadow-cyan-500/10 border border-slate-800" />
            <span className="text-base font-black tracking-wider bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent">
              AI BUG HUNTER
            </span>
          </div>
 
          {/* Navigation links */}
          <nav className="p-4 space-y-1">
            <button
              onClick={() => setActivePage("dashboard")}
              className={`w-full flex items-center gap-3 px-4 py-2.5 rounded-lg text-xs font-bold transition-all text-left cursor-pointer ${
                activePage === "dashboard"
                  ? "bg-slate-900 border-l-2 border-cyan-500 text-cyan-400"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/30"
              }`}
            >
              <LayoutDashboard className="w-4 h-4" />
              <span>Security Dashboard</span>
            </button>
 
            <button
              onClick={() => setActivePage("upload")}
              className={`w-full flex items-center gap-3 px-4 py-2.5 rounded-lg text-xs font-bold transition-all text-left cursor-pointer ${
                activePage === "upload"
                  ? "bg-slate-900 border-l-2 border-cyan-500 text-cyan-400"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/30"
              }`}
            >
              <PlusCircle className="w-4 h-4" />
              <span>New Analysis Scan</span>
            </button>
 
            <button
              onClick={() => setActivePage("settings")}
              className={`w-full flex items-center gap-3 px-4 py-2.5 rounded-lg text-xs font-bold transition-all text-left cursor-pointer ${
                activePage === "settings"
                  ? "bg-slate-900 border-l-2 border-cyan-500 text-cyan-400"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/30"
              }`}
            >
              <Settings className="w-4 h-4" />
              <span>System Settings</span>
            </button>
 
            {role === "admin" && (
              <button
                onClick={() => setActivePage("admin")}
                className={`w-full flex items-center gap-3 px-4 py-2.5 rounded-lg text-xs font-bold transition-all text-left cursor-pointer ${
                  activePage === "admin"
                    ? "bg-slate-900 border-l-2 border-cyan-500 text-cyan-400"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/30"
                }`}
              >
                <Users className="w-4 h-4" />
                <span>Admin Administration</span>
              </button>
            )}
          </nav>
        </div>
 
        {/* User Card & Log Out */}
        <div className="p-4 border-t border-slate-900 space-y-4">
          <div className="flex items-center gap-2.5 px-2">
            <div className="w-8 h-8 rounded-full bg-slate-900 flex items-center justify-center border border-slate-800 text-slate-400">
              <User className="w-4 h-4" />
            </div>
            <div className="truncate">
              <span className="text-xs font-bold text-slate-200 block truncate">{username}</span>
              <span className="text-[10px] text-slate-500 block capitalize font-medium">{role}</span>
            </div>
          </div>
          <button
            onClick={handleLogout}
            className="w-full flex items-center gap-3 px-4 py-2 text-xs font-bold text-slate-500 hover:text-rose-400 rounded-lg hover:bg-rose-500/5 cursor-pointer transition-all text-left"
          >
            <LogOut className="w-4 h-4" />
            <span>Log Out Account</span>
          </button>
        </div>
      </aside>
 
      {/* Main Content Layout */}
      <div className="flex-1 flex flex-col min-h-screen z-10">
        {/* Top Header */}
        <header className="h-16 border-b border-slate-900 flex items-center justify-end px-8 shrink-0 bg-slate-950/40 backdrop-blur">
          <div className="flex items-center gap-1.5 text-xs text-slate-400 font-bold bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-full shadow-inner">
            <div className="w-2 h-2 rounded-full bg-emerald-500 pulsing-dot"></div>
            <span>Security Engine Active</span>
          </div>
        </header>
 
        {/* Page Content viewport */}
        <main className="flex-1 p-8 overflow-y-auto">
          {activePage === "dashboard" && (
            <Dashboard
              onNavigateToUpload={() => setActivePage("upload")}
              onNavigateToScanProgress={navigateToScanProgress}
              onNavigateToScanResults={navigateToScanResults}
            />
          )}

          {activePage === "upload" && (
            <UploadProject
              onUploadSuccess={navigateToScanProgress}
              onCancel={() => setActivePage("dashboard")}
            />
          )}

          {activePage === "scan-progress" && activeScanId !== null && (
            <ScanProgress
              scanId={activeScanId}
              onScanComplete={navigateToScanResults}
              onCancel={() => setActivePage("dashboard")}
            />
          )}

          {activePage === "scan-results" && activeScanId !== null && (
            <ScanResults
              scanId={activeScanId}
              onNavigateToDashboard={() => setActivePage("dashboard")}
            />
          )}

          {activePage === "settings" && <SettingsPage />}

          {activePage === "admin" && (
            role === "admin" ? (
              <AdminPanel />
            ) : (
              <div className="flex flex-col items-center justify-center min-h-[50vh] space-y-4">
                <div className="p-6 glass-panel rounded-xl border border-rose-500/20 bg-rose-500/5 text-center max-w-md animate-fade-in">
                  <span className="text-3xl">🚫</span>
                  <h2 className="text-lg font-black text-rose-400 mt-2">Access Denied</h2>
                  <p className="text-xs text-slate-400 mt-1">
                    You do not have administrative privileges to access the User Management panel.
                  </p>
                  <button
                    onClick={() => setActivePage("dashboard")}
                    className="mt-4 px-4 py-2 bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-350 hover:text-slate-100 rounded-lg text-xs font-bold transition-all cursor-pointer"
                  >
                    Return to Dashboard
                  </button>
                </div>
              </div>
            )
          )}
        </main>
      </div>
    </div>
  );
};
export default App;
