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
import { AIChatPage } from "./pages/AIChatPage";
import { api } from "./services/api";
import { 
  LayoutDashboard, PlusCircle, Settings, Users, LogOut, User,
  ChevronLeft, ChevronRight, Search, Bell, Shield, Menu, X, MessageSquare
} from "lucide-react";

type PageType = "dashboard" | "upload" | "scan-progress" | "scan-results" | "settings" | "admin" | "ai-chat";

export const App: React.FC = () => {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem("token"));


  const [role, setRole] = useState<string | null>(() => localStorage.getItem("role"));
  const [username, setUsername] = useState<string | null>(() => localStorage.getItem("username"));
  const [activePage, setActivePage] = useState<PageType>("dashboard");
  const [activeScanId, setActiveScanId] = useState<number | null>(null);
  const [authView, setAuthView] = useState<"login" | "register" | "forgot-password">("login");
  
  // Shell UI states
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);

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

  const navItems = [
    { id: "dashboard", label: "Security Dashboard", icon: LayoutDashboard },
    { id: "upload", label: "New Analysis Scan", icon: PlusCircle },
    { id: "ai-chat", label: "AI Security Chat", icon: MessageSquare },
    { id: "settings", label: "System Settings", icon: Settings },
    ...(role === "admin" ? [{ id: "admin", label: "Admin Administration", icon: Users }] : []),
  ];

  return (
    <div className="flex min-h-screen bg-[#030712] text-slate-100 font-sans cyber-grid relative overflow-x-hidden">
      
      {/* Background radial gradient highlights */}
      <div className="fixed top-0 left-1/4 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none -z-10" />
      <div className="fixed bottom-0 right-1/4 w-96 h-96 bg-violet-500/5 rounded-full blur-3xl pointer-events-none -z-10" />

      {/* Sidebar Navigation for Desktop */}
      <aside
        className={`hidden md:flex flex-col justify-between shrink-0 glass-panel border-r border-slate-800/80 z-30 transition-all duration-300 ${
          sidebarCollapsed ? "w-20" : "w-64"
        }`}
      >
        <div>
          {/* Logo Badge */}
          <div className="h-16 flex items-center justify-between px-4 border-b border-slate-800/80">
            <div className="flex items-center gap-3 overflow-hidden">
              <div className="relative">
                <img
                  src={logo}
                  alt="AI Bug Hunter Logo"
                  className="h-10 w-auto max-w-[140px] rounded-lg object-contain shadow-lg shadow-cyan-500/20 border border-slate-800/80 shrink-0"
                />


                <div className="absolute -bottom-0.5 -right-0.5 w-3 h-3 bg-emerald-500 rounded-full border-2 border-slate-950 status-dot-active" />
              </div>
              {!sidebarCollapsed && (
                <div className="truncate">
                  <span className="text-sm font-black tracking-wider text-gradient block leading-none">
                    AI BUG HUNTER
                  </span>
                  <span className="text-[10px] text-slate-400 font-mono tracking-widest uppercase">
                    ENTERPRISE SAST
                  </span>
                </div>
              )}
            </div>

            <button
              onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800/60 transition-colors cursor-pointer"
              title={sidebarCollapsed ? "Expand Sidebar" : "Collapse Sidebar"}
            >
              {sidebarCollapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
            </button>
          </div>

          {/* Navigation Links */}
          <nav className="p-3 space-y-1.5">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activePage === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActivePage(item.id as PageType)}
                  title={sidebarCollapsed ? item.label : undefined}
                  className={`w-full flex items-center gap-3 px-3.5 py-3 rounded-xl text-xs font-bold transition-all cursor-pointer relative group ${
                    isActive
                      ? "bg-gradient-to-r from-cyan-500/15 via-blue-500/10 to-violet-500/15 text-cyan-300 border border-cyan-500/30 shadow-[0_0_15px_rgba(6,182,212,0.1)]"
                      : "text-slate-400 hover:text-slate-100 hover:bg-slate-800/40 border border-transparent"
                  }`}
                >
                  {isActive && (
                    <div className="absolute left-0 top-2 bottom-2 w-1 bg-gradient-to-b from-cyan-400 to-violet-500 rounded-r-full" />
                  )}
                  <Icon className={`w-4 h-4 shrink-0 transition-transform group-hover:scale-110 ${isActive ? "text-cyan-400" : "text-slate-400"}`} />
                  {!sidebarCollapsed && <span className="truncate">{item.label}</span>}
                </button>
              );
            })}
          </nav>
        </div>

        {/* User Card & Log Out */}
        <div className="p-3 border-t border-slate-800/80 space-y-2">
          {!sidebarCollapsed && (
            <div className="flex items-center gap-3 p-2 rounded-xl bg-slate-900/60 border border-slate-800/60">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500/20 to-violet-500/20 flex items-center justify-center border border-cyan-500/30 text-cyan-400 font-bold shrink-0">
                <User className="w-4 h-4" />
              </div>
              <div className="truncate">
                <span className="text-xs font-bold text-slate-200 block truncate">{username}</span>
                <span className="text-[10px] text-cyan-400 block capitalize font-mono font-medium">
                  {role} Role
                </span>
              </div>
            </div>
          )}

          <button
            onClick={handleLogout}
            title={sidebarCollapsed ? "Log Out Account" : undefined}
            className={`w-full flex items-center gap-3 px-3.5 py-2.5 text-xs font-bold text-slate-400 hover:text-rose-400 rounded-xl hover:bg-rose-500/10 border border-transparent hover:border-rose-500/20 cursor-pointer transition-all ${
              sidebarCollapsed ? "justify-center" : ""
            }`}
          >
            <LogOut className="w-4 h-4 shrink-0" />
            {!sidebarCollapsed && <span>Log Out Account</span>}
          </button>
        </div>
      </aside>

      {/* Main Content Layout */}
      <div className="flex-1 flex flex-col min-h-screen min-w-0 z-10">
        {/* Top Header Bar */}
        <header className="h-16 border-b border-slate-800/80 flex items-center justify-between px-4 md:px-8 shrink-0 bg-slate-950/60 backdrop-blur-md sticky top-0 z-20">
          
          {/* Left Mobile Menu Toggle & Title indicator */}
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="md:hidden p-2 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800/60"
            >
              <Menu className="w-5 h-5" />
            </button>

            <div className="hidden sm:flex items-center gap-2 text-xs text-slate-400 font-mono">
              <Shield className="w-4 h-4 text-cyan-400" />
              <span className="text-slate-200 font-bold">SAST Security Suite</span>
              <span className="text-slate-600">/</span>
              <span className="capitalize text-cyan-400 font-bold">{activePage.replace("-", " ")}</span>
            </div>
          </div>

          {/* Right Controls Header */}
          <div className="flex items-center gap-3">
            {/* Search/Command Trigger */}
            <button
              onClick={() => setSearchOpen(!searchOpen)}
              className="hidden sm:flex items-center gap-2 px-3 py-1.5 bg-slate-900/80 border border-slate-800 rounded-xl text-xs text-slate-400 hover:text-slate-200 hover:border-slate-700 transition-all cursor-pointer"
            >
              <Search className="w-3.5 h-3.5 text-cyan-400" />
              <span>Search platform...</span>
              <kbd className="px-1.5 py-0.5 text-[9px] bg-slate-800 border border-slate-700 rounded text-slate-400 font-mono">
                ⌘K
              </kbd>
            </button>

            {/* Security Engine Status Badge */}
            <div className="flex items-center gap-2 px-3 py-1.5 bg-emerald-500/10 border border-emerald-500/30 rounded-full text-xs font-mono text-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.1)]">
              <div className="w-2 h-2 rounded-full bg-emerald-400 status-dot-active" />
              <span className="font-bold hidden md:inline">Security Engine Active</span>
              <span className="font-bold md:hidden">Active</span>
            </div>

            {/* Notifications Button */}
            <button
              onClick={() => setNotificationsOpen(!notificationsOpen)}
              className="relative p-2 rounded-xl text-slate-400 hover:text-slate-100 hover:bg-slate-800/60 border border-slate-800/60 transition-colors cursor-pointer"
            >
              <Bell className="w-4 h-4" />
              <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-cyan-400 rounded-full animate-ping" />
              <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-cyan-400 rounded-full" />
            </button>
          </div>
        </header>

        {/* Mobile Navigation Drawer */}
        {mobileMenuOpen && (
          <div className="md:hidden fixed inset-0 z-40 bg-slate-950/80 backdrop-blur-md flex flex-col p-6 animate-fade-in">
            <div className="flex items-center justify-between pb-4 border-b border-slate-800">
              <div className="flex items-center gap-3">
                <img src={logo} alt="Logo" className="h-9 w-auto object-contain rounded-lg" />


                <span className="font-bold text-gradient">AI BUG HUNTER</span>
              </div>
              <button onClick={() => setMobileMenuOpen(false)} className="p-2 text-slate-400">
                <X className="w-6 h-6" />
              </button>
            </div>
            <nav className="mt-6 space-y-2 flex-1">
              {navItems.map((item) => {
                const Icon = item.icon;
                return (
                  <button
                    key={item.id}
                    onClick={() => {
                      setActivePage(item.id as PageType);
                      setMobileMenuOpen(false);
                    }}
                    className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-bold ${
                      activePage === item.id ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/30" : "text-slate-400"
                    }`}
                  >
                    <Icon className="w-5 h-5" />
                    <span>{item.label}</span>
                  </button>
                );
              })}
            </nav>
            <button
              onClick={handleLogout}
              className="w-full flex items-center justify-center gap-2 py-3 bg-rose-500/10 text-rose-400 rounded-xl font-bold border border-rose-500/20"
            >
              <LogOut className="w-4 h-4" /> Log Out
            </button>
          </div>
        )}

        {/* Search Modal Triggered */}
        {searchOpen && (
          <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-md flex items-start justify-center pt-20 p-4">
            <div className="w-full max-w-xl glass-panel rounded-2xl p-4 border-slate-700 shadow-2xl relative">
              <div className="flex items-center gap-3 px-3 py-2 bg-slate-900/80 rounded-xl border border-slate-800">
                <Search className="w-5 h-5 text-cyan-400" />
                <input
                  type="text"
                  placeholder="Search scans, rules, vulnerabilities..."
                  className="w-full bg-transparent text-sm text-slate-100 focus:outline-none"
                  autoFocus
                />
                <button onClick={() => setSearchOpen(false)} className="text-xs text-slate-500 uppercase font-mono">
                  ESC
                </button>
              </div>
              <div className="mt-4 p-4 text-center text-xs text-slate-500 font-mono">
                Press ESC or click outside to dismiss command search
              </div>
            </div>
          </div>
        )}

        {/* Notifications Drawer */}
        {notificationsOpen && (
          <div className="absolute top-16 right-4 z-40 w-80 glass-panel rounded-2xl p-4 border-slate-700/60 shadow-2xl animate-fade-in">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200">System Notifications</h4>
              <button onClick={() => setNotificationsOpen(false)} className="text-slate-400 hover:text-slate-200 text-xs">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="mt-3 space-y-2 text-xs">
              <div className="p-2.5 bg-slate-900/60 rounded-xl border border-slate-800">
                <span className="font-bold text-cyan-400 block">Security Scanners Online</span>
                <span className="text-slate-400 text-[11px]">Gitleaks, Bandit & Semgrep engines ready.</span>
              </div>
              <div className="p-2.5 bg-slate-900/60 rounded-xl border border-slate-800">
                <span className="font-bold text-emerald-400 block">Ollama AI Active</span>
                <span className="text-slate-400 text-[11px]">Local LLM model connected for remediation.</span>
              </div>
            </div>
          </div>
        )}

        {/* Main Content Viewport */}
        <main className="flex-1 p-4 md:p-8 overflow-y-auto">
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
              onNavigateToChat={() => setActivePage("ai-chat")}
            />
          )}

          {activePage === "ai-chat" && <AIChatPage initialScanId={activeScanId} />}

          {activePage === "settings" && <SettingsPage />}

          {activePage === "admin" && (
            role === "admin" ? (
              <AdminPanel />
            ) : (
              <div className="flex flex-col items-center justify-center min-h-[50vh] space-y-4">
                <div className="p-6 glass-panel rounded-2xl border border-rose-500/20 bg-rose-500/5 text-center max-w-md animate-fade-in">
                  <span className="text-3xl block">🚫</span>
                  <h2 className="text-lg font-black text-rose-400 mt-2">Access Denied</h2>
                  <p className="text-xs text-slate-400 mt-1">
                    You do not have administrative privileges to access the User Management panel.
                  </p>
                  <button
                    onClick={() => setActivePage("dashboard")}
                    className="mt-4 px-4 py-2 bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-300 rounded-xl text-xs font-bold transition-all cursor-pointer"
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
