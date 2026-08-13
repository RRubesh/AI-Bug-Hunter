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
import { CyberBackground } from "./components/CyberBackground";
import { api } from "./services/api";
import { 
  LayoutDashboard, PlusCircle, Settings, Users, LogOut, User,
  ChevronLeft, ChevronRight, Search, Bell, Shield, Menu, X, MessageSquare,
  Sparkles, CheckCircle2, ShieldCheck, Activity
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
  const [searchQuery, setSearchQuery] = useState("");

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

  // Global Keyboard Shortcut: CMD+K / CTRL+K for Command Search
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setSearchOpen((prev) => !prev);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

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
    ...(role === "admin" ? [{ id: "admin", label: "User Administration", icon: Users }] : []),
  ];

  return (
    <div className="flex min-h-screen bg-[#030712] text-slate-100 font-sans cyber-grid relative overflow-x-hidden">
      
      {/* Interactive Cyber Particle Background Canvas */}
      <CyberBackground />

      {/* Ambient background glow accents */}
      <div className="fixed top-0 left-1/4 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none -z-10" />
      <div className="fixed bottom-0 right-1/4 w-96 h-96 bg-violet-500/5 rounded-full blur-3xl pointer-events-none -z-10" />

      {/* Desktop Sidebar Navigation */}
      <aside
        className={`hidden md:flex flex-col justify-between shrink-0 glass-panel border-r border-slate-800/80 z-30 transition-all duration-300 ${
          sidebarCollapsed ? "w-20" : "w-64"
        }`}
      >
        <div>
          {/* Brand Logo Header */}
          <div className="h-16 flex items-center justify-between px-4 border-b border-slate-800/80">
            <div className="flex items-center gap-3 overflow-hidden">
              <div className="relative shrink-0">
                <img
                  src={logo}
                  alt="AI Bug Hunter Logo"
                  className="h-10 w-auto max-w-[140px] rounded-xl object-contain shadow-lg shadow-cyan-500/20 border border-slate-700/60 shrink-0"
                />
                <div className="absolute -bottom-0.5 -right-0.5 w-3 h-3 bg-emerald-500 rounded-full border-2 border-slate-950 status-dot-active" />
              </div>
              {!sidebarCollapsed && (
                <div className="truncate">
                  <span className="text-sm font-black tracking-wider text-gradient block leading-none">
                    AI BUG HUNTER
                  </span>
                  <span className="text-[10px] text-cyan-400/80 font-mono tracking-widest uppercase mt-0.5 block">
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
                      ? "bg-gradient-to-r from-cyan-500/15 via-blue-500/10 to-violet-500/15 text-cyan-300 border border-cyan-500/30 shadow-[0_0_15px_rgba(6,182,212,0.12)]"
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

        {/* User Footer Profile & Logout */}
        <div className="p-3 border-t border-slate-800/80 space-y-2">
          {!sidebarCollapsed && (
            <div className="flex items-center gap-3 p-2.5 rounded-xl bg-slate-900/60 border border-slate-800/60">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500/20 to-violet-500/20 flex items-center justify-center border border-cyan-500/30 text-cyan-400 font-bold shrink-0">
                <User className="w-4 h-4" />
              </div>
              <div className="truncate">
                <span className="text-xs font-bold text-slate-200 block truncate">{username}</span>
                <span className="text-[10px] text-cyan-400 block capitalize font-mono font-medium">
                  {role || "User"} Role
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

      {/* Main Viewport Container */}
      <div className="flex-1 flex flex-col min-h-screen min-w-0 z-10">
        
        {/* Top Header Bar */}
        <header className="h-16 border-b border-slate-800/80 flex items-center justify-between px-4 md:px-8 shrink-0 bg-slate-950/70 backdrop-blur-md sticky top-0 z-20">
          
          {/* Mobile Header Left & Breadcrumb */}
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="md:hidden min-h-[44px] min-w-[44px] flex items-center justify-center rounded-xl text-slate-300 hover:text-white hover:bg-slate-800/80 border border-slate-800 transition-colors"
              aria-label="Toggle mobile menu"
            >
              <Menu className="w-5 h-5" />
            </button>

            {/* Mobile Brand Title */}
            <div className="flex items-center gap-2 md:hidden">
              <img src={logo} alt="Logo" className="h-7 w-auto rounded-md object-contain border border-slate-800" />
              <span className="text-xs font-black text-gradient uppercase tracking-wider">AI BUG HUNTER</span>
            </div>

            {/* Desktop Breadcrumb */}
            <div className="hidden md:flex items-center gap-2 text-xs text-slate-400 font-mono">
              <Shield className="w-4 h-4 text-cyan-400" />
              <span className="text-slate-200 font-bold">SAST Security Platform</span>
              <span className="text-slate-600">/</span>
              <span className="capitalize text-cyan-400 font-bold">{activePage.replace("-", " ")}</span>
            </div>
          </div>

          {/* Right Header Controls */}
          <div className="flex items-center gap-2 md:gap-3">
            
            {/* Command Search Bar Trigger */}
            <button
              onClick={() => setSearchOpen(!searchOpen)}
              className="flex items-center gap-2 px-3 py-2 md:py-1.5 bg-slate-900/80 border border-slate-800 rounded-xl text-xs text-slate-400 hover:text-slate-200 hover:border-slate-700 transition-all cursor-pointer min-h-[40px] md:min-h-0"
            >
              <Search className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
              <span className="hidden sm:inline">Search platform...</span>
              <kbd className="hidden sm:inline-block px-1.5 py-0.5 text-[9px] bg-slate-800 border border-slate-700 rounded text-slate-400 font-mono">
                ⌘K
              </kbd>
            </button>

            {/* Security Engine Status Badge */}
            <div className="flex items-center gap-2 px-3 py-1.5 bg-emerald-500/10 border border-emerald-500/30 rounded-full text-xs font-mono text-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.12)]">
              <div className="w-2 h-2 rounded-full bg-emerald-400 status-dot-active" />
              <span className="font-bold hidden sm:inline">Engine Active</span>
              <span className="font-bold sm:hidden text-[10px]">Active</span>
            </div>

            {/* Notifications Button */}
            <button
              onClick={() => setNotificationsOpen(!notificationsOpen)}
              className="relative min-h-[40px] min-w-[40px] flex items-center justify-center rounded-xl text-slate-400 hover:text-slate-100 hover:bg-slate-800/60 border border-slate-800/60 transition-colors cursor-pointer"
              aria-label="Notifications"
            >
              <Bell className="w-4 h-4" />
              <span className="absolute top-2 right-2 w-2 h-2 bg-cyan-400 rounded-full animate-ping" />
              <span className="absolute top-2 right-2 w-2 h-2 bg-cyan-400 rounded-full" />
            </button>
          </div>
        </header>

        {/* Mobile Slide-Out Drawer */}
        {mobileMenuOpen && (
          <div className="md:hidden fixed inset-0 z-50 bg-slate-950/90 backdrop-blur-xl flex flex-col p-6 animate-fade-in">
            <div className="flex items-center justify-between pb-4 border-b border-slate-800">
              <div className="flex items-center gap-3">
                <img src={logo} alt="Logo" className="h-9 w-auto object-contain rounded-lg border border-slate-800" />
                <div>
                  <span className="font-black text-gradient block text-sm">AI BUG HUNTER</span>
                  <span className="text-[10px] text-cyan-400 font-mono">SOC SECURITY SUITE</span>
                </div>
              </div>
              <button
                onClick={() => setMobileMenuOpen(false)}
                className="min-h-[44px] min-w-[44px] flex items-center justify-center rounded-xl text-slate-400 hover:text-white hover:bg-slate-800/60"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            <nav className="mt-6 space-y-2 flex-1">
              {navItems.map((item) => {
                const Icon = item.icon;
                const isActive = activePage === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => {
                      setActivePage(item.id as PageType);
                      setMobileMenuOpen(false);
                    }}
                    className={`w-full flex items-center gap-3 px-4 py-3.5 rounded-xl text-sm font-bold min-h-[48px] transition-all ${
                      isActive
                        ? "bg-gradient-to-r from-cyan-500/20 via-blue-500/15 to-violet-500/20 text-cyan-300 border border-cyan-500/40 shadow-lg shadow-cyan-500/10"
                        : "text-slate-300 hover:bg-slate-900/60 border border-transparent"
                    }`}
                  >
                    <Icon className={`w-5 h-5 ${isActive ? "text-cyan-400" : "text-slate-400"}`} />
                    <span>{item.label}</span>
                  </button>
                );
              })}
            </nav>

            <div className="pt-4 border-t border-slate-800 space-y-3">
              <div className="flex items-center gap-3 p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="w-8 h-8 rounded-lg bg-cyan-500/20 flex items-center justify-center border border-cyan-500/30 text-cyan-400 font-bold">
                  <User className="w-4 h-4" />
                </div>
                <div className="truncate">
                  <span className="text-xs font-bold text-slate-200 block truncate">{username}</span>
                  <span className="text-[10px] text-cyan-400 block font-mono capitalize">{role || "User"} Role</span>
                </div>
              </div>

              <button
                onClick={handleLogout}
                className="w-full flex items-center justify-center gap-2 py-3.5 bg-rose-500/10 text-rose-400 rounded-xl font-bold border border-rose-500/20 min-h-[48px]"
              >
                <LogOut className="w-4 h-4" /> Log Out Account
              </button>
            </div>
          </div>
        )}

        {/* Command Search Modal */}
        {searchOpen && (
          <div
            className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-md flex items-start justify-center pt-16 p-4"
            onClick={() => setSearchOpen(false)}
          >
            <div
              className="w-full max-w-xl glass-panel rounded-2xl p-4 border-slate-700/80 shadow-2xl relative space-y-4"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex items-center gap-3 px-3.5 py-2.5 bg-slate-900/90 rounded-xl border border-slate-800">
                <Search className="w-5 h-5 text-cyan-400 shrink-0" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search scans, rules, vulnerabilities, CVEs..."
                  className="w-full bg-transparent text-sm text-slate-100 focus:outline-none"
                  autoFocus
                />
                <button
                  onClick={() => setSearchOpen(false)}
                  className="text-xs text-slate-400 hover:text-slate-200 uppercase font-mono px-2 py-1 bg-slate-800 rounded border border-slate-700"
                >
                  ESC
                </button>
              </div>

              <div className="space-y-2 text-xs">
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500 font-bold block px-1">
                  Quick Navigation Shortcuts
                </span>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    onClick={() => {
                      setActivePage("upload");
                      setSearchOpen(false);
                    }}
                    className="p-2.5 bg-slate-900/60 hover:bg-slate-800/80 rounded-xl border border-slate-800 text-left flex items-center gap-2 text-slate-300"
                  >
                    <PlusCircle className="w-4 h-4 text-cyan-400" /> Start New Scan
                  </button>
                  <button
                    onClick={() => {
                      setActivePage("ai-chat");
                      setSearchOpen(false);
                    }}
                    className="p-2.5 bg-slate-900/60 hover:bg-slate-800/80 rounded-xl border border-slate-800 text-left flex items-center gap-2 text-slate-300"
                  >
                    <MessageSquare className="w-4 h-4 text-violet-400" /> Ask AI Security Assistant
                  </button>
                  <button
                    onClick={() => {
                      setActivePage("settings");
                      setSearchOpen(false);
                    }}
                    className="p-2.5 bg-slate-900/60 hover:bg-slate-800/80 rounded-xl border border-slate-800 text-left flex items-center gap-2 text-slate-300"
                  >
                    <Settings className="w-4 h-4 text-blue-400" /> System Settings & LLM
                  </button>
                  <button
                    onClick={() => {
                      setActivePage("dashboard");
                      setSearchOpen(false);
                    }}
                    className="p-2.5 bg-slate-900/60 hover:bg-slate-800/80 rounded-xl border border-slate-800 text-left flex items-center gap-2 text-slate-300"
                  >
                    <LayoutDashboard className="w-4 h-4 text-emerald-400" /> Executive Dashboard
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* System Notifications Drawer */}
        {notificationsOpen && (
          <div className="absolute top-16 right-4 z-40 w-80 glass-panel rounded-2xl p-4 border-slate-700/80 shadow-2xl animate-fade-in space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200 font-mono">
                System Alerts
              </h4>
              <button onClick={() => setNotificationsOpen(false)} className="text-slate-400 hover:text-slate-200">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="space-y-2 text-xs">
              <div className="p-2.5 bg-slate-900/60 rounded-xl border border-slate-800 flex items-start gap-2.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <span className="font-bold text-emerald-400 block">Scanners Ready</span>
                  <span className="text-slate-400 text-[11px]">Gitleaks, Bandit & Semgrep engines online.</span>
                </div>
              </div>
              <div className="p-2.5 bg-slate-900/60 rounded-xl border border-slate-800 flex items-start gap-2.5">
                <Sparkles className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                <div>
                  <span className="font-bold text-cyan-400 block">AI Remediator Active</span>
                  <span className="text-slate-400 text-[11px]">Local LLM model connected for instant fixes.</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Viewport Main Content */}
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
