import React, { useEffect, useState } from "react";
import { api } from "../services/api";
import type { Scan, Vulnerability, ChatMessage } from "../services/api";
import { 
  ShieldAlert, ShieldX, AlertTriangle, Info, Terminal, Download, 
  MessageSquare, Sparkles, Send, FileCode
} from "lucide-react";

interface ScanResultsProps {
  scanId: number;
  onNavigateToDashboard: () => void;
}

export const ScanResults: React.FC<ScanResultsProps> = ({ scanId, onNavigateToDashboard }) => {
  const [scan, setScan] = useState<Scan | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [fileContent, setFileContent] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [loadingFile, setLoadingFile] = useState(false);
  const [enriching, setEnriching] = useState(false);
  const [error, setError] = useState("");

  const userRole = localStorage.getItem("role");
  const isPaidOrAdmin = userRole === "admin" || userRole === "paid";

  // Chat integration inside sidebar
  const [chatOpen, setChatOpen] = useState(false);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [chatInput, setChatInput] = useState("");
  const [sendingChat, setSendingChat] = useState(false);

  useEffect(() => {
    let active = true;
    const fetchResults = async () => {
      try {
        const scanData = await api.getScan(scanId);
        if (!active) return;
        setScan(scanData);
        const vulnsData = await api.getVulnerabilities(scanId);
        if (!active) return;
        setVulnerabilities(vulnsData);
        if (vulnsData.length > 0) {
          setSelectedVuln(vulnsData[0]);
        }
      } catch (err: unknown) {
        if (!active) return;
        const errMsg = err instanceof Error ? err.message : "Failed to fetch scan results.";
        setError(errMsg);
      } finally {
        if (active) {
          setLoading(false);
        }
      }
    };

    (async () => {
      await Promise.resolve();
      if (active) {
        fetchResults();
      }
    })();

    return () => {
      active = false;
    };
  }, [scanId]);

  // Fetch file content whenever selected vulnerability changes
  useEffect(() => {
    if (!selectedVuln || !scan) return;
    
    const fetchCode = async () => {
      setLoadingFile(true);
      try {
        const content = await api.getFileContent(scan.project_id, selectedVuln.file_path);
        setFileContent(content);
      } catch {
        // Fallback to empty content or snippet only
        setFileContent("");
      } finally {
        setLoadingFile(false);
      }
    };
    
    fetchCode();
  }, [selectedVuln, scan]);

  // Load chat messages when chat sidebar opens
  useEffect(() => {
    if (chatOpen && scan) {
      const fetchChat = async () => {
        try {
          const history = await api.getChatHistory(scan.id);
          setChatMessages(history);
        } catch (err) {
          console.error(err);
        }
      };
      fetchChat();
    }
  }, [chatOpen, scan]);

  const handleEnrich = async () => {
    if (!selectedVuln) return;
    setEnriching(true);
    try {
      const updatedVuln = await api.enrichVulnerability(selectedVuln.id);
      setSelectedVuln(updatedVuln);
      // Update in main list
      setVulnerabilities(vulnerabilities.map((v) => (v.id === updatedVuln.id ? updatedVuln : v)));
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      alert("Failed to enrich: " + errMsg);
    } finally {
      setEnriching(false);
    }
  };

  const handleSendChat = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!chatInput.trim() || !scan || sendingChat) return;

    const userText = chatInput;
    setChatInput("");
    setSendingChat(true);

    // Optimistically add user message to list
    const tempUserMsg: ChatMessage = {
      id: Date.now(),
      scan_id: scan.id,
      user_id: 0,
      message: userText,
      is_ai: false,
      created_at: new Date().toISOString(),
    };
    setChatMessages((prev) => [...prev, tempUserMsg]);

    try {
      const aiReply = await api.sendChatMessage(scan.id, userText, selectedVuln?.id);
      setChatMessages((prev) => [...prev.filter((m) => m.id !== tempUserMsg.id), tempUserMsg, aiReply]);
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      alert("Chat failed: " + errMsg);
    } finally {
      setSendingChat(false);
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity.toUpperCase()) {
      case "CRITICAL":
        return <ShieldX className="w-4 h-4 text-rose-500" />;
      case "HIGH":
        return <ShieldAlert className="w-4 h-4 text-orange-500" />;
      case "MEDIUM":
        return <AlertTriangle className="w-4 h-4 text-amber-500" />;
      default:
        return <Info className="w-4 h-4 text-blue-500" />;
    }
  };

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity.toUpperCase()) {
      case "CRITICAL":
        return "bg-rose-500/10 text-rose-400 border border-rose-500/25";
      case "HIGH":
        return "bg-orange-500/10 text-orange-400 border border-orange-500/25";
      case "MEDIUM":
        return "bg-amber-500/10 text-amber-400 border border-amber-500/25";
      default:
        return "bg-blue-500/10 text-blue-400 border border-blue-500/25";
    }
  };

  const downloadReportFile = async (format: string) => {
    try {
      const token = localStorage.getItem("token");
      const headers: HeadersInit = {};
      if (token) {
        headers["Authorization"] = `Bearer ${token}`;
      }
      const response = await fetch(`/api/scans/${scanId}/report/${format}`, {
        headers,
      });
      if (!response.ok) {
        throw new Error(`Failed to download report (${response.status})`);
      }
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      
      const extension = format;
      a.download = `AI_Bug_Hunter_Report_${scan?.project.name || "scan"}_${scanId}.${extension}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      alert("Error downloading report: " + (err instanceof Error ? err.message : String(err)));
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="w-10 h-10 border-4 border-slate-800 border-t-rose-500 rounded-full animate-spin"></div>
      </div>
    );
  }

  // Group vulnerabilities by file path for listing
  const filesMap: { [path: string]: Vulnerability[] } = {};
  vulnerabilities.forEach((v) => {
    if (!filesMap[v.file_path]) {
      filesMap[v.file_path] = [];
    }
    filesMap[v.file_path].push(v);
  });

  return (
    <div className="space-y-6 relative min-h-[85vh] animate-fade-in">
      {error && (
        <div className="p-3 bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs rounded-lg">
          {error}
        </div>
      )}
      {/* Top Results Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-black text-slate-100">{scan?.project.name}</h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-900 text-slate-400 border border-slate-800 uppercase">
              {scan?.project.language_detected}
            </span>
          </div>
          <p className="text-[10px] text-slate-500 mt-1 font-mono">
            Scan Session ID: #{scanId} | Completed: {scan?.finished_at ? new Date(scan.finished_at).toLocaleString() : "Unknown"}
          </p>
        </div>

        {/* Report downloads */}
        <div className="flex gap-2">
          <button
            onClick={() => downloadReportFile("pdf")}
            className="px-3 py-1.5 bg-slate-950 border border-slate-800 hover:bg-slate-900 text-[10px] font-bold text-slate-300 rounded-lg flex items-center gap-1.5 cursor-pointer transition-colors"
          >
            <Download className="w-3.5 h-3.5" /> PDF
          </button>
          <button
            onClick={() => downloadReportFile("html")}
            className="px-3 py-1.5 bg-slate-950 border border-slate-800 hover:bg-slate-900 text-[10px] font-bold text-slate-300 rounded-lg flex items-center gap-1.5 cursor-pointer transition-colors"
          >
            <Download className="w-3.5 h-3.5" /> HTML
          </button>
          <button
            onClick={() => downloadReportFile("json")}
            className="px-3 py-1.5 bg-slate-950 border border-slate-800 hover:bg-slate-900 text-[10px] font-bold text-slate-300 rounded-lg flex items-center gap-1.5 cursor-pointer transition-colors"
          >
            <Download className="w-3.5 h-3.5" /> JSON
          </button>
          <button
            onClick={onNavigateToDashboard}
            className="px-3 py-1.5 bg-gradient-to-r from-slate-800 to-slate-700 text-[10px] font-bold text-white rounded-lg cursor-pointer"
          >
            Dashboard
          </button>
        </div>
      </div>

      {/* Main Results Layout Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left column: Findings Index */}
        <div className="lg:col-span-4 space-y-4 max-h-[70vh] overflow-y-auto pr-2">
          <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Scan Findings Index</span>
          
          {Object.keys(filesMap).length > 0 ? (
            Object.keys(filesMap).map((filePath) => (
              <div key={filePath} className="glass-panel border-slate-800/80 rounded-xl p-3 space-y-2">
                <div className="flex items-center gap-1.5 border-b border-slate-900 pb-1.5">
                  <FileCode className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                  <span className="text-[10px] font-semibold text-slate-400 truncate" title={filePath}>{filePath.split('/').pop()}</span>
                </div>
                
                <div className="space-y-1.5">
                  {filesMap[filePath].map((vuln) => (
                    <button
                      key={vuln.id}
                      onClick={() => setSelectedVuln(vuln)}
                      className={`w-full p-2 rounded-lg flex items-center justify-between text-left text-xs transition-colors cursor-pointer border ${
                        selectedVuln?.id === vuln.id 
                          ? "bg-slate-900 border-blue-500/50" 
                          : "bg-slate-950/20 border-transparent hover:bg-slate-900/50"
                      }`}
                    >
                      <div className="flex items-center gap-2 truncate">
                        {getSeverityIcon(vuln.severity)}
                        <span className="font-medium text-slate-200 truncate">{vuln.category}</span>
                      </div>
                      <span className="text-[9px] text-slate-500 font-mono pl-2 shrink-0">L{vuln.line_number || "N/A"}</span>
                    </button>
                  ))}
                </div>
              </div>
            ))
          ) : (
            <div className="p-8 text-center border border-dashed border-slate-800 rounded-xl text-xs text-slate-500">
              No findings generated
            </div>
          )}
        </div>

        {/* Right column: Code Highlights & Detail Drawer */}
        <div className="lg:col-span-8 space-y-5">
          {selectedVuln ? (
            <>
              {/* Vulnerability Metadata */}
              <div className="glass-panel border-slate-800 rounded-xl p-5 space-y-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="flex items-center gap-2.5">
                    <span className={`px-2.5 py-0.5 text-[10px] font-bold rounded-full ${getSeverityBadgeClass(selectedVuln.severity)}`}>
                      {selectedVuln.severity}
                    </span>
                    <h2 className="text-base font-bold text-slate-100">{selectedVuln.category}</h2>
                  </div>
                  <span className="text-[10px] text-slate-500 font-bold bg-slate-900 px-2 py-0.5 rounded border border-slate-850">
                    {selectedVuln.tool_name}
                  </span>
                </div>
                
                <div>
                  <span className="text-[10px] text-slate-500 font-bold block uppercase tracking-wider">Vulnerable File Location</span>
                  <span className="text-xs text-slate-300 font-mono mt-0.5 block">{selectedVuln.file_path} {selectedVuln.line_number && `: Line ${selectedVuln.line_number}`}</span>
                </div>

                <div>
                  <span className="text-[10px] text-slate-500 font-bold block uppercase tracking-wider">Vulnerability Threat Details</span>
                  <p className="text-xs text-slate-300 mt-1 leading-relaxed">{selectedVuln.message}</p>
                </div>
              </div>

              {/* In-File Code Highlight Section */}
              <div className="glass-panel border-slate-800 rounded-xl overflow-hidden shadow-2xl">
                <div className="bg-slate-950 px-4 py-2 border-b border-slate-850 flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-rose-500" />
                  <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider font-mono">Source Code Preview</span>
                </div>
                
                <div className="p-4 bg-slate-950 max-h-[30vh] overflow-y-auto text-xs font-mono leading-relaxed">
                  {loadingFile ? (
                    <div className="py-6 text-center text-slate-600">Loading code preview...</div>
                  ) : fileContent ? (
                    fileContent.split("\n").map((line, idx) => {
                      const lineNum = idx + 1;
                      const isTarget = lineNum === selectedVuln.line_number;
                      return (
                        <div 
                          key={idx} 
                          className={`flex items-start -mx-4 px-4 ${isTarget ? "bg-rose-500/10 border-l-2 border-rose-500 text-rose-300" : "text-slate-400"}`}
                        >
                          <span className="w-8 select-none text-[10px] text-slate-600 text-right pr-3 shrink-0">{lineNum}</span>
                          <span className="whitespace-pre">{line}</span>
                        </div>
                      );
                    })
                  ) : (
                    <pre className="text-rose-400 bg-rose-950/15 border border-rose-900/35 p-3 rounded text-[11px] whitespace-pre-wrap leading-normal">
                      Could not fetch full file. Snippet:
                      {"\n"}{selectedVuln.code_snippet || "No snippet available."}
                    </pre>
                  )}
                </div>
              </div>

              {/* Remediation & AI Analysis tabs */}
              <div className="glass-panel border-slate-800 rounded-xl p-5 space-y-4">
                <div className="flex border-b border-slate-800/80 pb-2 justify-between items-center">
                  <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">Fix Remediation & AI Assistant</span>
                  <div className="flex gap-2">
                    <button
                      onClick={() => setChatOpen(true)}
                      className="px-2.5 py-1 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-[10px] font-bold text-slate-300 rounded flex items-center gap-1 cursor-pointer"
                    >
                      <MessageSquare className="w-3.5 h-3.5" /> AI Chat
                    </button>
                  </div>
                </div>

                <div className="space-y-4">
                  {/* Standard Remediation Box */}
                  <div className="p-3.5 bg-slate-950/60 border border-slate-850 rounded-xl space-y-1">
                    <span className="text-[10px] font-bold text-slate-400 block uppercase tracking-wider">Defensive Remediation Guide</span>
                    <p className="text-xs text-slate-300 leading-relaxed">{selectedVuln.remediation}</p>
                  </div>

                  {/* AI Explanation & Rewrite Block */}
                  {!isPaidOrAdmin ? (
                    <div className="pt-3 border-t border-slate-900 text-center py-6 px-4 bg-slate-950/40 border border-slate-900/60 rounded-xl space-y-3 animate-fade-in">
                      <div className="w-9 h-9 rounded-full bg-amber-500/10 border border-amber-500/20 flex items-center justify-center mx-auto text-amber-400 shadow-lg shadow-amber-950/20">
                        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="lucide lucide-lock"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                      </div>
                      <div className="space-y-1 max-w-sm mx-auto">
                        <h4 className="text-[10px] font-black text-slate-200 uppercase tracking-wider">AI Security Review Locked</h4>
                        <p className="text-[9px] text-slate-400 leading-relaxed">
                          Custom vulnerability explanations and secure code suggestions are premium features. Upgrade your account to the <strong>Paid Plan</strong> to unlock defensive AI remediation.
                        </p>
                      </div>
                    </div>
                  ) : selectedVuln.ai_explanation ? (
                    <div className="space-y-3 pt-3 border-t border-slate-900">
                      <div className="flex items-center gap-1.5 text-emerald-400">
                        <Sparkles className="w-4 h-4 fill-emerald-400/25" />
                        <span className="text-[10px] font-bold uppercase tracking-wider">AI Security Review</span>
                      </div>
                      
                      <div className="text-xs text-slate-300 leading-relaxed whitespace-pre-line bg-emerald-950/5 border border-emerald-900/10 p-4 rounded-xl">
                        {selectedVuln.ai_explanation}
                      </div>

                      {selectedVuln.ai_fix && (
                        <div className="space-y-2">
                          <span className="text-[10px] font-bold text-emerald-400 block uppercase tracking-wider">AI Secure Implementation Recommendation</span>
                          <pre className="p-4 bg-emerald-950/20 border border-emerald-900/30 rounded-xl overflow-x-auto text-[10px] text-emerald-300 font-mono leading-normal">
                            {selectedVuln.ai_fix}
                          </pre>
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="pt-3 border-t border-slate-900 text-center py-4">
                      <p className="text-xs text-slate-500 mb-3">AI secure remediation analysis has not been loaded for this vulnerability.</p>
                      <button
                        onClick={handleEnrich}
                        disabled={enriching}
                        className="px-4 py-2 bg-gradient-to-r from-emerald-500 to-teal-500 text-white text-xs font-bold rounded-lg shadow shadow-emerald-500/10 hover:from-emerald-600 cursor-pointer disabled:opacity-50 flex items-center gap-1.5 mx-auto"
                      >
                        {enriching ? (
                          <>
                            <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin"></span>
                            <span>AI is Thinking...</span>
                          </>
                        ) : (
                          <>
                            <Sparkles className="w-3.5 h-3.5" /> Explain with AI Assistant
                          </>
                        )}
                      </button>
                    </div>
                  )}
                </div>
              </div>
            </>
          ) : (
            <div className="p-12 text-center border border-dashed border-slate-800 rounded-xl text-xs text-slate-500">
              Select a vulnerability from the index to display details
            </div>
          )}
        </div>
      </div>

      {/* Floating Chat Sidebar Drawer */}
      {chatOpen && (
        <div className="fixed inset-y-0 right-0 w-full md:w-96 bg-slate-950 border-l border-slate-800/80 shadow-2xl z-50 flex flex-col transition-all duration-300 animate-slide-in">
          {/* Sidebar Header */}
          <div className="p-4 border-b border-slate-850 flex justify-between items-center">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-amber-400 fill-amber-400/25" />
              <span className="text-xs font-bold text-slate-200">AI Remediation Assistant</span>
            </div>
            <button
              onClick={() => setChatOpen(false)}
              className="text-slate-500 hover:text-slate-300 text-xs font-bold cursor-pointer"
            >
              ✕
            </button>
          </div>

          {/* Chat message logs */}
          <div className="flex-1 p-4 overflow-y-auto space-y-4 scroll-smooth">
            {!isPaidOrAdmin ? (
              <div className="h-full flex flex-col items-center justify-center text-center p-6 space-y-3.5">
                <div className="w-11 h-11 bg-amber-500/10 border border-amber-500/20 rounded-full flex items-center justify-center text-amber-400 shadow-lg shadow-amber-950/20 animate-pulse">
                  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="lucide lucide-lock"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                </div>
                <div className="space-y-1">
                  <h4 className="text-[10px] font-black text-slate-200 uppercase tracking-wider">AI Chat Assistant Locked</h4>
                  <p className="text-[9px] text-slate-500 leading-relaxed max-w-[220px] mx-auto">
                    Get interactive explanations, defensive refactoring tips, and code review support directly in your scan. Ask your administrator to upgrade your account to Paid.
                  </p>
                </div>
              </div>
            ) : chatMessages.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-center p-6 text-slate-600">
                <MessageSquare className="w-8 h-8 mb-2" />
                <span className="text-xs">Ask anything about this scan's results or how to fix these vulnerabilities.</span>
              </div>
            ) : (
              chatMessages.map((msg) => (
                <div key={msg.id} className={`flex flex-col ${msg.is_ai ? "items-start" : "items-end"}`}>
                  <div 
                    className={`max-w-[85%] rounded-xl p-3 text-xs leading-relaxed ${
                      msg.is_ai 
                        ? "bg-slate-900 border border-slate-800 text-slate-200 whitespace-pre-line" 
                        : "bg-gradient-to-tr from-rose-500 to-amber-500 text-white"
                    }`}
                  >
                    {msg.message}
                  </div>
                  <span className="text-[9px] text-slate-600 mt-1 font-mono">
                    {new Date(msg.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </span>
                </div>
              ))
            )}
            
            {sendingChat && (
              <div className="flex items-center gap-2 text-xs text-slate-500 font-mono">
                <span className="w-3.5 h-3.5 border-2 border-slate-700 border-t-amber-500 rounded-full animate-spin"></span>
                AI is typing response...
              </div>
            )}
          </div>

          {/* Prompt input field */}
          <form onSubmit={handleSendChat} className="p-4 border-t border-slate-850 flex gap-2">
            <input
              type="text"
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              disabled={!isPaidOrAdmin || sendingChat}
              className="flex-1 px-3 py-2 bg-slate-950 border border-slate-850 rounded-lg text-slate-200 placeholder-slate-600 text-xs focus:outline-none focus:border-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
              placeholder={isPaidOrAdmin ? "How can I refactor this using env variables?" : "Premium feature locked"}
              required
            />
            <button
              type="submit"
              disabled={!isPaidOrAdmin || sendingChat || !chatInput.trim()}
              className="p-2 bg-gradient-to-r from-rose-500 to-amber-500 text-white rounded-lg hover:from-rose-600 disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
            >
              <Send className="w-3.5 h-3.5" />
            </button>
          </form>
        </div>
      )}
    </div>
  );
};
