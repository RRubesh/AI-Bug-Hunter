import React, { useState } from "react";
import { api } from "../services/api";
import { FileArchive, GitBranch, Code2, Upload, AlertCircle, ShieldAlert, Globe, Search } from "lucide-react";
import { CODE_EXAMPLES } from "../constants/codeExamples";

interface UploadProjectProps {
  onUploadSuccess: (projectId: number) => void;
  onCancel: () => void;
}

const LANGUAGE_COLORS: Record<string, { bg: string; border: string; text: string; glow: string }> = {
  Python: { bg: "hover:bg-blue-500/10", border: "hover:border-blue-500/30", text: "hover:text-blue-400", glow: "border-blue-500/50 bg-blue-500/10 text-blue-400 shadow-blue-500/10" },
  PHP: { bg: "hover:bg-violet-500/10", border: "hover:border-violet-500/30", text: "hover:text-violet-400", glow: "border-violet-500/50 bg-violet-500/10 text-violet-400 shadow-violet-500/10" },
  Go: { bg: "hover:bg-cyan-500/10", border: "hover:border-cyan-500/30", text: "hover:text-cyan-400", glow: "border-cyan-500/50 bg-cyan-500/10 text-cyan-400 shadow-cyan-500/10" },
  JS: { bg: "hover:bg-yellow-500/10", border: "hover:border-yellow-500/30", text: "hover:text-yellow-400", glow: "border-yellow-500/50 bg-yellow-500/10 text-yellow-400 shadow-yellow-500/10" },
  TS: { bg: "hover:bg-blue-600/10", border: "hover:border-blue-600/30", text: "hover:text-blue-400", glow: "border-blue-600/50 bg-blue-600/10 text-blue-400 shadow-blue-600/10" },
  Java: { bg: "hover:bg-orange-500/10", border: "hover:border-orange-500/30", text: "hover:text-orange-400", glow: "border-orange-500/50 bg-orange-500/10 text-orange-400 shadow-orange-500/10" },
  C: { bg: "hover:bg-slate-500/10", border: "hover:border-slate-500/30", text: "hover:text-slate-400", glow: "border-slate-500/50 bg-slate-500/10 text-slate-400 shadow-slate-500/10" },
  "C++": { bg: "hover:bg-indigo-500/10", border: "hover:border-indigo-500/30", text: "hover:text-indigo-400", glow: "border-indigo-500/50 bg-indigo-500/10 text-indigo-400 shadow-indigo-500/10" },
  "C#": { bg: "hover:bg-emerald-500/10", border: "hover:border-emerald-500/30", text: "hover:text-emerald-400", glow: "border-emerald-500/50 bg-emerald-500/10 text-emerald-400 shadow-emerald-500/10" },
  Rust: { bg: "hover:bg-red-500/10", border: "hover:border-red-500/30", text: "hover:text-red-400", glow: "border-red-500/50 bg-red-500/10 text-red-400 shadow-red-500/10" },
};

const TEMPLATE_METADATA: Record<string, { title: string; desc: string; tags: string[]; iconColor: string }> = {
  Python: { title: "Python SAST", desc: "Scan custom Python source files for vulnerabilities.", tags: ["Python", "Custom Code", "Bandit"], iconColor: "text-blue-400 bg-blue-500/10" },
  PHP: { title: "PHP Script", desc: "Scan custom PHP script files for vulnerabilities.", tags: ["PHP", "Custom Code", "Semgrep"], iconColor: "text-violet-400 bg-violet-500/10" },
  Go: { title: "Go Backend", desc: "Scan custom Go source files for vulnerabilities.", tags: ["Go", "Custom Code", "Semgrep"], iconColor: "text-cyan-400 bg-cyan-500/10" },
  JS: { title: "JavaScript Node", desc: "Scan custom JavaScript source files for vulnerabilities.", tags: ["JavaScript", "Custom Code", "Semgrep"], iconColor: "text-yellow-400 bg-yellow-500/10" },
  TS: { title: "TypeScript Express", desc: "Scan custom TypeScript source files for vulnerabilities.", tags: ["TypeScript", "Custom Code", "Semgrep"], iconColor: "text-blue-400 bg-blue-500/10" },
  Java: { title: "Java Source", desc: "Scan custom Java source files for vulnerabilities.", tags: ["Java", "Custom Code", "Semgrep"], iconColor: "text-orange-400 bg-orange-500/10" },
  C: { title: "C Codebase", desc: "Scan custom C source files for vulnerabilities.", tags: ["C", "Custom Code", "Semgrep"], iconColor: "text-slate-400 bg-slate-500/10" },
  "C++": { title: "C++ CLI App", desc: "Scan custom C++ source files for vulnerabilities.", tags: ["C++", "Custom Code", "Semgrep"], iconColor: "text-indigo-400 bg-indigo-500/10" },
  "C#": { title: "C# SQL Database", desc: "Scan custom C# source files for vulnerabilities.", tags: ["C#", "Custom Code", "Semgrep"], iconColor: "text-emerald-400 bg-emerald-500/10" },
  Rust: { title: "Rust Cargo", desc: "Scan custom Rust source files for vulnerabilities.", tags: ["Rust", "Custom Code", "Semgrep"], iconColor: "text-red-400 bg-red-500/10" },
};

export const UploadProject: React.FC<UploadProjectProps> = ({ onUploadSuccess, onCancel }) => {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [uploadType, setUploadType] = useState<"zip" | "git" | "file" | "url">("zip");
  
  // Input specific state
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [gitUrl, setGitUrl] = useState("");
  const [pastedCode, setPastedCode] = useState("");
  const [activeLanguage, setActiveLanguage] = useState<string | null>(null);
  const [templateSearchQuery, setTemplateSearchQuery] = useState("");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setSelectedFile(e.target.files[0]);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name) {
      setError("Project name is required.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const formData = new FormData();
      formData.append("name", name);
      if (description) formData.append("description", description);
      formData.append("upload_type", uploadType);

      if (uploadType === "zip") {
        if (!selectedFile) throw new Error("Please select a ZIP file containing the source code.");
        formData.append("file", selectedFile);
      } else if (uploadType === "git") {
        if (!gitUrl) throw new Error("Please enter a valid Git Repository URL.");
        formData.append("git_url", gitUrl);
      } else if (uploadType === "url") {
        if (!gitUrl) throw new Error("Please enter a website or URL link.");
        formData.append("git_url", gitUrl);
      } else if (uploadType === "file") {
        if (!pastedCode) throw new Error("Pasted source code is empty.");
        formData.append("pasted_code", pastedCode);
      }

      const proj = await api.createProject(formData);
      
      // Auto trigger scan on successful upload
      const scan = await api.triggerScan(proj.id);
      onUploadSuccess(scan.id);
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : "Failed to upload project. Check input parameters.";
      setError(errMsg);
      setLoading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-black text-slate-100 tracking-tight">Upload Codebase to Analyzer</h1>
        <p className="text-xs text-slate-400 mt-1">
          Submit source files, clone a repository, or copy-paste code for security checking.
        </p>
      </div>

      {error && (
        <div className="p-3 bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs rounded-lg flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="p-6 glass-panel rounded-xl border-slate-800 space-y-4">
          <h2 className="text-xs font-bold text-slate-400 uppercase tracking-wider border-b border-slate-800/80 pb-2">Project Metadata</h2>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1.5">Project Name</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full px-3.5 py-2 bg-slate-950/60 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-600 text-xs focus:outline-none focus:border-blue-500"
                placeholder="Secure API Gateway"
                required
              />
            </div>
            <div>
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1.5">Description (Optional)</label>
              <input
                type="text"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                className="w-full px-3.5 py-2 bg-slate-950/60 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-600 text-xs focus:outline-none focus:border-blue-500"
                placeholder="Python backend web app"
              />
            </div>
          </div>
        </div>

        {/* Upload Source Tab Selector */}
        <div className="p-6 glass-panel rounded-xl border-slate-800 space-y-5">
          <h2 className="text-xs font-bold text-slate-400 uppercase tracking-wider border-b border-slate-800/80 pb-2">Code Ingestion Method</h2>

          <div className="flex border-b border-slate-800/80">
            <button
              type="button"
              onClick={() => setUploadType("zip")}
              className={`flex-1 pb-3 text-xs font-bold flex items-center justify-center gap-2 cursor-pointer border-b-2 transition-colors ${
                uploadType === "zip" ? "border-rose-500 text-rose-400" : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              <FileArchive className="w-4 h-4" /> ZIP Archive
            </button>
            <button
              type="button"
              onClick={() => setUploadType("git")}
              className={`flex-1 pb-3 text-xs font-bold flex items-center justify-center gap-2 cursor-pointer border-b-2 transition-colors ${
                uploadType === "git" ? "border-rose-500 text-rose-400" : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              <GitBranch className="w-4 h-4" /> Git Clone
            </button>
            <button
              type="button"
              onClick={() => setUploadType("url")}
              className={`flex-1 pb-3 text-xs font-bold flex items-center justify-center gap-2 cursor-pointer border-b-2 transition-colors ${
                uploadType === "url" ? "border-rose-500 text-rose-400" : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              <Globe className="w-4 h-4" /> Web Link
            </button>
            <button
              type="button"
              onClick={() => setUploadType("file")}
              className={`flex-1 pb-3 text-xs font-bold flex items-center justify-center gap-2 cursor-pointer border-b-2 transition-colors ${
                uploadType === "file" ? "border-rose-500 text-rose-400" : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              <Code2 className="w-4 h-4" /> Paste Code
            </button>
          </div>

          {/* Form Ingestion Sections */}
          <div className="pt-2">
            {uploadType === "zip" && (
              <div className="flex flex-col items-center justify-center border-2 border-dashed border-slate-800 hover:border-slate-700/80 rounded-xl p-8 transition-colors bg-slate-950/20 text-center relative">
                <input
                  type="file"
                  accept=".zip"
                  onChange={handleFileChange}
                  className="absolute inset-0 opacity-0 cursor-pointer"
                />
                <Upload className="w-10 h-10 text-slate-500 mb-3" />
                <span className="text-xs font-bold text-slate-300">
                  {selectedFile ? selectedFile.name : "Click or drag ZIP archive to upload"}
                </span>
                <span className="text-[10px] text-slate-500 mt-1">Maximum file size: 50MB</span>
              </div>
            )}

            {uploadType === "git" && (
              <div className="space-y-3">
                <label className="block text-xs font-semibold text-slate-400">Git Clone Repository URL</label>
                <input
                  type="url"
                  value={gitUrl}
                  onChange={(e) => setGitUrl(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-950/60 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-600 text-xs focus:outline-none focus:border-blue-500 font-mono"
                  placeholder="https://github.com/OWASP/NodeGoat.git"
                />
                <span className="text-[10px] text-slate-500 block leading-normal">
                  Note: The server will perform a shallow clone (`--depth 1`) of the repository. Public repositories are supported.
                </span>
              </div>
            )}

            {uploadType === "url" && (
              <div className="space-y-3">
                <label className="block text-xs font-semibold text-slate-400">Website / Download URL Link</label>
                <input
                  type="url"
                  value={gitUrl}
                  onChange={(e) => setGitUrl(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-950/60 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-600 text-xs focus:outline-none focus:border-blue-500 font-mono"
                  placeholder="https://example.com/project.zip"
                  required
                />
                <span className="text-[10px] text-slate-500 block leading-normal">
                  Note: Provide a link to a ZIP archive or a raw source code file. The analyzer will automatically download and ingest the code.
                </span>
              </div>
            )}

            {uploadType === "file" && (() => {
              const filteredTemplates = Object.keys(CODE_EXAMPLES).filter((lang) => {
                const meta = TEMPLATE_METADATA[lang];
                if (!meta) return false;
                const query = templateSearchQuery.toLowerCase();
                const matchesLang = lang.toLowerCase().includes(query);
                const matchesTitle = meta.title.toLowerCase().includes(query);
                const matchesDesc = meta.desc.toLowerCase().includes(query);
                const matchesTags = meta.tags.some(tag => tag.toLowerCase().includes(query));
                return matchesLang || matchesTitle || matchesDesc || matchesTags;
              });

              return (
                <div className="space-y-4 animate-fade-in">
                  <div className="space-y-2.5">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                      <label className="block text-xs font-semibold text-slate-400">Select Vulnerable Language Template</label>
                      <div className="relative w-full sm:max-w-xs">
                        <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                        <input
                          type="text"
                          placeholder="Search by language or tag (e.g. SQLi)..."
                          value={templateSearchQuery}
                          onChange={(e) => setTemplateSearchQuery(e.target.value)}
                          className="w-full pl-8.5 pr-4 py-1.5 bg-slate-950/80 border border-slate-850 hover:border-slate-800 focus:border-blue-500/80 text-slate-200 text-[10px] rounded-lg focus:outline-none focus:ring-1 focus:ring-blue-500/30 transition-all font-medium"
                        />
                      </div>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 bg-slate-955/20 p-4 border border-slate-900 rounded-2xl max-h-[40vh] overflow-y-auto pr-2">
                      {filteredTemplates.length === 0 ? (
                        <div className="col-span-full text-center py-8 text-slate-500 text-xs font-semibold">
                          No matching vulnerability templates found. Try searching another category.
                        </div>
                      ) : (
                        filteredTemplates.map((lang) => {
                          const isActive = activeLanguage === lang;
                          const colors = LANGUAGE_COLORS[lang] || { bg: "hover:bg-slate-800", border: "hover:border-slate-700", text: "hover:text-slate-200", glow: "border-rose-500/50 bg-rose-500/10 text-rose-455" };
                          const meta = TEMPLATE_METADATA[lang] || { title: lang, desc: "Sample code snippet", tags: ["Vulnerabilities"], iconColor: "text-slate-400 bg-slate-800" };
                          return (
                            <button
                              key={lang}
                              type="button"
                              onClick={() => {
                                if (isActive) {
                                  setPastedCode("");
                                  setActiveLanguage(null);
                                  setName("");
                                  setDescription("");
                                } else {
                                  setPastedCode(CODE_EXAMPLES[lang].code);
                                  setActiveLanguage(lang);
                                  if (!name || name.trim() === "" || name.includes("Example") || name.includes("Vulnerability")) {
                                    setName(`${lang} Vulnerability Example`);
                                  }
                                  if (!description || description.trim() === "" || description.includes("Vulnerable") || description.includes("demonstration")) {
                                    setDescription(`Vulnerable ${lang} demonstration snippet`);
                                  }
                                }
                              }}
                              className={`p-3.5 rounded-xl border text-left transition-all duration-250 cursor-pointer flex flex-col justify-between space-y-2.5 ${
                                isActive
                                  ? `${colors.glow} scale-102 border-l-2 font-black shadow-lg shadow-slate-950/40`
                                  : `bg-slate-950/60 border-slate-850/60 text-slate-400 ${colors.bg} ${colors.border} ${colors.text} hover:scale-101 hover:shadow-md active:scale-98`
                              }`}
                            >
                              <div className="space-y-1 w-full">
                                <div className="flex items-center justify-between">
                                  <div className="flex items-center gap-2">
                                    <span className={`p-1.5 rounded-lg shrink-0 ${meta.iconColor}`}>
                                      <Code2 className="w-3.5 h-3.5" />
                                    </span>
                                    <span className={`text-xs font-black tracking-tight ${isActive ? "text-white" : "text-slate-200"}`}>
                                      {lang}
                                    </span>
                                  </div>
                                  <span className="text-[8px] font-mono font-medium text-slate-500 uppercase tracking-widest">
                                    {meta.title}
                                  </span>
                                </div>
                                <p className="text-[10px] text-slate-400 leading-normal font-medium mt-0.5">
                                  {meta.desc}
                                </p>
                              </div>

                              <div className="flex flex-wrap gap-1.5 pt-2 border-t border-slate-900/60 w-full">
                                {meta.tags.map((tag) => (
                                  <span
                                    key={tag}
                                    className={`text-[8px] font-bold px-1.5 py-0.5 rounded ${
                                      isActive
                                        ? "bg-rose-500/20 text-rose-300 border border-rose-500/10"
                                        : "bg-slate-900 text-slate-500 border border-slate-850"
                                    }`}
                                  >
                                    {tag}
                                  </span>
                                ))}
                              </div>
                            </button>
                          );
                        })
                      )}
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <label className="block text-xs font-semibold text-slate-400">Single File Code Editor</label>
                      {(pastedCode || activeLanguage) && (
                        <button
                          type="button"
                          onClick={() => {
                            setPastedCode("");
                            setActiveLanguage(null);
                            setName("");
                            setDescription("");
                          }}
                          className="text-[10px] font-bold text-rose-400 hover:text-rose-350 cursor-pointer transition-colors"
                        >
                          Clear Editor
                        </button>
                      )}
                    </div>
                    <textarea
                      value={pastedCode}
                      onChange={(e) => {
                        setPastedCode(e.target.value);
                        setActiveLanguage(null);
                      }}
                      rows={12}
                      className="w-full p-3.5 bg-slate-950/60 border border-slate-850 rounded-lg text-slate-355 placeholder-slate-600 text-xs font-mono focus:outline-none focus:border-blue-500/80 focus:ring-1 focus:ring-blue-500/30 transition-all leading-relaxed shadow-inner"
                      placeholder={`# Paste your code here\ndef process_query(user_input):\n    query = "SELECT * FROM users WHERE name = " + user_input\n    db.execute(query)`}
                    />
                  </div>
                </div>
              );
            })()}
          </div>
        </div>

        {/* Warning Banner */}
        <div className="p-4 bg-amber-500/5 border border-amber-500/10 rounded-xl flex items-start gap-3">
          <ShieldAlert className="w-5 h-5 text-amber-500 shrink-0 mt-0.5" />
          <div>
            <span className="text-xs font-bold text-amber-400">Security Warning</span>
            <p className="text-[11px] text-slate-400 mt-1 leading-normal">
              By uploading this code, it will be indexed locally for vulnerabilities checking and parsed by the local AI engine. Ensure you have the permissions to review the scanned code.
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex gap-4">
          <button
            type="button"
            onClick={onCancel}
            disabled={loading}
            className="flex-1 py-2.5 px-4 bg-slate-950 border border-slate-800 hover:bg-slate-900 text-slate-300 text-xs font-bold rounded-lg cursor-pointer transition-colors disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={loading}
            className="flex-1 py-2.5 px-4 bg-gradient-to-r from-rose-500 to-amber-500 text-white text-xs font-bold rounded-lg shadow-md hover:from-rose-600 hover:to-amber-600 cursor-pointer transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
          >
            {loading ? (
              <>
                <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></span>
                <span>Uploading & Analysing...</span>
              </>
            ) : (
              <span>Trigger Scan Run</span>
            )}
          </button>
        </div>
      </form>
    </div>
  );
};
