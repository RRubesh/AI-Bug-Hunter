// Frontend API connector for AI Bug Hunter

export interface User {
  id: number;
  username: string;
  role: string;
  created_at: string;
}

export interface Project {
  id: number;
  name: string;
  description?: string;
  upload_type: string;
  file_path?: string;
  language_detected?: string;
  owner_id: number;
  owner_username?: string;
  created_at: string;
  updated_at: string;
  latest_scan?: Scan;
  scans?: Scan[];
}

export interface Scan {
  id: number;
  project_id: number;
  status: string;
  progress: number;
  trigger_type: string;
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  created_at: string;
  finished_at?: string;
  project?: Project;
}

export interface Vulnerability {
  id: number;
  scan_id: number;
  file_path: string;
  line_number?: number;
  code_snippet?: string;
  severity: string;
  category: string;
  message: string;
  tool_name: string;
  status?: string;
  remediation?: string;
  ai_explanation?: string;
  ai_fix?: string;
  created_at: string;
}

export interface ChatMessage {
  id: number;
  scan_id: number;
  user_id: number;
  message: string;
  is_ai: boolean;
  created_at: string;
}

export interface SeverityStats {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScanStats {
  total_scans: number;
  total_vulnerabilities: number;
  severity_distribution: SeverityStats;
  scans_history: Scan[];
  critical_vulnerabilities?: number;
  high_vulnerabilities?: number;
  medium_vulnerabilities?: number;
  low_vulnerabilities?: number;
}

export interface DashboardSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total_scans: number;
  total_vulnerabilities: number;
  fixed_vulnerabilities: number;
  security_score: number;
  recent_scans: Scan[];
}

export interface AppSettings {
  ollama_url: string;
  default_model: string;
  available_models: string[];
  ai_provider: string;
  openai_api_key_configured: boolean;
  gemini_api_key_configured: boolean;
  groq_api_key_configured: boolean;
  claude_api_key_configured: boolean;
  grok_api_key_configured: boolean;
}

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

export const isCloudDeployment = (): boolean => {
  const url = API_BASE_URL || (typeof window !== "undefined" ? window.location.href : "");
  return url.includes("vercel.app") || url.includes("render.com");
};

export const getMaxUploadSizeMB = (): number => {
  return 50;
};

export const getMaxUploadSizeBytes = (): number => {
  return getMaxUploadSizeMB() * 1024 * 1024;
};

const getApiUrl = (path: string): string => {
  const cleanPath = path.startsWith("/") ? path : `/${path}`;
  return API_BASE_URL ? `${API_BASE_URL}${cleanPath}` : cleanPath;
};

const safeJson = async (res: Response) => {
  const text = await res.text();
  let data: any = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    if (!res.ok) {
      if (res.status === 413) {
        throw new Error("Uploaded file/payload is too large for the server (HTTP 413). Upload limit is 50 MB per request. Please compress your project into a smaller ZIP (excluding node_modules, .git, and venv) or use the Git Repository / Paste Code option.");
      }
      if (res.status === 504 || res.status === 502) {
        throw new Error(`Server gateway timeout (HTTP ${res.status}). The requested operation timed out on the cloud server.`);
      }
      throw new Error(`Server error (${res.status}). Verify backend URL is configured correctly.`);
    }
    throw new Error("Invalid response format received from server.");
  }
  if (!res.ok) {
    if (res.status === 413) {
      throw new Error(data.detail || "Uploaded file/payload is too large for the server (HTTP 413). Upload limit is 50 MB per request. Please compress your project into a smaller ZIP (excluding node_modules, .git, and venv) or use the Git Repository / Paste Code option.");
    }
    throw new Error(data.detail || `HTTP ${res.status} error from backend`);
  }
  return data;
};

const getHeaders = (multipart = false) => {
  const token = localStorage.getItem("token");
  const headers: HeadersInit = {};
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  if (!multipart) {
    headers["Content-Type"] = "application/json";
  }
  return headers;
};

export const api = {
  // --- AUTHENTICATION ---
  async register(username: string, password: string): Promise<User> {
    const res = await fetch(getApiUrl("/api/auth/register"), {
      method: "POST",
      headers: getHeaders(),
      body: JSON.stringify({ username, password }),
    });
    return safeJson(res);
  },

  async forgotPassword(username: string, recoveryKey: string, newPassword: string): Promise<{ message: string }> {
    const res = await fetch(getApiUrl("/api/auth/forgot-password"), {
      method: "POST",
      headers: getHeaders(),
      body: JSON.stringify({ username, recovery_key: recoveryKey, new_password: newPassword }),
    });
    return safeJson(res);
  },

  async login(username: string, password: string): Promise<{ access_token: string, role: string, username: string }> {
    const formData = new URLSearchParams();
    formData.append("username", username);
    formData.append("password", password);

    const res = await fetch(getApiUrl("/api/auth/login"), {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: formData.toString(),
    });
    const data = await safeJson(res);
    localStorage.setItem("token", data.access_token);
    localStorage.setItem("role", data.role);
    localStorage.setItem("username", data.username);
    return data;
  },

  logout() {
    localStorage.removeItem("token");
    localStorage.removeItem("role");
    localStorage.removeItem("username");
  },

  async getMe(): Promise<User> {
    const res = await fetch(getApiUrl("/api/auth/me"), {
      headers: getHeaders(),
    });
    return safeJson(res);
  },

  // --- PROJECTS ---
  async getProjects(): Promise<Project[]> {
    const res = await fetch(getApiUrl("/api/projects"), {
      headers: getHeaders(),
    });
    return safeJson(res);
  },

  async createProject(formData: FormData): Promise<Project> {
    const res = await fetch(getApiUrl("/api/projects"), {
      method: "POST",
      headers: getHeaders(true),
      body: formData,
    });
    return safeJson(res);
  },

  async deleteProject(id: number): Promise<void> {
    const res = await fetch(getApiUrl(`/api/projects/${id}`), {
      method: "DELETE",
      headers: getHeaders(),
    });
    await safeJson(res);
  },

  // --- SCANS ---
  async triggerScan(projectId: number): Promise<Scan> {
    const res = await fetch(getApiUrl(`/api/scans/${projectId}`), {
      method: "POST",
      headers: getHeaders(),
    });
    return safeJson(res);
  },

  async getScans(projectId: number): Promise<Scan[]> {
    const res = await fetch(getApiUrl(`/api/scans/project/${projectId}`), {
      headers: getHeaders(),
    });
    return safeJson(res);
  },

  async getScan(scanId: number): Promise<Scan> {
    const res = await fetch(getApiUrl(`/api/scans/${scanId}`), {
      headers: getHeaders(),
    });
    return safeJson(res);
  },

  async getVulnerabilities(scanId: number): Promise<Vulnerability[]> {
    const res = await fetch(getApiUrl(`/api/scans/${scanId}/vulnerabilities`), {
      headers: getHeaders(),
    });
    return safeJson(res);
  },

  async getVulnerability(vulnId: number): Promise<Vulnerability> {
    const res = await fetch(getApiUrl(`/api/vulnerabilities/${vulnId}`), {
      headers: getHeaders(),
    });
    return safeJson(res);
  },

  async getFileContent(projectId: number, filePath: string): Promise<string> {
    const res = await fetch(getApiUrl(`/api/projects/${projectId}/file-content?path=${encodeURIComponent(filePath)}`), {
      headers: getHeaders(),
    });
    const data = await safeJson(res);
    return data.content;
  },

  // --- AI SECURITY ASSISTANT ---
  async enrichVulnerability(vulnId: number): Promise<Vulnerability> {
    const res = await fetch(getApiUrl(`/api/ai/enrich/${vulnId}`), {
      method: "POST",
      headers: getHeaders(),
    });
    return safeJson(res);
  },

  async getChatHistory(scanId: number): Promise<ChatMessage[]> {
    const res = await fetch(getApiUrl(`/api/ai/chat/${scanId}`), {
      headers: getHeaders(),
    });
    return safeJson(res);
  },

  async sendChatMessage(scanId: number, message: string, vulnerabilityId?: number): Promise<ChatMessage> {
    const res = await fetch(getApiUrl(`/api/ai/chat/${scanId}`), {
      method: "POST",
      headers: getHeaders(),
      body: JSON.stringify({ message, vulnerability_id: vulnerabilityId }),
    });
    return safeJson(res);
  },

  async updateVulnerabilityStatus(vulnId: number, status: string): Promise<Vulnerability> {
    const res = await fetch(getApiUrl(`/api/vulnerabilities/${vulnId}`), {
      method: "PATCH",
      headers: getHeaders(),
      body: JSON.stringify({ status }),
    });
    return safeJson(res);
  },

  async cancelScan(scanId: number): Promise<Scan> {
    const res = await fetch(getApiUrl(`/api/scans/${scanId}/cancel`), {
      method: "POST",
      headers: getHeaders(),
    });
    return safeJson(res);
  },

  async deleteScan(scanId: number): Promise<void> {
    const res = await fetch(getApiUrl(`/api/scans/${scanId}`), {
      method: "DELETE",
      headers: getHeaders(),
    });
    await safeJson(res);
  },

  getReportDownloadUrl(scanId: number, format: "pdf" | "html" | "json" | "csv" = "pdf"): string {
    const token = localStorage.getItem("token");
    const query = token ? `?token=${encodeURIComponent(token)}` : "";
    return getApiUrl(`/api/scans/${scanId}/report/${format}${query}`);
  },

  async downloadReportFile(scanId: number, format: "pdf" | "html" | "json" | "csv"): Promise<void> {
    const url = this.getReportDownloadUrl(scanId, format);
    const res = await fetch(url, { headers: getHeaders() });
    if (!res.ok) {
      const errText = await res.text().catch(() => "");
      throw new Error(`Download failed (${res.status}): ${errText || res.statusText}`);
    }
    const blob = await res.blob();
    const blobUrl = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = blobUrl;
    a.download = `AI_Bug_Hunter_Report_${scanId}.${format}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(blobUrl);
  },

  // --- DASHBOARD & SETTINGS ---
  async getDashboardSummary(): Promise<DashboardSummary> {
    const res = await fetch(getApiUrl("/api/dashboard/summary"), {
      headers: getHeaders(),
    });
    return safeJson(res);
  },

  async getDashboardStats(): Promise<ScanStats> {
    const res = await fetch(getApiUrl("/api/dashboard/stats"), {
      headers: getHeaders(),
    });
    return safeJson(res);
  },

  async getSettings(): Promise<AppSettings> {
    try {
      const res = await fetch(getApiUrl("/api/settings"), {
        headers: getHeaders(),
      });
      return await safeJson(res);
    } catch (err: unknown) {
      if (err instanceof Error) throw err;
      throw new Error("Unable to connect to FastAPI backend server");
    }
  },

  async updateSettings(settings: {
    ollama_url?: string;
    default_model?: string;
    ai_provider?: string;
    openai_api_key?: string;
    gemini_api_key?: string;
    groq_api_key?: string;
    claude_api_key?: string;
    grok_api_key?: string;
  }): Promise<AppSettings> {
    try {
      const res = await fetch(getApiUrl("/api/settings"), {
        method: "POST",
        headers: getHeaders(),
        body: JSON.stringify(settings),
      });
      return await safeJson(res);
    } catch (err: unknown) {
      if (err instanceof Error) throw err;
      throw new Error("Unable to connect to FastAPI backend server");
    }
  },

  // --- ADMIN PANEL ---
  async getAdminUsers(): Promise<User[]> {
    const res = await fetch(getApiUrl("/api/admin/users"), {
      headers: getHeaders(),
    });
    return safeJson(res);
  },

  async updateAdminUserRole(userId: number, role: string): Promise<void> {
    const res = await fetch(getApiUrl(`/api/admin/users/${userId}/role?role=${role}`), {
      method: "POST",
      headers: getHeaders(),
    });
    await safeJson(res);
  },

  async createAdminUser(username: string, password: string, role: string): Promise<User> {
    const res = await fetch(getApiUrl(`/api/admin/users?role=${role}`), {
      method: "POST",
      headers: getHeaders(),
      body: JSON.stringify({ username, password }),
    });
    return safeJson(res);
  },

  async deleteAdminUser(userId: number): Promise<void> {
    const res = await fetch(getApiUrl(`/api/admin/users/${userId}`), {
      method: "DELETE",
      headers: getHeaders(),
    });
    await safeJson(res);
  }
};
