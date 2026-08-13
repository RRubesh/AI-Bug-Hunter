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
    const res = await fetch("/api/auth/register", {
      method: "POST",
      headers: getHeaders(),
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Registration failed");
    }
    return res.json();
  },

  async forgotPassword(username: string, recoveryKey: string, newPassword: string): Promise<{ message: string }> {
    const res = await fetch("/api/auth/forgot-password", {
      method: "POST",
      headers: getHeaders(),
      body: JSON.stringify({ username, recovery_key: recoveryKey, new_password: newPassword }),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Password reset failed");
    }
    return res.json();
  },

  async login(username: string, password: string): Promise<{ access_token: string, role: string, username: string }> {
    const formData = new URLSearchParams();
    formData.append("username", username);
    formData.append("password", password);

    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: formData.toString(),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Login failed");
    }
    const data = await res.json();
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
    const res = await fetch("/api/auth/me", {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error("Unauthorized");
    return res.json();
  },

  // --- PROJECTS ---
  async getProjects(): Promise<Project[]> {
    const res = await fetch("/api/projects", {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error("Failed to fetch projects");
    return res.json();
  },

  async createProject(formData: FormData): Promise<Project> {
    const res = await fetch("/api/projects", {
      method: "POST",
      headers: getHeaders(true),
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Failed to upload project");
    }
    return res.json();
  },

  async deleteProject(id: number): Promise<void> {
    const res = await fetch(`/api/projects/${id}`, {
      method: "DELETE",
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error("Failed to delete project");
  },

  // --- SCANS ---
  async triggerScan(projectId: number): Promise<Scan> {
    const res = await fetch(`/api/scans/${projectId}`, {
      method: "POST",
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error("Failed to trigger scan");
    return res.json();
  },

  async getScans(projectId: number): Promise<Scan[]> {
    const res = await fetch(`/api/scans/project/${projectId}`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error("Failed to fetch scans");
    return res.json();
  },

  async getScan(scanId: number): Promise<Scan> {
    const res = await fetch(`/api/scans/${scanId}`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error("Failed to fetch scan");
    return res.json();
  },

  async getVulnerabilities(scanId: number): Promise<Vulnerability[]> {
    const res = await fetch(`/api/scans/${scanId}/vulnerabilities`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error("Failed to fetch vulnerabilities");
    return res.json();
  },

  async getVulnerability(vulnId: number): Promise<Vulnerability> {
    const res = await fetch(`/api/vulnerabilities/${vulnId}`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error("Failed to fetch vulnerability details");
    return res.json();
  },

  async getFileContent(projectId: number, filePath: string): Promise<string> {
    const res = await fetch(`/api/projects/${projectId}/file-content?path=${encodeURIComponent(filePath)}`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error("Failed to fetch file content");
    const data = await res.json();
    return data.content;
  },

  // --- AI SECURITY ASSISTANT ---
  async enrichVulnerability(vulnId: number): Promise<Vulnerability> {
    const res = await fetch(`/api/ai/enrich/${vulnId}`, {
      method: "POST",
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error("Failed to enrich vulnerability");
    return res.json();
  },

  async getChatHistory(scanId: number): Promise<ChatMessage[]> {
    const res = await fetch(`/api/ai/chat/${scanId}`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error("Failed to fetch chat history");
    return res.json();
  },

  async sendChatMessage(scanId: number, message: string, vulnerabilityId?: number): Promise<ChatMessage> {
    const res = await fetch(`/api/ai/chat/${scanId}`, {
      method: "POST",
      headers: getHeaders(),
      body: JSON.stringify({ message, vulnerability_id: vulnerabilityId }),
    });
    if (!res.ok) throw new Error("Failed to get response from AI Assistant");
    return res.json();
  },

  async updateVulnerabilityStatus(vulnId: number, status: string): Promise<Vulnerability> {
    const res = await fetch(`/api/vulnerabilities/${vulnId}`, {
      method: "PATCH",
      headers: getHeaders(),
      body: JSON.stringify({ status }),
    });
    if (!res.ok) throw new Error("Failed to update vulnerability status");
    return res.json();
  },

  async cancelScan(scanId: number): Promise<Scan> {
    const res = await fetch(`/api/scans/${scanId}/cancel`, {
      method: "POST",
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error("Failed to cancel scan");
    return res.json();
  },

  async deleteScan(scanId: number): Promise<void> {
    const res = await fetch(`/api/scans/${scanId}`, {
      method: "DELETE",
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error("Failed to delete scan");
  },

  getReportDownloadUrl(scanId: number, format: "pdf" | "html" | "json" | "csv" = "pdf"): string {
    const token = localStorage.getItem("token");
    const query = token ? `?token=${encodeURIComponent(token)}` : "";
    return `/api/scans/${scanId}/report/${format}${query}`;
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
    const res = await fetch("/api/dashboard/summary", {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error("Failed to fetch dashboard summary");
    return res.json();
  },

  async getDashboardStats(): Promise<ScanStats> {
    const res = await fetch("/api/dashboard/stats", {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error("Failed to fetch dashboard statistics");
    return res.json();
  },

  async getSettings(): Promise<AppSettings> {
    try {
      const res = await fetch("/api/settings", {
        headers: getHeaders(),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `FastAPI backend error (${res.status})`);
      }
      return await res.json();
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
      const res = await fetch("/api/settings", {
        method: "POST",
        headers: getHeaders(),
        body: JSON.stringify(settings),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `Failed to update settings (${res.status})`);
      }
      return await res.json();
    } catch (err: unknown) {
      if (err instanceof Error) throw err;
      throw new Error("Unable to connect to FastAPI backend server");
    }
  },

  // --- ADMIN PANEL ---
  async getAdminUsers(): Promise<User[]> {
    const res = await fetch("/api/admin/users", {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error("Failed to fetch users");
    return res.json();
  },

  async updateAdminUserRole(userId: number, role: string): Promise<void> {
    const res = await fetch(`/api/admin/users/${userId}/role?role=${role}`, {
      method: "POST",
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error("Failed to update user role");
  },

  async createAdminUser(username: string, password: string, role: string): Promise<User> {
    const res = await fetch(`/api/admin/users?role=${role}`, {
      method: "POST",
      headers: getHeaders(),
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Failed to create user");
    }
    return res.json();
  },

  async deleteAdminUser(userId: number): Promise<void> {
    const res = await fetch(`/api/admin/users/${userId}`, {
      method: "DELETE",
      headers: getHeaders(),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Failed to delete user");
    }
  }
};
