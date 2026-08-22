import React, { useEffect, useState } from "react";
import { api } from "../services/api";
import type { User } from "../services/api";
import { PageHeader } from "../components/ui/PageHeader";
import { CyberRadarLoader } from "../components/CyberRadarLoader";
import { GlassCard } from "../components/ui/GlassCard";
import { Button } from "../components/ui/Button";
import { Modal } from "../components/ui/Modal";
import { 
  Users, AlertCircle, Plus, Trash2, Search, User as UserIcon, Mail, Shield, ShieldAlert, FileText, CheckCircle2
} from "lucide-react";

export const AdminPanel: React.FC = () => {
  const [activeTab, setActiveTab] = useState<"overview" | "users" | "audit">("overview");
  const [users, setUsers] = useState<User[]>([]);
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [adminStats, setAdminStats] = useState<{ totalScans: number; totalReports: number }>({ totalScans: 0, totalReports: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [updatingUser, setUpdatingUser] = useState<number | null>(null);

  // Search & Filter state
  const [searchQuery, setSearchQuery] = useState("");
  const [roleFilter, setRoleFilter] = useState("all");

  // Create User modal state
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [newUsername, setNewUsername] = useState("");
  const [newEmail, setNewEmail] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState("user");
  const [creatingUser, setCreatingUser] = useState(false);

  // Delete user state
  const [deleteConfirmUserId, setDeleteConfirmUserId] = useState<number | null>(null);
  const [deletingUser, setDeletingUser] = useState(false);

  const currentUsername = localStorage.getItem("username");
  const userRole = localStorage.getItem("role");

  useEffect(() => {
    let active = true;
    if (userRole === "admin") {
      Promise.all([
        api.getAdminUsers().catch(() => []),
        api.getAuditLogs().catch(() => ({ events: [] })),
        api.getAdminStats().catch(() => ({ totalScans: 0, totalReports: 0 }))
      ])
        .then(([usersData, logsData, statsData]) => {
          if (active) {
            setUsers(usersData);
            setAuditLogs(logsData?.events || []);
            setAdminStats(statsData || { totalScans: 0, totalReports: 0 });
          }
        })
        .catch(() => {
          if (active) setError("Unauthorized access or failed to fetch admin data.");
        })
        .finally(() => {
          if (active) setLoading(false);
        });
    }
    return () => {
      active = false;
    };
  }, [userRole]);

  const handleRoleChange = async (userId: number, newRoleVal: string) => {
    setUpdatingUser(userId);
    setError("");
    setSuccess("");
    try {
      await api.updateAdminUserRole(userId, newRoleVal);
      setUsers(users.map((u) => (u.id === userId ? { ...u, role: newRoleVal } : u)));
      setSuccess(`User role updated to ${newRoleVal.toUpperCase()}`);
      setTimeout(() => setSuccess(""), 3000);
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      setError("Failed to update role: " + errMsg);
    } finally {
      setUpdatingUser(null);
    }
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreatingUser(true);
    setError("");
    setSuccess("");
    try {
      const newUser = await api.createAdminUser(newUsername.trim(), newEmail.trim().toLowerCase(), newPassword, newRole);
      setUsers([...users, newUser]);
      setIsCreateModalOpen(false);
      setNewUsername("");
      setNewEmail("");
      setNewPassword("");
      setNewRole("user");
      setSuccess(`Created user ${newUser.username} successfully.`);
      setTimeout(() => setSuccess(""), 3000);
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      setError("Failed to create user: " + errMsg);
    } finally {
      setCreatingUser(false);
    }
  };

  const handleDeleteUser = async (userId: number) => {
    setDeletingUser(true);
    setError("");
    setSuccess("");
    try {
      await api.deleteAdminUser(userId);
      setUsers(users.filter((u) => u.id !== userId));
      setDeleteConfirmUserId(null);
      setSuccess("User account deleted successfully.");
      setTimeout(() => setSuccess(""), 3000);
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      setError("Failed to delete user: " + errMsg);
      setDeleteConfirmUserId(null);
    } finally {
      setDeletingUser(false);
    }
  };

  if (userRole !== "admin") {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] space-y-4">
        <GlassCard className="p-8 text-center max-w-md">
          <span className="text-3xl block">🚫</span>
          <h2 className="text-lg font-black text-rose-400 mt-2">Access Denied</h2>
          <p className="text-xs text-slate-400 mt-1">
            You do not have administrative privileges to view this portal.
          </p>
        </GlassCard>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[65vh]">
        <CyberRadarLoader size="md" text="LOADING USER ACCOUNTS & AUDIT TRAIL" />
      </div>
    );
  }

  const filteredUsers = users.filter((user) => {
    const q = searchQuery.toLowerCase();
    const matchesSearch = user.username.toLowerCase().includes(q) || (user.email && user.email.toLowerCase().includes(q));
    const matchesRole = roleFilter === "all" || user.role === roleFilter;
    return matchesSearch && matchesRole;
  });

  return (
    <div className="max-w-6xl mx-auto space-y-8 animate-fade-in">
      
      {/* Header */}
      <PageHeader
        title="Security Administration"
        subtitle="System-level statistics, user role permissions, and platform audit logs"
        badge={
          <span className="px-3 py-1 bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 rounded-full text-xs font-mono font-bold">
            ADMINISTRATOR PRIVILEGES
          </span>
        }
        action={
          <Button variant="primary" icon={Plus} onClick={() => setIsCreateModalOpen(true)}>
            Add New User
          </Button>
        }
      />

      {error && (
        <div className="p-4 bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs rounded-2xl flex items-center gap-3">
          <AlertCircle className="w-5 h-5 shrink-0 text-rose-500" />
          <span>{error}</span>
        </div>
      )}

      {success && (
        <div className="p-4 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs rounded-2xl flex items-center gap-3">
          <CheckCircle2 className="w-5 h-5 shrink-0 text-emerald-500" />
          <span>{success}</span>
        </div>
      )}

      {/* System-Level Overview Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <GlassCard className="p-6 relative overflow-hidden group hover:border-cyan-500/40 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">
              TOTAL SCANS
            </span>
            <div className="w-8 h-8 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <Shield className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-4xl font-black font-mono text-slate-100">
              {adminStats.totalScans.toLocaleString()}
            </span>
            <span className="text-xs text-slate-400 font-mono">scans across system</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-2 font-mono">Real-time aggregate from MongoDB Atlas</p>
        </GlassCard>

        <GlassCard className="p-6 relative overflow-hidden group hover:border-violet-500/40 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">
              TOTAL REPORTS
            </span>
            <div className="w-8 h-8 rounded-xl bg-violet-500/10 border border-violet-500/30 flex items-center justify-center text-violet-400">
              <FileText className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-4xl font-black font-mono text-slate-100">
              {adminStats.totalReports.toLocaleString()}
            </span>
            <span className="text-xs text-slate-400 font-mono">generated compliance reports</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-2 font-mono">Real-time aggregate from MongoDB Atlas</p>
        </GlassCard>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-3 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveTab("users")}
          className={`px-4 py-2 text-xs font-mono font-bold rounded-xl transition-all cursor-pointer flex items-center gap-2 ${
            activeTab === "users"
              ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/30"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          <Users className="w-4 h-4" /> User Accounts ({users.length})
        </button>
        <button
          onClick={() => setActiveTab("audit")}
          className={`px-4 py-2 text-xs font-mono font-bold rounded-xl transition-all cursor-pointer flex items-center gap-2 ${
            activeTab === "audit"
              ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/30"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          <FileText className="w-4 h-4" /> Security Audit Trail ({auditLogs.length})
        </button>
      </div>

      {activeTab === "users" ? (
        <GlassCard className="p-6">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
            <div>
              <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200 font-mono flex items-center gap-2">
                <Shield className="w-4 h-4 text-cyan-400" /> Platform Role Access Control
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">Strict role model: User (standard access) and Admin (full administrative control)</p>
            </div>

            <div className="flex items-center gap-3">
              <div className="relative">
                <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                <input
                  type="text"
                  placeholder="Search user or email..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-9 pr-3 py-2 bg-slate-950/80 border border-slate-800 rounded-xl text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-sans"
                />
              </div>

              <select
                value={roleFilter}
                onChange={(e) => setRoleFilter(e.target.value)}
                className="px-3 py-2 bg-slate-950/80 border border-slate-800 rounded-xl text-xs text-slate-300 focus:outline-none focus:border-cyan-500 font-sans cursor-pointer"
              >
                <option value="all">All Roles</option>
                <option value="user">User</option>
                <option value="admin">Admin</option>
              </select>
            </div>
          </div>

          <div className="mt-4 overflow-x-auto">
            <table className="w-full text-left text-xs font-sans">
              <thead>
                <tr className="border-b border-slate-800 text-[11px] font-bold uppercase tracking-wider text-slate-400 font-mono">
                  <th className="pb-3 px-3">User ID</th>
                  <th className="pb-3 px-3">Account</th>
                  <th className="pb-3 px-3">Email Address</th>
                  <th className="pb-3 px-3">Role</th>
                  <th className="pb-3 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredUsers.map((u) => (
                  <tr key={u.id} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-3.5 px-3 font-mono text-slate-500">#{u.id}</td>
                    <td className="py-3.5 px-3">
                      <div className="flex items-center gap-2">
                        <UserIcon className="w-4 h-4 text-slate-400 shrink-0" />
                        <span className="font-bold text-slate-100">{u.username}</span>
                        {u.username === currentUsername && (
                          <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                            YOU
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-3.5 px-3">
                      <div className="flex items-center gap-1.5 text-slate-300 font-mono">
                        <Mail className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                        <span>{u.email || `${u.username}@aibughunter.local`}</span>
                      </div>
                    </td>
                    <td className="py-3.5 px-3 font-mono">
                      <select
                        value={u.role === "admin" ? "admin" : "user"}
                        onChange={(e) => handleRoleChange(u.id, e.target.value)}
                        disabled={updatingUser === u.id}
                        className={`px-2.5 py-1 rounded-lg text-xs font-semibold focus:outline-none cursor-pointer border ${
                          u.role === "admin"
                            ? "bg-violet-500/10 text-violet-300 border-violet-500/30"
                            : "bg-slate-950 text-slate-300 border-slate-800"
                        }`}
                      >
                        <option value="user">User</option>
                        <option value="admin">Admin</option>
                      </select>
                    </td>
                    <td className="py-3.5 px-3 text-right">
                      {u.username !== currentUsername && (
                        <button
                          onClick={() => setDeleteConfirmUserId(u.id)}
                          className="p-1.5 rounded-lg text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 border border-transparent hover:border-rose-500/20 transition-all cursor-pointer"
                          title="Delete User"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </GlassCard>
      ) : (
        <GlassCard className="p-6">
          <div className="flex items-center justify-between pb-4 border-b border-slate-800">
            <div>
              <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200 font-mono flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-cyan-400" /> Platform Security & Audit Trail
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">Immutable audit events recorded across authentication, role changes, and system access</p>
            </div>
            <span className="text-xs font-mono text-slate-400">Last 50 Events</span>
          </div>

          <div className="mt-4 overflow-x-auto">
            {auditLogs.length === 0 ? (
              <div className="py-8 text-center text-xs text-slate-500 font-mono">
                No recent security audit events recorded.
              </div>
            ) : (
              <table className="w-full text-left text-xs font-sans">
                <thead>
                  <tr className="border-b border-slate-800 text-[11px] font-bold uppercase tracking-wider text-slate-400 font-mono">
                    <th className="pb-3 px-3">Timestamp</th>
                    <th className="pb-3 px-3">Event Type</th>
                    <th className="pb-3 px-3">Description</th>
                    <th className="pb-3 px-3">User ID</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                  {auditLogs.map((log, i) => (
                    <tr key={i} className="hover:bg-slate-900/40 transition-colors">
                      <td className="py-3 px-3 text-slate-400">
                        {log.created_at ? new Date(log.created_at).toLocaleString() : "Recent"}
                      </td>
                      <td className="py-3 px-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          log.event_type?.includes("failed") || log.event_type?.includes("deleted")
                            ? "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                            : log.event_type?.includes("admin")
                            ? "bg-violet-500/10 text-violet-400 border border-violet-500/20"
                            : "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20"
                        }`}>
                          {log.event_type}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-slate-300 font-sans text-xs">
                        {log.description}
                      </td>
                      <td className="py-3 px-3 text-slate-500">
                        {log.user_id ? `#${log.user_id}` : "System / Anonymous"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </GlassCard>
      )}

      {/* Create User Modal */}
      <Modal
        isOpen={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        title="Provision New User Account"
        subtitle="Specify account credentials, email, and security role"
      >
        <form onSubmit={handleCreateUser} className="space-y-4">
          <div>
            <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1 font-mono">
              Username
            </label>
            <input
              type="text"
              value={newUsername}
              onChange={(e) => setNewUsername(e.target.value)}
              placeholder="e.g. security_auditor"
              className="w-full px-4 py-2.5 glass-input rounded-xl text-sm focus:outline-none"
              required
            />
          </div>

          <div>
            <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1 font-mono">
              Email Address
            </label>
            <input
              type="email"
              value={newEmail}
              onChange={(e) => setNewEmail(e.target.value)}
              placeholder="auditor@company.com"
              className="w-full px-4 py-2.5 glass-input rounded-xl text-sm focus:outline-none"
              required
            />
          </div>

          <div>
            <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1 font-mono">
              Password
            </label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="••••••••"
              className="w-full px-4 py-2.5 glass-input rounded-xl text-sm focus:outline-none"
              required
            />
          </div>

          <div>
            <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1 font-mono">
              Role Permission
            </label>
            <select
              value={newRole}
              onChange={(e) => setNewRole(e.target.value)}
              className="w-full px-4 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-sm text-slate-200 focus:outline-none cursor-pointer"
            >
              <option value="user">User (Standard Access)</option>
              <option value="admin">Admin (Full Administrative Privileges)</option>
            </select>
          </div>

          <div className="pt-4 flex justify-end gap-3 border-t border-slate-800">
            <Button type="button" variant="ghost" onClick={() => setIsCreateModalOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" icon={Plus} loading={creatingUser}>
              Create User Account
            </Button>
          </div>
        </form>
      </Modal>

      {/* Delete User Confirmation Modal */}
      <Modal
        isOpen={deleteConfirmUserId !== null}
        onClose={() => setDeleteConfirmUserId(null)}
        title="Confirm Account Deletion"
        subtitle="This action is permanent and revokes all system access."
      >
        <div className="space-y-4">
          <p className="text-xs text-slate-300">
            Are you sure you want to delete user account <strong className="text-rose-400 font-mono">#{deleteConfirmUserId}</strong>?
          </p>
          <div className="flex justify-end gap-3 pt-4 border-t border-slate-800">
            <Button variant="ghost" onClick={() => setDeleteConfirmUserId(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              icon={Trash2}
              loading={deletingUser}
              onClick={() => deleteConfirmUserId && handleDeleteUser(deleteConfirmUserId)}
            >
              Delete User Account
            </Button>
          </div>
        </div>
      </Modal>

    </div>
  );
};

export default AdminPanel;
