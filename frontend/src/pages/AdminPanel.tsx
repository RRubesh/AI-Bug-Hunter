import React, { useEffect, useState } from "react";
import { api } from "../services/api";
import type { User } from "../services/api";
import { PageHeader } from "../components/ui/PageHeader";
import { CyberRadarLoader } from "../components/CyberRadarLoader";
import { GlassCard } from "../components/ui/GlassCard";
import { Button } from "../components/ui/Button";
import { Modal } from "../components/ui/Modal";
import { 
  Users, AlertCircle, Plus, Trash2, Search, User as UserIcon
} from "lucide-react";

export const AdminPanel: React.FC = () => {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [updatingUser, setUpdatingUser] = useState<number | null>(null);

  // Search & Filter state
  const [searchQuery, setSearchQuery] = useState("");
  const [roleFilter, setRoleFilter] = useState("all");

  // Create User modal state
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [newUsername, setNewUsername] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState("developer");
  const [creatingUser, setCreatingUser] = useState(false);

  // Delete user state
  const [deleteConfirmUserId, setDeleteConfirmUserId] = useState<number | null>(null);
  const [deletingUser, setDeletingUser] = useState(false);

  const currentUsername = localStorage.getItem("username");
  const userRole = localStorage.getItem("role");

  useEffect(() => {
    let active = true;
    if (userRole === "admin") {
      api.getAdminUsers()
        .then((data) => {
          if (active) setUsers(data);
        })
        .catch(() => {
          if (active) setError("Unauthorized access or failed to fetch users list.");
        })
        .finally(() => {
          if (active) setLoading(false);
        });
    }
    return () => {
      active = false;
    };
  }, [userRole]);

  const handleRoleChange = async (userId: number, newRole: string) => {
    setUpdatingUser(userId);
    try {
      await api.updateAdminUserRole(userId, newRole);
      setUsers(users.map((u) => (u.id === userId ? { ...u, role: newRole } : u)));
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      alert("Failed to update role: " + errMsg);
    } finally {
      setUpdatingUser(null);
    }
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreatingUser(true);
    setError("");
    try {
      const newUser = await api.createAdminUser(newUsername, newPassword, newRole);
      setUsers([...users, newUser]);
      setIsCreateModalOpen(false);
      setNewUsername("");
      setNewPassword("");
      setNewRole("developer");
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
    try {
      await api.deleteAdminUser(userId);
      setUsers(users.filter((u) => u.id !== userId));
      setDeleteConfirmUserId(null);
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
            You do not have administrative privileges to view this page.
          </p>
        </GlassCard>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[65vh]">
        <CyberRadarLoader size="md" text="LOADING USER ACCOUNTS & PERMISSIONS" />
      </div>
    );
  }

  const filteredUsers = users.filter((user) => {
    const matchesSearch = user.username.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesRole = roleFilter === "all" || user.role === roleFilter;
    return matchesSearch && matchesRole;
  });

  return (
    <div className="max-w-6xl mx-auto space-y-8 animate-fade-in">
      
      {/* Header */}
      <PageHeader
        title="Admin Administration & User Roles"
        subtitle="Manage developer accounts, access levels, and security authorization"
        badge={
          <span className="px-3 py-1 bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 rounded-full text-xs font-mono font-bold">
            {users.length} Registered Accounts
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

      {/* Users Data Table Panel */}
      <GlassCard className="p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
          <div>
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200 font-mono flex items-center gap-2">
              <Users className="w-4 h-4 text-cyan-400" /> Registered User Accounts
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">Control role privileges (Admin, Paid, Developer)</p>
          </div>

          <div className="flex items-center gap-3">
            <div className="relative">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search username..."
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
              <option value="admin">Admin</option>
              <option value="paid">Paid</option>
              <option value="developer">Developer</option>
            </select>
          </div>
        </div>

        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-left text-xs font-sans">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] font-bold uppercase tracking-wider text-slate-400 font-mono">
                <th className="pb-3 px-3">User ID</th>
                <th className="pb-3 px-3">Username</th>
                <th className="pb-3 px-3">Role</th>
                <th className="pb-3 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredUsers.map((u) => (
                <tr key={u.id} className="hover:bg-slate-900/40 transition-colors">
                  <td className="py-3 px-3 font-mono text-slate-500">#{u.id}</td>
                  <td className="py-3 px-3">
                    <div className="flex items-center gap-2">
                      <UserIcon className="w-4 h-4 text-slate-400" />
                      <span className="font-bold text-slate-100">{u.username}</span>
                      {u.username === currentUsername && (
                        <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                          YOU
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="py-3 px-3 font-mono">
                    <select
                      value={u.role}
                      onChange={(e) => handleRoleChange(u.id, e.target.value)}
                      disabled={updatingUser === u.id}
                      className="px-2.5 py-1 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500 cursor-pointer"
                    >
                      <option value="developer">Developer</option>
                      <option value="paid">Paid User</option>
                      <option value="admin">Admin</option>
                    </select>
                  </td>
                  <td className="py-3 px-3 text-right">
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

      {/* Create User Modal */}
      <Modal
        isOpen={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        title="Register New Developer Account"
        subtitle="Provide credentials and assign platform authorization role"
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
              placeholder="new_developer"
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
              Initial Role
            </label>
            <select
              value={newRole}
              onChange={(e) => setNewRole(e.target.value)}
              className="w-full px-4 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-sm text-slate-200 focus:outline-none cursor-pointer"
            >
              <option value="developer">Developer</option>
              <option value="paid">Paid User</option>
              <option value="admin">Admin</option>
            </select>
          </div>

          <div className="pt-4 flex justify-end gap-3 border-t border-slate-800">
            <Button type="button" variant="ghost" onClick={() => setIsCreateModalOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" icon={Plus} loading={creatingUser}>
              Create Account
            </Button>
          </div>
        </form>
      </Modal>

      {/* Delete User Confirmation Modal */}
      <Modal
        isOpen={deleteConfirmUserId !== null}
        onClose={() => setDeleteConfirmUserId(null)}
        title="Confirm User Deletion"
        subtitle="This action is permanent and removes all user access rights."
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
