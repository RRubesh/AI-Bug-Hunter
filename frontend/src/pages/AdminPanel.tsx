import React, { useEffect, useState } from "react";
import { api } from "../services/api";
import type { User } from "../services/api";
import { 
  Users, UserCheck, RefreshCw, AlertCircle, Plus, Trash2, 
  Search, Filter, Shield, User as UserIcon, X 
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

  const fetchUsers = async () => {
    setLoading(true);
    setError("");
    try {
      const data = await api.getAdminUsers();
      setUsers(data);
    } catch {
      setError("Unauthorized access or failed to fetch users list.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    let active = true;
    (async () => {
      await Promise.resolve();
      if (active && userRole === "admin") {
        fetchUsers();
      }
    })();
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

  // Client-side access guard
  if (userRole !== "admin") {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] space-y-4">
        <div className="p-6 glass-panel rounded-xl border border-rose-500/20 bg-rose-500/5 text-center max-w-md animate-fade-in">
          <span className="text-3xl block">🚫</span>
          <h2 className="text-lg font-black text-rose-400 mt-2">Access Denied</h2>
          <p className="text-xs text-slate-400 mt-1">
            You do not have administrative privileges to view this page.
          </p>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[50vh]">
        <div className="w-10 h-10 border-4 border-slate-800 border-t-rose-500 rounded-full animate-spin"></div>
      </div>
    );
  }

  // Filtered users lists
  const filteredUsers = users.filter((user) => {
    const matchesSearch = user.username.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesRole = roleFilter === "all" || user.role === roleFilter;
    return matchesSearch && matchesRole;
  });

  const totalUsers = users.length;
  const adminCount = users.filter((u) => u.role === "admin").length;
  const paidCount = users.filter((u) => u.role === "paid").length;
  const developerCount = users.filter((u) => u.role === "developer").length;

  return (
    <div className="max-w-4xl mx-auto space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-black text-slate-100 tracking-tight">User Management Dashboard</h1>
          <p className="text-xs text-slate-400 mt-1">
            Manage developer accounts, authorization levels, and roles within the SAST engine.
          </p>
        </div>
        <button
          onClick={fetchUsers}
          className="p-2 bg-slate-900 border border-slate-850 hover:bg-slate-850 hover:border-slate-800 text-slate-400 rounded-lg cursor-pointer transition-colors"
          title="Refresh User List"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {error && (
        <div className="p-3.5 bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs rounded-lg flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-5">
        <div className="p-5 glass-panel rounded-xl border border-slate-850 flex items-center justify-between hover:border-slate-800 transition-all">
          <div>
            <span className="text-[10px] text-slate-500 font-bold block uppercase tracking-wider">Total Users</span>
            <span className="text-3xl font-black text-slate-100 mt-1 block">{totalUsers}</span>
          </div>
          <div className="p-3 bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 rounded-xl">
            <Users className="w-5 h-5" />
          </div>
        </div>

        <div className="p-5 glass-panel rounded-xl border border-slate-850 flex items-center justify-between hover:border-slate-800 transition-all">
          <div>
            <span className="text-[10px] text-slate-500 font-bold block uppercase tracking-wider">Administrators</span>
            <span className="text-3xl font-black text-rose-400 mt-1 block">{adminCount}</span>
          </div>
          <div className="p-3 bg-rose-500/10 text-rose-400 border border-rose-500/20 rounded-xl">
            <Shield className="w-5 h-5" />
          </div>
        </div>

        <div className="p-5 glass-panel rounded-xl border border-slate-850 flex items-center justify-between hover:border-slate-800 transition-all">
          <div>
            <span className="text-[10px] text-slate-500 font-bold block uppercase tracking-wider">Paid Users</span>
            <span className="text-3xl font-black text-amber-400 mt-1 block">{paidCount}</span>
          </div>
          <div className="p-3 bg-amber-500/10 text-amber-400 border border-amber-500/20 rounded-xl">
            <Shield className="w-5 h-5 text-amber-400" />
          </div>
        </div>

        <div className="p-5 glass-panel rounded-xl border border-slate-850 flex items-center justify-between hover:border-slate-800 transition-all">
          <div>
            <span className="text-[10px] text-slate-500 font-bold block uppercase tracking-wider">Developers</span>
            <span className="text-3xl font-black text-emerald-400 mt-1 block">{developerCount}</span>
          </div>
          <div className="p-3 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-xl">
            <UserIcon className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row gap-4 items-center justify-between bg-slate-955/60 p-4 border border-slate-900 rounded-xl">
        <div className="relative w-full sm:max-w-xs">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search by username..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-slate-950 border border-slate-850 hover:border-slate-800 text-slate-200 text-xs rounded-lg focus:outline-none focus:border-cyan-500 transition-colors"
          />
        </div>

        <div className="flex items-center gap-3 w-full sm:w-auto justify-end">
          <div className="flex items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-slate-500" />
            <select
              value={roleFilter}
              onChange={(e) => setRoleFilter(e.target.value)}
              className="px-3 py-2 bg-slate-950 border border-slate-850 text-slate-350 text-xs rounded-lg focus:outline-none focus:border-cyan-500 cursor-pointer"
            >
              <option value="all">All Roles</option>
              <option value="admin">Admins</option>
              <option value="paid">Paid Users</option>
              <option value="developer">Developers</option>
            </select>
          </div>

          <button
            onClick={() => setIsCreateModalOpen(true)}
            className="flex items-center gap-1.5 px-4 py-2 bg-gradient-to-r from-cyan-500 to-emerald-500 hover:from-cyan-600 hover:to-emerald-600 text-slate-950 hover:text-slate-900 text-xs font-black rounded-lg cursor-pointer transition-all shadow-lg shadow-cyan-500/10"
          >
            <Plus className="w-4 h-4 stroke-[3px]" />
            <span>Add User</span>
          </button>
        </div>
      </div>

      {/* Users Database Grid */}
      <div className="p-5 glass-panel rounded-xl border border-slate-850 space-y-4">
        <div className="flex items-center gap-2 border-b border-slate-900 pb-2.5">
          <Users className="w-4 h-4 text-cyan-500" />
          <h2 className="text-xs font-bold text-slate-300 uppercase tracking-wider">Registered Users</h2>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="text-slate-500 border-b border-slate-900 pb-2">
                <th className="pb-2 font-bold uppercase">User ID</th>
                <th className="pb-2 font-bold uppercase">Username</th>
                <th className="pb-2 font-bold uppercase">Role</th>
                <th className="pb-2 font-bold uppercase">Created At</th>
                <th className="pb-2 font-bold uppercase text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredUsers.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-slate-500 text-xs">
                    No users found matching current filters.
                  </td>
                </tr>
              ) : (
                filteredUsers.map((user) => (
                  <tr key={user.id} className="border-b border-slate-900/60 hover:bg-slate-900/30 transition-colors">
                    <td className="py-3 text-slate-500 font-mono">#{user.id}</td>
                    <td className="py-3 font-bold text-slate-300 flex items-center gap-1.5">
                      <UserCheck className="w-3.5 h-3.5 text-slate-500" />
                      {user.username}
                    </td>
                    <td className="py-3 font-semibold text-slate-400">
                      <span className={`px-2 py-0.5 rounded text-[9px] font-bold border ${
                        user.role === "admin" 
                          ? "bg-rose-500/10 text-rose-400 border-rose-500/25" 
                          : user.role === "paid"
                          ? "bg-amber-500/10 text-amber-400 border-amber-500/25"
                          : "bg-blue-500/10 text-blue-400 border-blue-500/25"
                      }`}>
                        {user.role.toUpperCase()}
                      </span>
                    </td>
                    <td className="py-3 text-slate-500 font-mono">
                      {new Date(user.created_at).toLocaleDateString()}
                    </td>
                    <td className="py-3 text-right flex items-center justify-end gap-2.5">
                      <select
                        value={user.role}
                        onChange={(e) => handleRoleChange(user.id, e.target.value)}
                        disabled={updatingUser === user.id}
                        className="px-2 py-1 bg-slate-950 border border-slate-850 text-slate-300 text-[10px] rounded focus:outline-none focus:border-blue-500 cursor-pointer disabled:opacity-50"
                      >
                        <option value="developer">Developer</option>
                        <option value="paid">Paid</option>
                        <option value="admin">Admin</option>
                      </select>

                      {user.username !== currentUsername ? (
                        <button
                          onClick={() => setDeleteConfirmUserId(user.id)}
                          className="p-1.5 bg-slate-950 border border-slate-850 hover:bg-rose-500/10 hover:border-rose-500/30 text-slate-500 hover:text-rose-400 rounded transition-all cursor-pointer"
                          title="Delete User"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      ) : (
                        <span className="text-[10px] text-slate-500 font-semibold px-2 py-0.5 bg-slate-900 border border-slate-850 rounded">
                          You
                        </span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create User Modal */}
      {isCreateModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
          <div className="w-full max-w-sm glass-panel border border-slate-850 p-6 rounded-xl space-y-4 relative">
            <button
              onClick={() => {
                setIsCreateModalOpen(false);
                setNewUsername("");
                setNewPassword("");
                setNewRole("developer");
                setError("");
              }}
              className="absolute top-4 right-4 p-1 hover:bg-slate-900 rounded-lg text-slate-500 hover:text-slate-300 transition-colors cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>

            <div className="space-y-1">
              <h3 className="text-sm font-black text-slate-100 tracking-tight">Create New User Account</h3>
              <p className="text-[10px] text-slate-400">
                Register a new developer or administrator in the SAST environment.
              </p>
            </div>

            <form onSubmit={handleCreateUser} className="space-y-3.5">
              <div className="space-y-1">
                <label className="text-[10px] text-slate-400 font-bold uppercase tracking-wider block">Username</label>
                <input
                  type="text"
                  required
                  placeholder="Enter username..."
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-850 hover:border-slate-800 focus:border-cyan-500 text-slate-200 text-xs rounded-lg focus:outline-none transition-colors"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[10px] text-slate-400 font-bold uppercase tracking-wider block">Password</label>
                <input
                  type="password"
                  required
                  placeholder="Enter secure password..."
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-850 hover:border-slate-800 focus:border-cyan-500 text-slate-200 text-xs rounded-lg focus:outline-none transition-colors"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[10px] text-slate-400 font-bold uppercase tracking-wider block">Authorization Role</label>
                <select
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-850 focus:border-cyan-500 text-slate-350 text-xs rounded-lg focus:outline-none cursor-pointer"
                >
                  <option value="developer">Developer</option>
                  <option value="paid">Paid</option>
                  <option value="admin">Admin</option>
                </select>
              </div>

              <button
                type="submit"
                disabled={creatingUser}
                className="w-full flex items-center justify-center gap-2 py-2.5 bg-gradient-to-r from-cyan-500 to-emerald-500 hover:from-cyan-600 hover:to-emerald-600 disabled:opacity-50 text-slate-950 text-xs font-black rounded-lg cursor-pointer transition-all shadow-lg shadow-cyan-500/10"
              >
                {creatingUser ? (
                  <div className="w-4 h-4 border-2 border-slate-950 border-t-transparent rounded-full animate-spin"></div>
                ) : (
                  <span>Register Account</span>
                )}
              </button>
            </form>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deleteConfirmUserId !== null && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
          <div className="w-full max-w-sm glass-panel border border-slate-850 p-6 rounded-xl space-y-4 relative text-center">
            <div className="w-12 h-12 bg-rose-500/10 border border-rose-500/20 text-rose-400 rounded-full flex items-center justify-center mx-auto">
              <AlertCircle className="w-6 h-6" />
            </div>

            <div className="space-y-1">
              <h3 className="text-sm font-black text-slate-100 tracking-tight">Confirm User Deletion</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Are you absolutely sure you want to delete this user? This action will permanently remove all their uploaded projects, active scans, and vulnerability reports. This action cannot be undone.
              </p>
            </div>

            <div className="flex items-center gap-3 pt-2">
              <button
                onClick={() => setDeleteConfirmUserId(null)}
                className="flex-1 py-2 bg-slate-900 border border-slate-850 hover:bg-slate-850 hover:border-slate-800 text-slate-350 hover:text-slate-200 text-xs font-bold rounded-lg cursor-pointer transition-all"
              >
                Cancel
              </button>
              <button
                onClick={() => handleDeleteUser(deleteConfirmUserId)}
                disabled={deletingUser}
                className="flex-1 py-2 bg-rose-500 hover:bg-rose-600 disabled:opacity-50 text-slate-950 text-xs font-black rounded-lg cursor-pointer transition-all shadow-lg shadow-rose-500/10"
              >
                {deletingUser ? (
                  <div className="w-4 h-4 border-2 border-slate-950 border-t-transparent rounded-full animate-spin mx-auto"></div>
                ) : (
                  <span>Confirm Delete</span>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
export default AdminPanel;
