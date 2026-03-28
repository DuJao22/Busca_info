import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { Users, Plus, Trash2, Key, Copy, CheckCircle } from 'lucide-react';

export default function UsersPage() {
  const { token, user } = useAuth();
  const [users, setUsers] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isCreating, setIsCreating] = useState(false);
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState('user');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      const res = await fetch('/api/users', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setUsers(data);
      }
    } catch (error) {
      console.error('Error fetching users:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch('/api/users', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ username: newUsername, password: newPassword, role: newRole })
      });
      if (res.ok) {
        setNewUsername('');
        setNewPassword('');
        setNewRole('user');
        setIsCreating(false);
        fetchUsers();
      } else {
        const data = await res.json();
        alert(data.error || 'Erro ao criar usuário');
      }
    } catch (error) {
      console.error('Error creating user:', error);
      alert('Erro de conexão ao criar usuário');
    }
  };

  const handleDeleteUser = async (id: number) => {
    if (!confirm('Tem certeza que deseja excluir este usuário?')) return;
    try {
      const res = await fetch(`/api/users/${id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        fetchUsers();
      } else {
        alert('Erro ao excluir usuário');
      }
    } catch (error) {
      console.error('Error deleting user:', error);
    }
  };

  const handleCopyKey = (key: string) => {
    navigator.clipboard.writeText(key);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  if (user?.role !== 'admin') {
    return <div className="p-6 text-center text-zinc-500">Acesso negado.</div>;
  }

  return (
    <div className="max-w-6xl mx-auto py-6">
      <div className="md:flex md:items-center md:justify-between mb-8">
        <div className="flex-1 min-w-0">
          <h2 className="text-2xl font-bold leading-7 text-zinc-900 sm:text-3xl sm:truncate flex items-center gap-2">
            <Users className="w-8 h-8 text-zinc-400" />
            Gerenciamento de Usuários
          </h2>
        </div>
        <div className="mt-4 flex md:mt-0 md:ml-4">
          <button
            onClick={() => setIsCreating(!isCreating)}
            className="ml-3 inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-emerald-600 hover:bg-emerald-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-emerald-500"
          >
            <Plus className="-ml-1 mr-2 h-5 w-5" />
            Novo Usuário
          </button>
        </div>
      </div>

      {isCreating && (
        <div className="bg-white shadow rounded-lg mb-8 p-6 border border-zinc-200">
          <h3 className="text-lg font-medium text-zinc-900 mb-4">Criar Novo Usuário</h3>
          <form onSubmit={handleCreateUser} className="space-y-4 sm:flex sm:space-y-0 sm:gap-4 sm:items-end">
            <div className="flex-1">
              <label className="block text-sm font-medium text-zinc-700">Usuário</label>
              <input
                type="text"
                required
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
                className="mt-1 block w-full border border-zinc-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-emerald-500 focus:border-emerald-500 sm:text-sm"
              />
            </div>
            <div className="flex-1">
              <label className="block text-sm font-medium text-zinc-700">Senha</label>
              <input
                type="password"
                required
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="mt-1 block w-full border border-zinc-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-emerald-500 focus:border-emerald-500 sm:text-sm"
              />
            </div>
            <div className="w-48">
              <label className="block text-sm font-medium text-zinc-700">Função</label>
              <select
                value={newRole}
                onChange={(e) => setNewRole(e.target.value)}
                className="mt-1 block w-full bg-white border border-zinc-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-emerald-500 focus:border-emerald-500 sm:text-sm"
              >
                <option value="user">Usuário</option>
                <option value="admin">Administrador</option>
              </select>
            </div>
            <button
              type="submit"
              className="w-full sm:w-auto inline-flex justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-emerald-600 hover:bg-emerald-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-emerald-500"
            >
              Salvar
            </button>
          </form>
        </div>
      )}

      <div className="bg-white shadow rounded-lg overflow-hidden">
        <ul className="divide-y divide-zinc-200">
          {isLoading ? (
            <li className="p-6 text-center text-zinc-500">Carregando usuários...</li>
          ) : users.length === 0 ? (
            <li className="p-6 text-center text-zinc-500">Nenhum usuário encontrado.</li>
          ) : (
            users.map((u) => (
              <li key={u.id} className="p-6 hover:bg-zinc-50 transition-colors">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="flex items-center gap-3">
                      <p className="text-sm font-medium text-emerald-600 truncate">{u.username}</p>
                      <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                        u.role === 'admin' ? 'bg-purple-100 text-purple-800' : 'bg-green-100 text-green-800'
                      }`}>
                        {u.role === 'admin' ? 'Admin' : 'Usuário'}
                      </span>
                    </div>
                    <div className="mt-2 flex items-center text-sm text-zinc-500">
                      <Key className="flex-shrink-0 mr-1.5 h-4 w-4 text-zinc-400" />
                      <span className="truncate max-w-xs">{u.api_key}</span>
                      <button
                        onClick={() => handleCopyKey(u.api_key)}
                        className="ml-2 text-zinc-400 hover:text-emerald-600 transition-colors"
                        title="Copiar API Key"
                      >
                        {copiedKey === u.api_key ? (
                          <CheckCircle className="h-4 w-4 text-emerald-500" />
                        ) : (
                          <Copy className="h-4 w-4" />
                        )}
                      </button>
                    </div>
                  </div>
                  <div className="flex items-center gap-4">
                    {u.id !== user.id && (
                      <button
                        onClick={() => handleDeleteUser(u.id)}
                        className="text-red-600 hover:text-red-900 transition-colors p-2 rounded-full hover:bg-red-50"
                        title="Excluir Usuário"
                      >
                        <Trash2 className="w-5 h-5" />
                      </button>
                    )}
                  </div>
                </div>
              </li>
            ))
          )}
        </ul>
      </div>
    </div>
  );
}
