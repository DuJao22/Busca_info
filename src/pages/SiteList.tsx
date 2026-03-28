import React, { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { Trash2, Download, AlertTriangle, X, FileJson, Eye } from 'lucide-react';
import { Link } from 'react-router-dom';

export default function SiteList() {
  const { token } = useAuth();
  const [sites, setSites] = useState([]);
  const [isLoading, setIsLoading] = useState(true);

  // Modal states
  const [deleteModal, setDeleteModal] = useState<{ isOpen: boolean; id: number | null }>({ isOpen: false, id: null });
  const [alertModal, setAlertModal] = useState<{ isOpen: boolean; message: string }>({ isOpen: false, message: '' });
  const [viewModal, setViewModal] = useState<{ isOpen: boolean; site: any }>({ isOpen: false, site: null });

  const fetchSites = async () => {
    try {
      const res = await fetch('/api/sites', { headers: { Authorization: `Bearer ${token}` } });
      if (!res.ok) throw new Error('Failed to fetch sites');
      const data = await res.json();
      setSites(data);
    } catch (error) {
      console.error('Error fetching sites:', error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchSites();
  }, [token]);

  const confirmDelete = async () => {
    if (!deleteModal.id) return;

    try {
      await fetch(`/api/sites/${deleteModal.id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` }
      });
      setDeleteModal({ isOpen: false, id: null });
      fetchSites();
    } catch (error) {
      setDeleteModal({ isOpen: false, id: null });
      setAlertModal({ isOpen: true, message: 'Erro ao excluir análise' });
    }
  };

  const handleDownloadJson = async (filename: string) => {
    try {
      const res = await fetch(`/api/analyze/download/${filename}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (!res.ok) throw new Error('Falha ao baixar arquivo');
      
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Download error:', error);
      setAlertModal({ isOpen: true, message: 'Erro ao baixar o arquivo JSON.' });
    }
  };

  if (isLoading) {
    return <div className="flex justify-center py-12"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-emerald-600"></div></div>;
  }

  return (
    <div className="space-y-6">
      {/* View Details Modal */}
      {viewModal.isOpen && viewModal.site && (
        <div className="fixed inset-0 z-50 flex items-center justify-center overflow-y-auto overflow-x-hidden bg-black/50 p-4">
          <div className="relative w-full max-w-2xl rounded-2xl bg-white p-6 shadow-xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-4 border-b pb-4">
              <h3 className="text-xl font-semibold text-zinc-900">Detalhes da Análise</h3>
              <button onClick={() => setViewModal({ isOpen: false, site: null })} className="text-zinc-400 hover:text-zinc-600">
                <X className="h-6 w-6" />
              </button>
            </div>
            <div className="space-y-4">
              <div>
                <h4 className="text-sm font-medium text-zinc-500">Nome da Empresa</h4>
                <p className="mt-1 text-base text-zinc-900">{viewModal.site.name}</p>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <h4 className="text-sm font-medium text-zinc-500">Telefone</h4>
                  <p className="mt-1 text-base text-zinc-900">{viewModal.site.phone || 'N/A'}</p>
                </div>
                <div>
                  <h4 className="text-sm font-medium text-zinc-500">Cidade</h4>
                  <p className="mt-1 text-base text-zinc-900">{viewModal.site.city || 'N/A'}</p>
                </div>
              </div>
              <div>
                <h4 className="text-sm font-medium text-zinc-500">Endereço</h4>
                <p className="mt-1 text-base text-zinc-900">{viewModal.site.address || 'N/A'}</p>
              </div>
              <div>
                <h4 className="text-sm font-medium text-zinc-500">Descrição</h4>
                <p className="mt-1 text-base text-zinc-900">{viewModal.site.description || 'N/A'}</p>
              </div>
              <div>
                <h4 className="text-sm font-medium text-zinc-500">Serviços</h4>
                <p className="mt-1 text-base text-zinc-900">{viewModal.site.services || 'N/A'}</p>
              </div>
              {viewModal.site.map_link && (
                <div>
                  <h4 className="text-sm font-medium text-zinc-500">Link do Google Maps</h4>
                  <a href={viewModal.site.map_link} target="_blank" rel="noreferrer" className="mt-1 text-base text-emerald-600 hover:underline break-all">
                    {viewModal.site.map_link}
                  </a>
                </div>
              )}
              <div>
                <h4 className="text-sm font-medium text-zinc-500">Arquivo JSON</h4>
                <div className="mt-1 flex items-center gap-2">
                  <FileJson className="w-4 h-4 text-emerald-600" />
                  <span className="text-base text-zinc-900">{viewModal.site.slug}</span>
                </div>
              </div>
            </div>
            <div className="mt-6 flex justify-end gap-3 border-t pt-4">
              <button
                onClick={() => handleDownloadJson(viewModal.site.slug)}
                className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-700 flex items-center gap-2"
              >
                <Download className="w-4 h-4" />
                Baixar JSON
              </button>
              <button
                onClick={() => setViewModal({ isOpen: false, site: null })}
                className="rounded-lg border border-zinc-300 px-4 py-2 text-sm font-medium text-zinc-700 hover:bg-zinc-50"
              >
                Fechar
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Alert Modal */}
      {alertModal.isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center overflow-y-auto overflow-x-hidden bg-black/50 p-4">
          <div className="relative w-full max-w-md rounded-2xl bg-white p-6 shadow-xl">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-zinc-900">Aviso</h3>
              <button onClick={() => setAlertModal({ isOpen: false, message: '' })} className="text-zinc-400 hover:text-zinc-600">
                <X className="h-5 w-5" />
              </button>
            </div>
            <p className="text-zinc-600 mb-6">{alertModal.message}</p>
            <div className="flex justify-end">
              <button
                onClick={() => setAlertModal({ isOpen: false, message: '' })}
                className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-700"
              >
                OK
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deleteModal.isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center overflow-y-auto overflow-x-hidden bg-black/50 p-4">
          <div className="relative w-full max-w-md rounded-2xl bg-white p-6 shadow-xl">
            <div className="flex items-center gap-4 mb-4">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-red-100">
                <AlertTriangle className="h-6 w-6 text-red-600" />
              </div>
              <h3 className="text-lg font-semibold text-zinc-900">Excluir Análise</h3>
            </div>
            <p className="text-zinc-600 mb-6">Tem certeza que deseja excluir esta análise? O arquivo JSON será apagado.</p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setDeleteModal({ isOpen: false, id: null })}
                className="rounded-lg border border-zinc-300 px-4 py-2 text-sm font-medium text-zinc-700 hover:bg-zinc-50"
              >
                Cancelar
              </button>
              <button
                onClick={confirmDelete}
                className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700"
              >
                Excluir
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <h1 className="text-2xl font-bold text-zinc-900">Análises Salvas</h1>
        <Link
          to="/create"
          className="inline-flex items-center justify-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-emerald-600 hover:bg-emerald-700"
        >
          Nova Análise
        </Link>
      </div>

      <div className="bg-white shadow rounded-lg overflow-hidden">
        {/* Mobile View */}
        <div className="block sm:hidden">
          <ul className="divide-y divide-zinc-200">
            {sites.length === 0 ? (
              <li className="px-4 py-8 text-center text-sm text-zinc-500">
                <p className="mb-4">Nenhuma análise realizada ainda.</p>
                <Link to="/create" className="text-emerald-600 font-medium hover:underline">Faça sua primeira análise</Link>
              </li>
            ) : (
              sites.map((site: any) => (
                <li key={site.id} className="px-4 py-4">
                  <div className="flex items-center justify-between">
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-medium text-zinc-900 truncate">{site.name}</p>
                      <p className="text-xs text-zinc-500 truncate">{site.city}</p>
                    </div>
                    <div className="ml-2 flex-shrink-0 flex">
                      <p className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-emerald-100 text-emerald-800">
                        {new Date(site.created_at).toLocaleDateString('pt-BR')}
                      </p>
                    </div>
                  </div>
                  <div className="mt-2 flex justify-between items-center">
                    <div className="flex items-center text-sm text-zinc-500">
                      <FileJson className="flex-shrink-0 mr-1.5 h-4 w-4 text-emerald-600" />
                      <span className="truncate max-w-[150px]">{site.slug}</span>
                    </div>
                    <div className="flex items-center space-x-3">
                      <button onClick={() => setViewModal({ isOpen: true, site })} className="text-blue-600 hover:text-blue-900 flex items-center p-1" title="Ver Detalhes">
                        <Eye className="w-5 h-5" />
                      </button>
                      <button onClick={() => handleDownloadJson(site.slug)} className="text-emerald-600 hover:text-emerald-900 flex items-center p-1" title="Baixar JSON">
                        <Download className="w-5 h-5" />
                      </button>
                      <button onClick={() => setDeleteModal({ isOpen: true, id: site.id })} className="text-red-600 hover:text-red-900 flex items-center p-1" title="Excluir">
                        <Trash2 className="w-5 h-5" />
                      </button>
                    </div>
                  </div>
                </li>
              ))
            )}
          </ul>
        </div>

        {/* Desktop View */}
        <div className="hidden sm:block overflow-x-auto">
          <table className="min-w-full divide-y divide-zinc-200">
            <thead className="bg-zinc-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">Empresa</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">Arquivo</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">Data</th>
                <th className="px-6 py-3 text-right text-xs font-medium text-zinc-500 uppercase tracking-wider">Ações</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-zinc-200">
              {sites.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-6 py-12 text-center text-sm text-zinc-500">
                    <p className="mb-4">Nenhuma análise realizada ainda.</p>
                    <Link to="/create" className="text-emerald-600 font-medium hover:underline">Faça sua primeira análise</Link>
                  </td>
                </tr>
              ) : (
                sites.map((site: any) => {
                  return (
                    <tr key={site.id} className="hover:bg-zinc-50">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="text-sm font-medium text-zinc-900">{site.name}</div>
                        <div className="text-sm text-zinc-500">{site.city}</div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center space-x-2">
                          <FileJson className="w-4 h-4 text-emerald-600" />
                          <span className="text-sm text-zinc-600">{site.slug}</span>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-zinc-500">
                        {new Date(site.created_at).toLocaleDateString('pt-BR')}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                        <div className="flex items-center justify-end space-x-3">
                          <button onClick={() => setViewModal({ isOpen: true, site })} className="text-blue-600 hover:text-blue-900 flex items-center" title="Ver Detalhes">
                            <Eye className="w-4 h-4" />
                          </button>
                          <button onClick={() => handleDownloadJson(site.slug)} className="text-emerald-600 hover:text-emerald-900 flex items-center" title="Baixar JSON">
                            <Download className="w-4 h-4" />
                          </button>
                          <button onClick={() => setDeleteModal({ isOpen: true, id: site.id })} className="text-red-600 hover:text-red-900 flex items-center" title="Excluir">
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
