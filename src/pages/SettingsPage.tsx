import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { Settings, Key, CheckCircle, AlertCircle } from 'lucide-react';

export default function SettingsPage() {
  const { token, user } = useAuth();
  const [apiKey, setApiKey] = useState('');
  const [isSaving, setIsSaving] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error', text: string } | null>(null);

  useEffect(() => {
    fetchSettings();
  }, []);

  const fetchSettings = async () => {
    try {
      const res = await fetch('/api/settings', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        if (data.gemini_api_key) {
          setApiKey(data.gemini_api_key);
        }
      }
    } catch (error) {
      console.error('Error fetching settings:', error);
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    setMessage(null);

    try {
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ gemini_api_key: apiKey })
      });

      const data = await res.json();

      if (res.ok) {
        setMessage({ type: 'success', text: 'Configurações salvas com sucesso!' });
      } else {
        setMessage({ type: 'error', text: data.error || 'Erro ao salvar configurações.' });
      }
    } catch (error) {
      setMessage({ type: 'error', text: 'Erro de conexão ao salvar configurações.' });
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto py-6">
      <div className="md:flex md:items-center md:justify-between mb-8">
        <div className="flex-1 min-w-0">
          <h2 className="text-2xl font-bold leading-7 text-zinc-900 sm:text-3xl sm:truncate flex items-center gap-2">
            <Settings className="w-8 h-8 text-zinc-400" />
            Configurações do Sistema
          </h2>
          <p className="mt-1 text-sm text-zinc-500">
            Gerencie as chaves de API e outras configurações globais.
          </p>
        </div>
      </div>

      <div className="bg-white shadow rounded-lg overflow-hidden">
        <div className="p-6 border-b border-zinc-200">
          <h3 className="text-lg font-medium text-zinc-900 flex items-center gap-2">
            <Key className="w-5 h-5 text-emerald-600" />
            Integração com Inteligência Artificial (Gemini)
          </h3>
          <p className="mt-1 text-sm text-zinc-500">
            Para que o sistema consiga extrair dados dos links do Google Maps, é necessário fornecer uma chave de API válida do Google Gemini.
          </p>
        </div>

        <form onSubmit={handleSave} className="p-6">
          {message && (
            <div className={`mb-6 p-4 rounded-md flex items-start gap-3 ${
              message.type === 'success' ? 'bg-emerald-50 text-emerald-800 border border-emerald-200' : 'bg-red-50 text-red-800 border border-red-200'
            }`}>
              {message.type === 'success' ? (
                <CheckCircle className="w-5 h-5 text-emerald-600 flex-shrink-0 mt-0.5" />
              ) : (
                <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
              )}
              <p className="text-sm font-medium">{message.text}</p>
            </div>
          )}

          <div className="space-y-6">
            <div>
              <label htmlFor="apiKey" className="block text-sm font-medium text-zinc-700">
                Chave da API (Gemini API Key)
              </label>
              <div className="mt-1">
                <input
                  type="password"
                  name="apiKey"
                  id="apiKey"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  className="shadow-sm focus:ring-emerald-500 focus:border-emerald-500 block w-full sm:text-sm border-zinc-300 rounded-md px-4 py-2 border"
                  placeholder="AIzaSy..."
                />
              </div>
              <p className="mt-2 text-sm text-zinc-500">
                Você pode gerar uma chave gratuitamente no <a href="https://aistudio.google.com/app/apikey" target="_blank" rel="noopener noreferrer" className="text-emerald-600 hover:text-emerald-500 underline">Google AI Studio</a>.
              </p>
            </div>

            <div className="pt-6 border-t border-zinc-200">
              <h3 className="text-lg font-medium text-zinc-900 flex items-center gap-2 mb-4">
                <Key className="w-5 h-5 text-emerald-600" />
                Sua Chave de API Externa (Webhook)
              </h3>
              <label htmlFor="webhookKey" className="block text-sm font-medium text-zinc-700">
                Token de Autenticação (x-api-key)
              </label>
              <div className="mt-1 flex rounded-md shadow-sm">
                <input
                  type="text"
                  name="webhookKey"
                  id="webhookKey"
                  value={user?.api_key || ''}
                  readOnly
                  className="focus:ring-emerald-500 focus:border-emerald-500 flex-1 block w-full rounded-none rounded-l-md sm:text-sm border-zinc-300 px-4 py-2 border bg-zinc-50 text-zinc-500"
                />
                <button
                  type="button"
                  onClick={() => {
                    if (user?.api_key) {
                      navigator.clipboard.writeText(user.api_key);
                      alert('Chave copiada!');
                    }
                  }}
                  className="-ml-px relative inline-flex items-center space-x-2 px-4 py-2 border border-zinc-300 text-sm font-medium rounded-r-md text-zinc-700 bg-zinc-50 hover:bg-zinc-100 focus:outline-none focus:ring-1 focus:ring-emerald-500 focus:border-emerald-500"
                >
                  Copiar
                </button>
              </div>
              <p className="mt-2 text-sm text-zinc-500">
                Esta é a sua chave exclusiva. Use-a no cabeçalho <code>x-api-key</code> para autenticar requisições externas.
              </p>
            </div>
          </div>

          <div className="mt-8 flex justify-end">
            <button
              type="submit"
              disabled={isSaving}
              className="inline-flex justify-center items-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-emerald-600 hover:bg-emerald-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-emerald-500 disabled:opacity-50"
            >
              {isSaving ? 'Salvando...' : 'Salvar Configurações'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
