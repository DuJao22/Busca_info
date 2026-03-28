import React from 'react';
import { Code, Copy, CheckCircle, Terminal, Key, Globe } from 'lucide-react';
import { useState } from 'react';
import { useAuth } from '../context/AuthContext';

export default function ApiDocs() {
  const { user } = useAuth();
  const [copiedUrl, setCopiedUrl] = useState(false);
  const [copiedJson, setCopiedJson] = useState(false);
  const [copiedCurl, setCopiedCurl] = useState(false);
  
  const apiUrl = `${window.location.origin}/api/analyze-link`;
  const apiKey = user?.api_key || 'SEU_TOKEN_SECRETO';

  const jsonExample = `{
  "url": "https://maps.app.goo.gl/1psokcd5zz56YRYQ6"
}`;

  const curlExample = `curl -X POST ${apiUrl} \\
  -H "Content-Type: application/json" \\
  -H "x-api-key: ${apiKey}" \\
  -d '{"url": "https://maps.app.goo.gl/1psokcd5zz56YRYQ6"}'`;

  const responseExample = `{
  "success": true,
  "name": "Nome do Estabelecimento",
  "phone": "11999999999",
  "address": "Rua Exemplo, 123 - Bairro",
  "city": "São Paulo - SP",
  "description": "Descrição detalhada gerada pela IA...",
  "services": "Serviço 1, Serviço 2, Serviço 3"
}`;

  const handleCopyUrl = () => {
    navigator.clipboard.writeText(apiUrl);
    setCopiedUrl(true);
    setTimeout(() => setCopiedUrl(false), 2000);
  };

  const handleCopyJson = () => {
    navigator.clipboard.writeText(jsonExample);
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 2000);
  };

  const handleCopyCurl = () => {
    navigator.clipboard.writeText(curlExample);
    setCopiedCurl(true);
    setTimeout(() => setCopiedCurl(false), 2000);
  };

  return (
    <div className="max-w-4xl mx-auto py-6">
      <div className="md:flex md:items-center md:justify-between mb-8">
        <div className="flex-1 min-w-0">
          <h2 className="text-2xl font-bold leading-7 text-zinc-900 sm:text-3xl sm:truncate flex items-center gap-2">
            <Code className="w-8 h-8 text-zinc-400" />
            Documentação da API
          </h2>
          <p className="mt-1 text-sm text-zinc-500">
            Aprenda como integrar o extrator de dados do Google Maps em outras ferramentas (n8n, Make, Chatbots, etc).
          </p>
        </div>
      </div>

      <div className="bg-white shadow rounded-lg overflow-hidden mb-8">
        <div className="p-6 border-b border-zinc-200 bg-zinc-50">
          <h3 className="text-lg font-medium text-zinc-900 flex items-center gap-2">
            <Globe className="w-5 h-5 text-emerald-600" />
            Endpoint (URL da API)
          </h3>
        </div>
        <div className="p-6">
          <div className="flex flex-col sm:flex-row sm:items-center gap-4 bg-zinc-900 rounded-md p-4">
            <div className="flex items-center justify-between sm:justify-start w-full sm:w-auto">
              <span className="px-3 py-1 bg-emerald-600 text-white text-sm font-bold rounded-md">POST</span>
              <button 
                onClick={handleCopyUrl}
                className="sm:hidden text-zinc-400 hover:text-white transition-colors"
                title="Copiar URL"
              >
                {copiedUrl ? <CheckCircle className="w-5 h-5 text-emerald-500" /> : <Copy className="w-5 h-5" />}
              </button>
            </div>
            <code className="text-emerald-400 flex-1 overflow-x-auto break-all sm:break-normal text-sm sm:text-base">{apiUrl}</code>
            <button 
              onClick={handleCopyUrl}
              className="hidden sm:block text-zinc-400 hover:text-white transition-colors flex-shrink-0"
              title="Copiar URL"
            >
              {copiedUrl ? <CheckCircle className="w-5 h-5 text-emerald-500" /> : <Copy className="w-5 h-5" />}
            </button>
          </div>
        </div>
      </div>

      <div className="bg-white shadow rounded-lg overflow-hidden mb-8">
        <div className="p-6 border-b border-zinc-200 bg-zinc-50">
          <h3 className="text-lg font-medium text-zinc-900 flex items-center gap-2">
            <Key className="w-5 h-5 text-emerald-600" />
            Autenticação (Headers)
          </h3>
        </div>
        <div className="p-6">
          <p className="text-sm text-zinc-600 mb-4">
            Sua chave de API exclusiva já está configurada abaixo. Use-a no cabeçalho <code>x-api-key</code>.
          </p>
          <div className="bg-zinc-900 rounded-md p-4 overflow-x-auto">
            <pre className="text-zinc-300 text-sm">
              <code>
<span className="text-blue-400">Content-Type</span>: application/json{'\n'}
<span className="text-blue-400">x-api-key</span>: {apiKey}
              </code>
            </pre>
          </div>
        </div>
      </div>

      <div className="bg-white shadow rounded-lg overflow-hidden mb-8">
        <div className="p-6 border-b border-zinc-200 bg-zinc-50">
          <h3 className="text-lg font-medium text-zinc-900 flex items-center gap-2">
            <Terminal className="w-5 h-5 text-emerald-600" />
            Exemplo Completo (cURL)
          </h3>
        </div>
        <div className="p-6">
          <p className="text-sm text-zinc-600 mb-4">
            Copie o comando abaixo para testar a API no seu terminal ou importar no Postman/Insomnia.
          </p>
          <div className="relative bg-zinc-900 rounded-md p-4">
            <button 
              onClick={handleCopyCurl}
              className="absolute top-4 right-4 text-zinc-400 hover:text-white transition-colors"
              title="Copiar cURL"
            >
              {copiedCurl ? <CheckCircle className="w-5 h-5 text-emerald-500" /> : <Copy className="w-5 h-5" />}
            </button>
            <pre className="text-emerald-400 text-sm overflow-x-auto">
              <code>{curlExample}</code>
            </pre>
          </div>
        </div>
      </div>

      <div className="bg-white shadow rounded-lg overflow-hidden mb-8">
        <div className="p-6 border-b border-zinc-200 bg-zinc-50">
          <h3 className="text-lg font-medium text-zinc-900 flex items-center gap-2">
            <Terminal className="w-5 h-5 text-emerald-600" />
            Corpo da Requisição (Body)
          </h3>
        </div>
        <div className="p-6">
          <p className="text-sm text-zinc-600 mb-4">
            Envie um JSON contendo a URL do Google Maps que você deseja analisar.
          </p>
          <div className="relative bg-zinc-900 rounded-md p-4">
            <button 
              onClick={handleCopyJson}
              className="absolute top-4 right-4 text-zinc-400 hover:text-white transition-colors"
              title="Copiar JSON"
            >
              {copiedJson ? <CheckCircle className="w-5 h-5 text-emerald-500" /> : <Copy className="w-5 h-5" />}
            </button>
            <pre className="text-emerald-400 text-sm overflow-x-auto">
              <code>{jsonExample}</code>
            </pre>
          </div>
        </div>
      </div>

      <div className="bg-white shadow rounded-lg overflow-hidden">
        <div className="p-6 border-b border-zinc-200 bg-zinc-50">
          <h3 className="text-lg font-medium text-zinc-900 flex items-center gap-2">
            <CheckCircle className="w-5 h-5 text-emerald-600" />
            Exemplo de Resposta (Response)
          </h3>
        </div>
        <div className="p-6">
          <p className="text-sm text-zinc-600 mb-4">
            A API retornará um JSON estruturado com os dados extraídos pela Inteligência Artificial.
          </p>
          <div className="bg-zinc-900 rounded-md p-4 overflow-x-auto">
            <pre className="text-emerald-400 text-sm">
              <code>{responseExample}</code>
            </pre>
          </div>
          <div className="mt-4 p-4 bg-amber-50 border border-amber-200 rounded-md">
            <p className="text-sm text-amber-800">
              <strong>Nota:</strong> Se o link for inválido ou a IA não conseguir identificar o local com 100% de certeza, o campo <code>success</code> retornará <code>false</code> e um campo <code>errorMessage</code> será incluído.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
