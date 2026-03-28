import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Sparkles, CheckCircle, Download, FileJson } from 'lucide-react';
import { GoogleGenAI, Type } from '@google/genai';

export default function CreateSite() {
  const { token } = useAuth();
  const navigate = useNavigate();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [mapsLink, setMapsLink] = useState('');
  const [successData, setSuccessData] = useState<{filename: string, id: number} | null>(null);

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mapsLink) {
      setError('Por favor, insira um link do Google Maps.');
      return;
    }
    
    setIsLoading(true);
    setError('');

    try {
      // 1. Expand the URL if it's a short link
      let finalUrl = mapsLink;
      let placeNameHint = '';
      try {
        const expandRes = await fetch('/api/expand-url', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`
          },
          body: JSON.stringify({ url: mapsLink })
        });
        
        if (expandRes.ok) {
          const expandData = await expandRes.json();
          if (expandData.url) {
            finalUrl = expandData.url;
            
            // Try to extract place name from the expanded URL
            const match = finalUrl.match(/\/place\/([^\/]+)/);
            if (match && match[1]) {
              placeNameHint = decodeURIComponent(match[1].replace(/\+/g, ' '));
            }
          }
        }
      } catch (e) {
        console.warn('Failed to expand URL, using original', e);
      }

      // 2. Get API Key from settings
      const settingsRes = await fetch('/api/settings', {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      let apiKey = (import.meta as any).env.VITE_GEMINI_API_KEY; // Fallback to env
      
      if (settingsRes.ok) {
        const settings = await settingsRes.json();
        if (settings.gemini_api_key) {
          apiKey = settings.gemini_api_key;
        }
      }

      if (!apiKey) {
        setError('Chave da API do Gemini não configurada. Por favor, configure-a na página de Configurações.');
        setIsLoading(false);
        return;
      }

      // 3. Analyze with AI
      const ai = new GoogleGenAI({ apiKey: apiKey });
      const response = await ai.models.generateContent({
        model: "gemini-3.1-pro-preview",
        contents: `Você é um especialista em extração de dados.
Você recebeu o seguinte link do Google Maps: ${finalUrl}
${placeNameHint ? `\nDica: O nome do estabelecimento extraído da URL parece ser "${placeNameHint}".` : ''}

Sua missão é OBRIGATÓRIA:
1. USE A FERRAMENTA DE BUSCA DO GOOGLE (Google Search) para pesquisar este link ou o nome do estabelecimento que aparece na URL.
2. Descubra EXATAMENTE qual é o estabelecimento real (nome, nicho, endereço, telefone).
3. Se o link for genérico, quebrado, ou se você NÃO TIVER 100% DE CERTEZA de qual é o estabelecimento exato, você DEVE definir "success" como false e preencher o "errorMessage" explicando que não foi possível identificar o local e pedindo para o usuário verificar o link.
4. Se você encontrou o estabelecimento com sucesso, defina "success" como true e extraia os dados reais: Nome da empresa, telefone (apenas números com DDD), endereço completo e cidade.
5. Identifique o NICHO exato (ex: barbearia, lanchonete, clínica, restaurante).
6. Crie uma DESCRIÇÃO detalhada do negócio.
7. Liste os principais serviços oferecidos (ou que fazem sentido para o nicho), separados por vírgula.

NÃO INVENTE DADOS. Se não souber ou não encontrar o local exato, retorne success: false.`,
        config: {
          tools: [{ googleSearch: {} }],
          toolConfig: { includeServerSideToolInvocations: true },
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              success: { type: Type.BOOLEAN, description: "True se encontrou o estabelecimento exato, False se não conseguiu ou se o link for inválido" },
              errorMessage: { type: Type.STRING, description: "Mensagem de erro amigável se success for false" },
              name: { type: Type.STRING, description: "Nome da empresa" },
              phone: { type: Type.STRING, description: "Telefone com DDD, apenas números" },
              address: { type: Type.STRING, description: "Endereço completo" },
              city: { type: Type.STRING, description: "Cidade e Estado" },
              description: { type: Type.STRING, description: "Descrição do negócio" },
              services: { type: Type.STRING, description: "Lista de serviços separados por vírgula" },
            },
            required: ["success"]
          }
        }
      });

      if (response.text) {
        let extractedData;
        try {
          // Remove markdown code blocks if the AI includes them
          const cleanedText = response.text.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
          extractedData = JSON.parse(cleanedText);
        } catch (parseError) {
          console.error("JSON Parse Error:", parseError, "Raw text:", response.text);
          throw new Error("A resposta da IA não estava em um formato válido.");
        }
        
        if (!extractedData.success) {
          setError(extractedData.errorMessage || 'Não foi possível identificar o estabelecimento a partir deste link. Por favor, verifique o link.');
          setIsLoading(false);
          return;
        }

        // 4. Save the extracted data
        const saveRes = await fetch('/api/analyze/save', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`
          },
          body: JSON.stringify({
            ...extractedData,
            map_link: mapsLink
          })
        });

        let saveData;
        try {
          saveData = await saveRes.json();
        } catch (e) {
          throw new Error('Erro no servidor ao salvar os dados. (Verifique os logs da Vercel)');
        }
        
        if (!saveRes.ok) throw new Error(saveData.error || 'Erro ao salvar dados');

        setSuccessData({ filename: saveData.filename, id: saveData.id });
      }
    } catch (err: any) {
      console.error(err);
      setError('Erro ao analisar o link com IA. Verifique se o link é válido ou tente novamente.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleDownloadJson = async () => {
    if (successData) {
      try {
        const res = await fetch(`/api/analyze/download/${successData.filename}`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        if (!res.ok) throw new Error('Falha ao baixar arquivo');
        
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = successData.filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      } catch (error) {
        console.error('Download error:', error);
        alert('Erro ao baixar o arquivo JSON.');
      }
    }
  };

  if (successData) {
    return (
      <div className="max-w-3xl mx-auto py-12 px-4 sm:px-6 lg:px-8 text-center">
        <div className="bg-white rounded-2xl shadow-xl p-8 sm:p-12 border border-zinc-100">
          <div className="w-20 h-20 bg-emerald-100 rounded-full flex items-center justify-center mx-auto mb-6">
            <CheckCircle className="w-10 h-10 text-emerald-600" />
          </div>
          <h2 className="text-3xl font-bold text-zinc-900 mb-4">Análise Concluída!</h2>
          <p className="text-lg text-zinc-600 mb-8">
            Os dados do estabelecimento foram extraídos e salvos com sucesso.
          </p>
          
          <div className="bg-zinc-50 rounded-xl p-6 mb-8 border border-zinc-200">
            <p className="text-sm text-zinc-500 mb-2">Arquivo gerado:</p>
            <div className="text-lg sm:text-xl font-medium text-emerald-600 flex items-center justify-center gap-2 break-all">
              <FileJson className="w-5 h-5 flex-shrink-0" />
              {successData.filename}
            </div>
          </div>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <button
              onClick={handleDownloadJson}
              className="w-full sm:w-auto inline-flex items-center justify-center px-6 py-3 border border-transparent text-base font-medium rounded-md shadow-sm text-white bg-emerald-600 hover:bg-emerald-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-emerald-500"
            >
              <Download className="w-5 h-5 mr-2" />
              Baixar Arquivo JSON
            </button>
            <button
              onClick={() => navigate('/sites')}
              className="w-full sm:w-auto inline-flex items-center justify-center px-6 py-3 border border-zinc-300 text-base font-medium rounded-md text-zinc-700 bg-white hover:bg-zinc-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-emerald-500"
            >
              Ver Análises Salvas
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-3xl mx-auto py-6">
      <div className="md:flex md:items-center md:justify-between mb-8">
        <div className="flex-1 min-w-0">
          <h2 className="text-2xl font-bold leading-7 text-zinc-900 sm:text-3xl sm:truncate">
            Analisar Link do Google Maps
          </h2>
          <p className="mt-1 text-sm text-zinc-500">
            Cole o link abaixo para extrair automaticamente os dados do estabelecimento e salvar em formato JSON.
          </p>
        </div>
      </div>

      {error && (
        <div className="bg-red-50 border-l-4 border-red-400 p-4 mb-6">
          <div className="flex">
            <div className="ml-3">
              <p className="text-sm text-red-700">{error}</p>
            </div>
          </div>
        </div>
      )}

      <form onSubmit={handleAnalyze} className="bg-white shadow rounded-lg p-6">
        <div className="bg-emerald-50 border border-emerald-200 rounded-lg p-6 mb-8">
          <div className="flex items-start">
            <div className="flex-shrink-0 mt-1">
              <Sparkles className="h-6 w-6 text-emerald-600" />
            </div>
            <div className="ml-4 flex-1">
              <h3 className="text-lg font-medium text-emerald-900">Extração com Inteligência Artificial</h3>
              <p className="mt-1 text-sm text-emerald-700">
                Nossa IA vai buscar os dados reais do local e estruturá-los em um arquivo JSON.
              </p>
              <div className="mt-4 flex flex-col sm:flex-row gap-3">
                <input
                  type="url"
                  value={mapsLink}
                  onChange={(e) => setMapsLink(e.target.value)}
                  placeholder="https://maps.app.goo.gl/..."
                  required
                  className="flex-1 focus:ring-emerald-500 focus:border-emerald-500 block sm:text-sm border-emerald-300 rounded-md shadow-sm px-3 py-2 border bg-white"
                />
              </div>
            </div>
          </div>
        </div>

        <div className="pt-5 border-t border-zinc-200 mt-6">
          <div className="flex flex-col sm:flex-row sm:justify-end gap-3">
            <button
              type="button"
              onClick={() => navigate('/sites')}
              className="w-full sm:w-auto bg-white py-2 px-4 border border-zinc-300 rounded-md shadow-sm text-sm font-medium text-zinc-700 hover:bg-zinc-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-emerald-500 order-2 sm:order-1"
            >
              Cancelar
            </button>
            <button
              type="submit"
              disabled={isLoading}
              className="w-full sm:w-auto inline-flex justify-center items-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-emerald-600 hover:bg-emerald-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-emerald-500 disabled:opacity-50 order-1 sm:order-2"
            >
              {isLoading ? (
                <>
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                  Analisando...
                </>
              ) : (
                'Analisar e Extrair Dados'
              )}
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}
