import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import db from './src/db.js';
import fs from 'fs';
import crypto from 'crypto';
import { GoogleGenAI, Type } from '@google/genai';

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key-change-in-prod';

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

// Ensure 'dados' directory exists
const isVercel = process.env.VERCEL === '1' || process.env.VERCEL_ENV;
const dadosDir = isVercel ? '/tmp/dados' : path.join(process.cwd(), 'dados');
if (!fs.existsSync(dadosDir)) {
  fs.mkdirSync(dadosDir, { recursive: true });
}

// Initialize default admin if not exists, or update if it does
const adminExists = db.prepare('SELECT id FROM users WHERE LOWER(username) = LOWER(?)').get('DuJao');
const hash = bcrypt.hashSync('3003', 10);
if (!adminExists) {
  db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)').run('DuJao', hash, 'admin');
} else {
  db.prepare('UPDATE users SET password_hash = ? WHERE LOWER(username) = LOWER(?)').run(hash, 'DuJao');
}

// --- API Routes ---

// Auth Middleware
const authenticateToken = (req: any, res: any, next: any) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Login
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)').get(username) as any;

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Credenciais inválidas' });
  }

  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, user: { id: user.id, username: user.username, role: user.role, api_key: user.api_key } });
});

// Get current user
app.get('/api/auth/me', authenticateToken, (req: any, res) => {
  const user = db.prepare('SELECT id, username, role, api_key FROM users WHERE id = ?').get(req.user.id) as any;
  res.json(user);
});

// Get settings
app.get('/api/settings', authenticateToken, (req: any, res) => {
  const settings = db.prepare('SELECT key, value FROM settings').all() as any[];
  const settingsMap = settings.reduce((acc, curr) => {
    acc[curr.key] = curr.value;
    return acc;
  }, {});
  res.json(settingsMap);
});

// Users Management
app.get('/api/users', authenticateToken, (req: any, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Acesso negado' });
  }
  const users = db.prepare('SELECT id, username, role, api_key FROM users').all();
  res.json(users);
});

app.post('/api/users', authenticateToken, (req: any, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Acesso negado' });
  }
  const { username, password, role } = req.body;
  if (!username || !password || !role) {
    return res.status(400).json({ error: 'Todos os campos são obrigatórios' });
  }
  
  const existingUser = db.prepare('SELECT id FROM users WHERE LOWER(username) = LOWER(?)').get(username);
  if (existingUser) {
    return res.status(400).json({ error: 'Usuário já existe' });
  }

  try {
    const hash = bcrypt.hashSync(password, 10);
    const apiKey = crypto.randomBytes(24).toString('hex');
    db.prepare('INSERT INTO users (username, password_hash, role, api_key) VALUES (?, ?, ?, ?)').run(username, hash, role, apiKey);
    res.json({ success: true });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ error: 'Erro ao criar usuário' });
  }
});

app.delete('/api/users/:id', authenticateToken, (req: any, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Acesso negado' });
  }
  if (parseInt(req.params.id) === req.user.id) {
    return res.status(400).json({ error: 'Não é possível excluir o próprio usuário' });
  }
  
  try {
    db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'Erro ao excluir usuário' });
  }
});

// Save settings
app.post('/api/settings', authenticateToken, (req: any, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Acesso negado' });
  }
  
  const { gemini_api_key } = req.body;
  
  try {
    const stmt = db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value');
    
    db.transaction(() => {
      if (gemini_api_key !== undefined) {
        stmt.run('gemini_api_key', gemini_api_key);
      }
    })();
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error saving settings:', error);
    res.status(500).json({ error: 'Erro ao salvar configurações' });
  }
});

// Dashboard Stats
app.get('/api/stats', authenticateToken, (req: any, res) => {
  try {
    const total = db.prepare('SELECT COUNT(*) as count FROM sites').get() as any;
    const today = db.prepare("SELECT COUNT(*) as count FROM sites WHERE date(created_at) = date('now')").get() as any;
    
    res.json({
      total: total.count,
      today: today.count
    });
  } catch (error) {
    console.error('Error in /api/stats:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Save Analyzed Data
app.post('/api/analyze/save', authenticateToken, (req: any, res) => {
  const data = req.body;
  
  // Generate filename
  const safeName = data.name ? data.name.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/(^_|_$)+/g, '') : 'empresa';
  const timestamp = Date.now();
  const filename = `${safeName}_${timestamp}.json`;
  const filepath = path.join(dadosDir, filename);

  // Save JSON to 'dados' folder
  try {
    fs.writeFileSync(filepath, JSON.stringify(data, null, 2));
  } catch (err) {
    console.error('Error saving JSON file:', err);
    return res.status(500).json({ error: 'Erro ao salvar arquivo JSON' });
  }

  // Save to DB for history (reusing sites table)
  const result = db.prepare(`
    INSERT INTO sites (slug, name, phone, address, city, description, services, map_link, image_url, expires_at, user_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(filename, data.name || 'Desconhecido', data.phone || '', data.address || '', data.city || '', data.description || '', data.services || '', data.map_link || '', data.image_url || '', new Date().toISOString(), req.user.id);

  res.json({ id: result.lastInsertRowid, filename });
});

// List Analyzed Links
app.get('/api/sites', authenticateToken, (req: any, res) => {
  try {
    const sites = db.prepare('SELECT * FROM sites ORDER BY created_at DESC').all();
    res.json(sites);
  } catch (error) {
    console.error('Error in /api/sites:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Download JSON
app.get('/api/analyze/download/:filename', authenticateToken, (req: any, res) => {
  const filename = req.params.filename;
  const filepath = path.join(dadosDir, filename);

  if (!fs.existsSync(filepath)) {
    return res.status(404).json({ error: 'Arquivo não encontrado' });
  }

  res.download(filepath);
});

// Expand URL
app.post('/api/expand-url', authenticateToken, async (req: any, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL is required' });
    
    const response = await fetch(url, { 
      method: 'GET', 
      redirect: 'follow',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
      }
    });
    res.json({ url: response.url });
  } catch (error: any) {
    console.error('Error expanding URL:', error);
    res.status(500).json({ error: 'Failed to expand URL' });
  }
});

// Analyze Link Endpoint
app.post('/api/analyze-link', async (req: any, res: any) => {
  // Check for authorization (either JWT or a simple API key passed in headers)
  const authHeader = req.headers['authorization'];
  const apiKeyHeader = req.headers['x-api-key'];
  
  let isAuthenticated = false;
  
  if (apiKeyHeader) {
     // Check if it matches a user's API key
     const user = db.prepare('SELECT id FROM users WHERE api_key = ?').get(apiKeyHeader) as any;
     if (user) {
       isAuthenticated = true;
     }
  } else if (authHeader) {
     const token = authHeader.split(' ')[1];
     try {
       jwt.verify(token, JWT_SECRET);
       isAuthenticated = true;
     } catch (e) {
       // ignore
     }
  }

  if (!isAuthenticated) {
    return res.status(401).json({ error: 'Não autorizado. Forneça um token JWT válido ou um x-api-key configurado.' });
  }

  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ error: 'A URL é obrigatória no corpo da requisição ({"url": "..."}).' });
  }

  try {
    // Get Gemini API Key
    let geminiApiKey = process.env.GEMINI_API_KEY || process.env.VITE_GEMINI_API_KEY;
    const settings = db.prepare('SELECT key, value FROM settings').all() as any[];
    const settingsMap = settings.reduce((acc, curr) => {
      acc[curr.key] = curr.value;
      return acc;
    }, {} as any);

    if (settingsMap.gemini_api_key) {
      geminiApiKey = settingsMap.gemini_api_key;
    }

    if (!geminiApiKey) {
      return res.status(500).json({ error: 'Chave da API do Gemini não configurada no servidor.' });
    }

    const ai = new GoogleGenAI({ apiKey: geminiApiKey });
    
    // Extract place name hint if possible
    let placeNameHint = '';
    try {
      const urlObj = new URL(url);
      const pathParts = urlObj.pathname.split('/');
      const placePart = pathParts.find(part => part.includes('+') || part.includes('-'));
      if (placePart) {
        placeNameHint = decodeURIComponent(placePart.replace(/\+/g, ' '));
      }
    } catch (e) {
      // ignore
    }

    const response = await ai.models.generateContent({
      model: "gemini-3.1-pro-preview",
      contents: `Você é um especialista em extração de dados.
Você recebeu o seguinte link do Google Maps: ${url}
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

    let jsonStr = response.text || '';
    jsonStr = jsonStr.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
    const result = JSON.parse(jsonStr);

    return res.json(result);

  } catch (error: any) {
    console.error('Error analyzing link:', error);
    return res.status(500).json({ error: 'Erro ao analisar o link com a IA', details: error.message });
  }
});

// Delete Analyzed Data
app.delete('/api/sites/:id', authenticateToken, (req: any, res) => {
  const site = db.prepare('SELECT slug FROM sites WHERE id = ?').get(req.params.id) as any;
  if (site) {
    const filepath = path.join(dadosDir, site.slug);
    if (fs.existsSync(filepath)) {
      fs.unlinkSync(filepath);
    }
    db.prepare('DELETE FROM sites WHERE id = ?').run(req.params.id);
  }
  res.json({ success: true });
});

// --- Vercel Serverless Export ---
export default app;

// --- Local Development & Production Server ---
if (process.env.NODE_ENV !== 'production' && !process.env.VERCEL) {
  // Start Vite dev server
  createViteServer({
    server: { middlewareMode: true },
    appType: 'spa',
  }).then((vite) => {
    app.use(vite.middlewares);
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`Server running on http://localhost:${PORT}`);
    });
  });
} else if (!process.env.VERCEL) {
  // Serve static files in production (Render, Railway, VPS, etc.)
  const distPath = path.join(process.cwd(), 'dist');
  app.use(express.static(distPath));
  app.get('*', (req, res) => {
    res.sendFile(path.join(distPath, 'index.html'));
  });
  
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
  });
}
