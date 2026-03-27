import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import db from './src/db.js';
import fs from 'fs';

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key-change-in-prod';

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

app.use(cors());
app.use(express.json());

// Ensure 'dados' directory exists
const dadosDir = path.join(process.cwd(), 'dados');
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
  res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
});

// Get current user
app.get('/api/auth/me', authenticateToken, (req: any, res) => {
  res.json(req.user);
});

// Get settings
app.get('/api/settings', authenticateToken, (req: any, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Acesso negado' });
  }
  const settings = db.prepare('SELECT key, value FROM settings').all() as any[];
  const settingsMap = settings.reduce((acc, curr) => {
    acc[curr.key] = curr.value;
    return acc;
  }, {});
  res.json(settingsMap);
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
  const total = db.prepare('SELECT COUNT(*) as count FROM sites').get() as any;
  const today = db.prepare("SELECT COUNT(*) as count FROM sites WHERE date(created_at) = date('now')").get() as any;
  
  res.json({
    total: total.count,
    today: today.count
  });
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
  const sites = db.prepare('SELECT * FROM sites ORDER BY created_at DESC').all();
  res.json(sites);
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
