import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

// Ensure data directory exists
// On Vercel, only /tmp is writable. Otherwise, use local ./data folder.
const isVercel = process.env.VERCEL === '1' || process.env.VERCEL_ENV;
const dataDir = isVercel ? '/tmp' : path.join(process.cwd(), 'data');

if (!isVercel && !fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, 'database.sqlite');
const db = new Database(dbPath);

// Enable WAL mode for better performance
db.pragma('journal_mode = WAL');

// Initialize schema
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'operator',
    api_key TEXT UNIQUE
  );

  CREATE TABLE IF NOT EXISTS sites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    phone TEXT,
    address TEXT,
    city TEXT,
    description TEXT,
    services TEXT,
    map_link TEXT,
    image_url TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    status TEXT DEFAULT 'active',
    user_id INTEGER,
    FOREIGN KEY (user_id) REFERENCES users (id)
  );

  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`);

// Add api_key column if it doesn't exist (for existing databases)
try {
  db.exec("ALTER TABLE users ADD COLUMN api_key TEXT");
} catch (e) {
  // Column already exists, ignore
}

try {
  db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key)");
} catch (e) {
  // ignore
}

// Generate API keys for users that don't have one
const usersWithoutApiKey = db.prepare('SELECT id FROM users WHERE api_key IS NULL').all() as { id: number }[];
if (usersWithoutApiKey.length > 0) {
  const updateApiKey = db.prepare('UPDATE users SET api_key = ? WHERE id = ?');
  db.transaction(() => {
    for (const user of usersWithoutApiKey) {
      updateApiKey.run(crypto.randomBytes(24).toString('hex'), user.id);
    }
  })();
}

export default db;
