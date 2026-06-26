const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

const DB_PATH = path.join(__dirname, 'data', 'satelcom.db');
const BACKUP_DIR = path.join(__dirname, 'data', 'backups');
const EXPORT_DIR = path.join(__dirname, 'data', 'exports');

const ALLOWED_TABLES = ['users', 'entries', 'dues', 'collections', 'settings', 'supplier_payments', 'supplier_pay_records'];

const BACKUP_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes
const HOURLY_KEEP = 12;
const DAILY_KEEP = 30;

let db = null;
let backupTimer = null;

// ─── Save & Backup ─────────────────────────────────────────────

function saveDb() {
  if (!db) return;
  try {
    const data = db.export();
    if (!fs.existsSync(path.join(__dirname, 'data'))) {
      fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
    }
    fs.writeFileSync(DB_PATH, Buffer.from(data));
  } catch (e) {
    console.error('CRITICAL: saveDb failed:', e.message);
  }
}

function backupDb(label) {
  if (!db || !fs.existsSync(DB_PATH)) return null;
  try {
    if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });
    const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const name = label ? `${label}-${ts}.db` : `satelcom-${ts}.db`;
    const dest = path.join(BACKUP_DIR, name);
    fs.copyFileSync(DB_PATH, dest);
    cleanupBackups();
    return dest;
  } catch (e) {
    console.error('Backup failed:', e.message);
    return null;
  }
}

function cleanupBackups() {
  if (!fs.existsSync(BACKUP_DIR)) return;
  const files = fs.readdirSync(BACKUP_DIR).filter(f => f.endsWith('.db')).sort().reverse();
  const hourly = files.filter(f => f.startsWith('hourly-'));
  const daily = files.filter(f => f.startsWith('daily-'));
  const auto = files.filter(f => f.startsWith('satelcom-'));

  // Keep only HOURLY_KEEP hourly backups
  while (hourly.length > HOURLY_KEEP) {
    const old = hourly.pop();
    try { fs.unlinkSync(path.join(BACKUP_DIR, old)); } catch {}
  }

  // Keep only DAILY_KEEP daily backups
  while (daily.length > DAILY_KEEP) {
    const old = daily.pop();
    try { fs.unlinkSync(path.join(BACKUP_DIR, old)); } catch {}
  }

  // Keep only 24 auto backups
  while (auto.length > 24) {
    const old = auto.pop();
    try { fs.unlinkSync(path.join(BACKUP_DIR, old)); } catch {}
  }
}

function startAutoBackup() {
  // Hourly backup
  backupTimer = setInterval(() => {
    backupDb('hourly');
    console.log('[AutoBackup] Hourly backup completed');
  }, 60 * 60 * 1000);

  // Daily backup at midnight
  const now = new Date();
  const msUntilMidnight = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1) - now;
  setTimeout(() => {
    backupDb('daily');
    console.log('[AutoBackup] Daily backup completed');
    // Then every 24 hours
    setInterval(() => {
      backupDb('daily');
      console.log('[AutoBackup] Daily backup completed');
    }, 24 * 60 * 60 * 1000);
  }, msUntilMidnight);
}

function stopAutoBackup() {
  if (backupTimer) clearInterval(backupTimer);
}

// ─── Integrity & Recovery ──────────────────────────────────────

function checkIntegrity() {
  if (!db) return { ok: false, error: 'No database loaded' };
  try {
    const r = db.exec('PRAGMA integrity_check');
    if (!r || !r.length || !r[0].values.length) return { ok: false, error: 'Empty integrity check result' };
    const result = r[0].values[0][0];
    return { ok: result === 'ok', result };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

function getLatestBackup() {
  if (!fs.existsSync(BACKUP_DIR)) return null;
  const files = fs.readdirSync(BACKUP_DIR)
    .filter(f => f.endsWith('.db'))
    .sort()
    .reverse();
  if (!files.length) return null;
  return path.join(BACKUP_DIR, files[0]);
}

function listBackups() {
  if (!fs.existsSync(BACKUP_DIR)) return [];
  return fs.readdirSync(BACKUP_DIR)
    .filter(f => f.endsWith('.db'))
    .sort()
    .reverse()
    .map(f => {
      const stat = fs.statSync(path.join(BACKUP_DIR, f));
      return { name: f, size: stat.size, date: stat.mtime.toISOString() };
    });
}

function restoreFromBackup(backupFile) {
  if (!fs.existsSync(backupFile)) return { ok: false, error: 'Backup file not found' };

  try {
    // First, verify the backup is valid
    const initSqlJs2 = require('sql.js');
    return initSqlJs2().then(SQL => {
      const buf = fs.readFileSync(backupFile);
      const testDb = new SQL.Database(buf);
      const integrity = testDb.exec('PRAGMA integrity_check');
      testDb.close();

      if (!integrity || !integrity.length || integrity[0].values[0][0] !== 'ok') {
        return { ok: false, error: 'Backup file is corrupted' };
      }

      // Backup current DB before restoring
      saveDb();
      backupDb('pre-restore');

      // Replace current DB
      fs.copyFileSync(backupFile, DB_PATH);

      // Reload into memory
      const buffer = fs.readFileSync(DB_PATH);
      db = new SQL.Database(buffer);
      db.run('PRAGMA foreign_keys = ON');

      return { ok: true, message: 'Database restored successfully' };
    });
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// ─── Export / Import ───────────────────────────────────────────

function exportAllData() {
  if (!db) return null;
  const tables = {};
  for (const t of ALLOWED_TABLES) {
    tables[t] = getAll('SELECT * FROM ' + t);
  }
  tables._meta = {
    exported_at: new Date().toISOString(),
    db_version: '1.0'
  };
  return tables;
}

function saveExportJson() {
  if (!fs.existsSync(EXPORT_DIR)) fs.mkdirSync(EXPORT_DIR, { recursive: true });
  const data = exportAllData();
  if (!data) return null;
  const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const filePath = path.join(EXPORT_DIR, `export-${ts}.json`);
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
  // Keep only 10 exports
  const exports = fs.readdirSync(EXPORT_DIR).filter(f => f.endsWith('.json')).sort().reverse();
  while (exports.length > 10) {
    try { fs.unlinkSync(path.join(EXPORT_DIR, exports.pop())); } catch {}
  }
  return filePath;
}

function importFromJson(filePath) {
  if (!fs.existsSync(filePath)) return { ok: false, error: 'File not found' };
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const data = JSON.parse(raw);
    return importFromData(data);
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

function importFromData(data) {
  if (!data || typeof data !== 'object') return { ok: false, error: 'Invalid data format' };
  try {
    saveDb();
    backupDb('pre-import');

    for (const t of ALLOWED_TABLES) {
      if (data[t] && Array.isArray(data[t])) {
        db.run('DELETE FROM ' + t);
        for (const row of data[t]) {
          const cols = Object.keys(row);
          const placeholders = cols.map(() => '?').join(',');
          const vals = cols.map(c => row[c]);
          db.run(`INSERT INTO ${t} (${cols.join(',')}) VALUES (${placeholders})`, vals);
        }
      }
    }
    saveDb();
    return { ok: true, message: 'Data imported successfully', rows: Object.keys(data).filter(k => ALLOWED_TABLES.includes(k)).map(k => `${k}: ${data[k].length}`).join(', ') };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// ─── Database Init ─────────────────────────────────────────────

async function initDb() {
  const SQL = await initSqlJs();

  const dbExists = fs.existsSync(DB_PATH);

  if (dbExists) {
    // Try loading existing DB
    try {
      const buffer = fs.readFileSync(DB_PATH);
      db = new SQL.Database(buffer);
      db.run('PRAGMA foreign_keys = ON');

      // Check integrity
      const integrity = checkIntegrity();
      if (!integrity.ok) {
        console.error('[RECOVERY] Database integrity check FAILED:', integrity.error || integrity.result);
        console.log('[RECOVERY] Attempting auto-recovery from latest backup...');

        const recovered = attemptRecovery(SQL);
        if (recovered) {
          console.log('[RECOVERY] Auto-recovery SUCCESSFUL');
        } else {
          console.error('[RECOVERY] Auto-recovery FAILED. Starting with fresh database.');
          db = new SQL.Database();
          db.run('PRAGMA foreign_keys = ON');
        }
      } else {
        console.log('[DB] Integrity check passed');
      }
    } catch (e) {
      console.error('[RECOVERY] Failed to load database:', e.message);
      console.log('[RECOVERY] Starting with fresh database...');
      db = new SQL.Database();
      db.run('PRAGMA foreign_keys = ON');
    }
  } else {
    db = new SQL.Database();
    db.run('PRAGMA foreign_keys = ON');
    console.log('[DB] New database created');
  }

  createSchema();
  runMigrations();
  seedDefaults();
  saveDb();
  backupDb('startup');
  startAutoBackup();

  console.log('[DB] Database ready at', DB_PATH);
  console.log('[DB] Auto-backup running every 5 min (hourly) + daily at midnight');
}

function attemptRecovery(SQL) {
  const backupFile = getLatestBackup();
  if (!backupFile) {
    console.log('[RECOVERY] No backup files found');
    return false;
  }

  try {
    console.log('[RECOVERY] Trying backup:', backupFile);
    const buf = fs.readFileSync(backupFile);
    const testDb = new SQL.Database(buf);
    const integrity = testDb.exec('PRAGMA integrity_check');
    testDb.close();

    if (integrity && integrity.length && integrity[0].values[0][0] === 'ok') {
      // Good backup found - restore it
      db.close();
      db = new SQL.Database(buf);
      db.run('PRAGMA foreign_keys = ON');
      saveDb();
      return true;
    }
  } catch (e) {
    console.error('[RECOVERY] Backup restore failed:', e.message);
  }

  // Try next backup
  const backups = listBackups();
  for (const b of backups) {
    if (b.name === path.basename(backupFile)) continue;
    try {
      const buf = fs.readFileSync(path.join(BACKUP_DIR, b.name));
      const testDb = new SQL.Database(buf);
      const integrity = testDb.exec('PRAGMA integrity_check');
      testDb.close();
      if (integrity && integrity.length && integrity[0].values[0][0] === 'ok') {
        db.close();
        db = new SQL.Database(buf);
        db.run('PRAGMA foreign_keys = ON');
        saveDb();
        console.log('[RECOVERY] Recovered from:', b.name);
        return true;
      }
    } catch {}
  }

  return false;
}

// ─── Query Helpers ─────────────────────────────────────────────

function getOne(sql, params = []) {
  const stmt = db.prepare(sql);
  if (params.length) stmt.bind(params);
  let result = null;
  if (stmt.step()) result = stmt.getAsObject();
  stmt.free();
  return result;
}

function getAll(sql, params = []) {
  const stmt = db.prepare(sql);
  if (params.length) stmt.bind(params);
  const results = [];
  while (stmt.step()) results.push(stmt.getAsObject());
  stmt.free();
  return results;
}

function qRun(sql, params = []) {
  db.run(sql, params);
  saveDb();
  return { changes: db.getRowsModified() };
}

function maxId(table) {
  if (!ALLOWED_TABLES.includes(table)) throw new Error('Invalid table name');
  const r = db.exec('SELECT MAX(id) as id FROM ' + table);
  if (!r || !r.length || !r[0].values || !r[0].values.length) return null;
  return r[0].values[0][0];
}

function getLocalDate() {
  const now = new Date();
  const y = now.getFullYear();
  const m = String(now.getMonth() + 1).padStart(2, '0');
  const d = String(now.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

function isValidDate(str) {
  return /^\d{4}-\d{2}-\d{2}$/.test(str) && !isNaN(new Date(str + 'T00:00:00').getTime());
}

function roundAmount(val) {
  return Math.round((val + Number.EPSILON) * 100) / 100;
}

// ─── Schema ────────────────────────────────────────────────────

function createSchema() {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      display_name TEXT,
      role TEXT DEFAULT 'staff',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS entries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      entry_date TEXT NOT NULL DEFAULT (date('now')),
      description TEXT NOT NULL,
      notes TEXT DEFAULT '',
      amount REAL NOT NULL CHECK(amount > 0),
      entry_type TEXT NOT NULL CHECK(entry_type IN ('main', 'cashout')),
      created_by INTEGER REFERENCES users(id),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS dues (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      client_name TEXT NOT NULL,
      amount REAL NOT NULL CHECK(amount > 0),
      note TEXT DEFAULT '',
      created_by INTEGER REFERENCES users(id),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS collections (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      due_id INTEGER REFERENCES dues(id) ON DELETE CASCADE,
      amount REAL NOT NULL CHECK(amount > 0),
      collected_by INTEGER REFERENCES users(id),
      collected_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS supplier_payments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      supplier_name TEXT NOT NULL,
      amount REAL NOT NULL CHECK(amount > 0),
      note TEXT DEFAULT '',
      created_by INTEGER REFERENCES users(id),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS supplier_pay_records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      supplier_payment_id INTEGER REFERENCES supplier_payments(id) ON DELETE CASCADE,
      amount REAL NOT NULL CHECK(amount > 0),
      paid_by INTEGER REFERENCES users(id),
      paid_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

function seedDefaults() {
  const rows = db.exec('SELECT COUNT(*) as count FROM users');
  if (!rows.length || !rows[0].values.length || rows[0].values[0][0] === 0) {
    const hash = bcrypt.hashSync('admin123', 10);
    db.run('INSERT INTO users (username, password_hash, display_name, role) VALUES (?, ?, ?, ?)', ['admin', hash, 'Admin', 'admin']);
  }
  const srows = db.exec('SELECT COUNT(*) as count FROM settings');
  if (!srows.length || !srows[0].values.length || srows[0].values[0][0] === 0) {
    db.run('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', ['opening_balance', '4300']);
  }
}

function runMigrations() {
  const cols = getAll("PRAGMA table_info(entries)").map(c => c.name);
  if (!cols.includes('customer_type')) {
    db.run("ALTER TABLE entries ADD COLUMN customer_type TEXT DEFAULT 'walkin'");
    console.log('[DB] Migration: added customer_type to entries');
  }
  if (!cols.includes('client_name')) {
    db.run("ALTER TABLE entries ADD COLUMN client_name TEXT DEFAULT ''");
    console.log('[DB] Migration: added client_name to entries');
  }
  const ucols = getAll("PRAGMA table_info(users)").map(c => c.name);
  if (!ucols.includes('permissions')) {
    db.run("ALTER TABLE users ADD COLUMN permissions TEXT DEFAULT ''");
    console.log('[DB] Migration: added permissions to users');
  }
}

module.exports = {
  initDb, getOne, getAll, qRun, maxId,
  backupDb, listBackups, restoreFromBackup,
  checkIntegrity, exportAllData, saveExportJson, importFromJson, importFromData,
  getLocalDate, isValidDate, roundAmount,
  stopAutoBackup, db: () => db
};
