const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

const DB_PATH = path.join(__dirname, 'data', 'satelcom.db');
const BACKUP_DIR = path.join(__dirname, 'data', 'backups');

const ALLOWED_TABLES = ['users', 'entries', 'dues', 'collections', 'settings', 'supplier_payments', 'supplier_pay_records'];

let db = null;

function saveDb() {
  if (!db) return;
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

function backupDb() {
  if (!db || !fs.existsSync(DB_PATH)) return;
  try {
    if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });
    const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    fs.copyFileSync(DB_PATH, path.join(BACKUP_DIR, `satelcom-${ts}.db`));
    const backups = fs.readdirSync(BACKUP_DIR).filter(f => f.endsWith('.db')).sort().reverse();
    while (backups.length > 7) {
      fs.unlinkSync(path.join(BACKUP_DIR, backups.pop()));
    }
  } catch (e) {
    console.error('Backup failed:', e.message);
  }
}

async function initDb() {
  const SQL = await initSqlJs();

  if (fs.existsSync(DB_PATH)) {
    const buffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buffer);
  } else {
    db = new SQL.Database();
  }

  db.run('PRAGMA foreign_keys = ON');
  createSchema();
  seedDefaults();
  saveDb();
  backupDb();

  console.log('Database initialized at', DB_PATH);
}

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

function getOne(sql, params = []) {
  const stmt = db.prepare(sql);
  if (params.length) stmt.bind(params);
  let result = null;
  if (stmt.step()) {
    result = stmt.getAsObject();
  }
  stmt.free();
  return result;
}

function getAll(sql, params = []) {
  const stmt = db.prepare(sql);
  if (params.length) stmt.bind(params);
  const results = [];
  while (stmt.step()) {
    results.push(stmt.getAsObject());
  }
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

module.exports = { initDb, getOne, getAll, qRun, maxId, backupDb, getLocalDate, isValidDate, roundAmount, db: () => db, exec: (sql) => db.exec(sql) };
