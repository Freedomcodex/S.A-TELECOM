const express = require('express');
const bcrypt = require('bcryptjs');
const { getOne, getAll, qRun, maxId, backupDb, getLocalDate, isValidDate, roundAmount } = require('./db');
const { generateToken, authenticate, adminOnly } = require('./middleware');

const router = express.Router();

// ─── Auth ───────────────────────────────────────────────────────

router.post('/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  const user = getOne('SELECT * FROM users WHERE username = ?', [username]);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = generateToken(user);
  res.json({
    token,
    user: { id: user.id, username: user.username, role: user.role, display_name: user.display_name }
  });
});

router.post('/auth/register', authenticate, adminOnly, (req, res) => {
  const { username, password, display_name, role } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  const existing = getOne('SELECT id FROM users WHERE username = ?', [username]);
  if (existing) {
    return res.status(409).json({ error: 'Username already exists' });
  }

  const hash = bcrypt.hashSync(password, 10);
  qRun('INSERT INTO users (username, password_hash, display_name, role) VALUES (?, ?, ?, ?)',
    [username, hash, display_name || username, role || 'staff']);

  res.status(201).json({ id: maxId('users'), username, display_name, role });
});

router.get('/auth/me', authenticate, (req, res) => {
  res.json(req.user);
});

// ─── Settings ───────────────────────────────────────────────────

router.get('/settings', authenticate, (req, res) => {
  const rows = getAll('SELECT key, value FROM settings');
  const map = {};
  rows.forEach(s => map[s.key] = s.value);
  res.json(map);
});

router.put('/settings', authenticate, adminOnly, (req, res) => {
  const { opening_balance } = req.body;
  if (opening_balance !== undefined) {
    qRun('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', ['opening_balance', String(opening_balance)]);
  }
  res.json({ success: true });
});

// ─── Entries ────────────────────────────────────────────────────

router.get('/entries', authenticate, (req, res) => {
  const { date, type } = req.query;
  let sql = `SELECT e.*, u.display_name as created_by_name
             FROM entries e LEFT JOIN users u ON e.created_by = u.id WHERE 1=1`;
  const params = [];

  if (date) { sql += ' AND e.entry_date = ?'; params.push(date); }
  if (type) { sql += ' AND e.entry_type = ?'; params.push(type); }

  sql += ' ORDER BY e.id ASC';
  res.json(getAll(sql, params));
});

router.post('/entries', authenticate, (req, res) => {
  let { entry_date, description, notes, amount, entry_type } = req.body;

  if (!description || !amount || !entry_type) {
    return res.status(400).json({ error: 'Description, amount, and entry_type required' });
  }
  if (!['main', 'cashout'].includes(entry_type)) {
    return res.status(400).json({ error: 'entry_type must be "main" or "cashout"' });
  }

  entry_date = entry_date || getLocalDate();
  if (!isValidDate(entry_date)) {
    return res.status(400).json({ error: 'Invalid date format. Use YYYY-MM-DD' });
  }

  amount = roundAmount(parseFloat(amount));
  if (isNaN(amount) || amount <= 0) {
    return res.status(400).json({ error: 'Amount must be a positive number' });
  }

  qRun(
    'INSERT INTO entries (entry_date, description, notes, amount, entry_type, created_by) VALUES (?, ?, ?, ?, ?, ?)',
    [entry_date, description, notes || '', amount, entry_type, req.user.id]
  );

  const entry = getOne('SELECT * FROM entries WHERE id = ?', [maxId('entries')]);
  res.status(201).json(entry);
});

router.delete('/entries/:id', authenticate, adminOnly, (req, res) => {
  const result = qRun('DELETE FROM entries WHERE id = ?', [req.params.id]);
  if (result.changes === 0) return res.status(404).json({ error: 'Entry not found' });
  res.json({ success: true });
});

// ─── Dues ───────────────────────────────────────────────────────

router.get('/dues', authenticate, (req, res) => {
  const dues = getAll(`
    SELECT d.id, d.client_name, d.amount as original_amount, d.note, d.created_at,
           COALESCE((SELECT SUM(c.amount) FROM collections c WHERE c.due_id = d.id), 0) as collected
    FROM dues d
    ORDER BY d.created_at DESC
  `);

  dues.forEach(d => {
    d.pending = d.original_amount - d.collected;
  });

  res.json(dues);
});

router.post('/dues', authenticate, (req, res) => {
  const { client_name, amount: rawAmount, note } = req.body;
  if (!client_name || !rawAmount) {
    return res.status(400).json({ error: 'client_name and amount required' });
  }

  const amount = roundAmount(parseFloat(rawAmount));
  if (isNaN(amount) || amount <= 0) {
    return res.status(400).json({ error: 'Amount must be a positive number' });
  }

  qRun('INSERT INTO dues (client_name, amount, note, created_by) VALUES (?, ?, ?, ?)',
    [client_name, amount, note || '', req.user.id]);

  const due = getOne('SELECT * FROM dues WHERE id = ?', [maxId('dues')]);
  res.status(201).json(due);
});

router.post('/dues/:id/collect', authenticate, (req, res) => {
  const rawAmount = req.body.amount;
  if (!rawAmount || rawAmount <= 0) {
    return res.status(400).json({ error: 'Valid collection amount required' });
  }

  const amount = roundAmount(parseFloat(rawAmount));
  if (isNaN(amount) || amount <= 0) {
    return res.status(400).json({ error: 'Amount must be a positive number' });
  }

  const due = getOne('SELECT * FROM dues WHERE id = ?', [req.params.id]);
  if (!due) return res.status(404).json({ error: 'Due not found' });

  const row = getOne('SELECT COALESCE(SUM(amount), 0) as total FROM collections WHERE due_id = ?', [req.params.id]);
  const collectedSoFar = row.total;
  const pending = due.amount - collectedSoFar;

  if (amount > pending) {
    return res.status(400).json({ error: `Collection amount exceeds pending balance (Tk ${pending})` });
  }

  qRun('INSERT INTO collections (due_id, amount, collected_by) VALUES (?, ?, ?)', [req.params.id, amount, req.user.id]);

  const updatedRow = getOne('SELECT COALESCE(SUM(amount), 0) as total FROM collections WHERE due_id = ?', [req.params.id]);
  const remaining = due.amount - updatedRow.total;

  res.json({ success: true, collected: updatedRow.total, pending: remaining });
});

router.delete('/dues/:id', authenticate, adminOnly, (req, res) => {
  qRun('DELETE FROM collections WHERE due_id = ?', [req.params.id]);
  const result = qRun('DELETE FROM dues WHERE id = ?', [req.params.id]);
  if (result.changes === 0) return res.status(404).json({ error: 'Due not found' });
  res.json({ success: true });
});

// ─── Supplier Payments ──────────────────────────────────────────

router.get('/supplier-payments', authenticate, (req, res) => {
  const payments = getAll(`
    SELECT sp.id, sp.supplier_name, sp.amount as original_amount, sp.note, sp.created_at,
           COALESCE((SELECT SUM(pr.amount) FROM supplier_pay_records pr WHERE pr.supplier_payment_id = sp.id), 0) as paid
    FROM supplier_payments sp
    ORDER BY sp.created_at DESC
  `);

  payments.forEach(p => {
    p.pending = p.original_amount - p.paid;
  });

  res.json(payments);
});

router.post('/supplier-payments', authenticate, (req, res) => {
  const { supplier_name, amount: rawAmount, note } = req.body;
  if (!supplier_name || !rawAmount) {
    return res.status(400).json({ error: 'supplier_name and amount required' });
  }

  const amount = roundAmount(parseFloat(rawAmount));
  if (isNaN(amount) || amount <= 0) {
    return res.status(400).json({ error: 'Amount must be a positive number' });
  }

  qRun('INSERT INTO supplier_payments (supplier_name, amount, note, created_by) VALUES (?, ?, ?, ?)',
    [supplier_name, amount, note || '', req.user.id]);

  const payment = getOne('SELECT * FROM supplier_payments WHERE id = ?', [maxId('supplier_payments')]);
  res.status(201).json(payment);
});

router.post('/supplier-payments/:id/pay', authenticate, (req, res) => {
  const rawAmount = req.body.amount;
  if (!rawAmount || rawAmount <= 0) {
    return res.status(400).json({ error: 'Valid payment amount required' });
  }

  const amount = roundAmount(parseFloat(rawAmount));
  if (isNaN(amount) || amount <= 0) {
    return res.status(400).json({ error: 'Amount must be a positive number' });
  }

  const payment = getOne('SELECT * FROM supplier_payments WHERE id = ?', [req.params.id]);
  if (!payment) return res.status(404).json({ error: 'Supplier payment record not found' });

  const row = getOne('SELECT COALESCE(SUM(amount), 0) as total FROM supplier_pay_records WHERE supplier_payment_id = ?', [req.params.id]);
  const paidSoFar = row.total;
  const pending = payment.amount - paidSoFar;

  if (amount > pending) {
    return res.status(400).json({ error: `Payment amount exceeds pending balance (Tk ${pending})` });
  }

  qRun('INSERT INTO supplier_pay_records (supplier_payment_id, amount, paid_by) VALUES (?, ?, ?)',
    [req.params.id, amount, req.user.id]);

  const updatedRow = getOne('SELECT COALESCE(SUM(amount), 0) as total FROM supplier_pay_records WHERE supplier_payment_id = ?', [req.params.id]);
  const remaining = payment.amount - updatedRow.total;

  res.json({ success: true, paid: updatedRow.total, pending: remaining });
});

router.delete('/supplier-payments/:id', authenticate, adminOnly, (req, res) => {
  qRun('DELETE FROM supplier_pay_records WHERE supplier_payment_id = ?', [req.params.id]);
  const result = qRun('DELETE FROM supplier_payments WHERE id = ?', [req.params.id]);
  if (result.changes === 0) return res.status(404).json({ error: 'Supplier payment not found' });
  res.json({ success: true });
});

// ─── Dashboard ──────────────────────────────────────────────────

router.get('/dashboard/summary', authenticate, (req, res) => {
  const today = getLocalDate();

  const settingsRow = getOne('SELECT value FROM settings WHERE key = ?', ['opening_balance']);
  const openingBalance = settingsRow ? parseFloat(settingsRow.value) : 0;

  const mainRow = getOne("SELECT COALESCE(SUM(amount), 0) as total FROM entries WHERE entry_type = 'main' AND entry_date = ?", [today]);
  const mainTotal = mainRow.total;

  const cashRow = getOne("SELECT COALESCE(SUM(amount), 0) as total FROM entries WHERE entry_type = 'cashout' AND entry_date = ?", [today]);
  const cashOutTotal = cashRow.total;

  const duesRow = getOne(`
    SELECT COALESCE(SUM(d.amount - COALESCE((SELECT SUM(c.amount) FROM collections c WHERE c.due_id = d.id), 0)), 0) as total FROM dues d
  `);
  const totalDues = duesRow.total;

  const collectedRow = getOne(
    'SELECT COALESCE(SUM(c.amount), 0) as total FROM collections c WHERE date(c.collected_at) = ?', [today]
  );

  res.json({
    openingBalance: roundAmount(openingBalance),
    mainLedgerTotal: roundAmount(mainTotal),
    cashOutTotal: roundAmount(cashOutTotal),
    netLedgerTotal: roundAmount(openingBalance + mainTotal - cashOutTotal),
    totalDues: roundAmount(totalDues),
    totalCollectedToday: roundAmount(collectedRow.total)
  });
});

router.get('/dashboard/charts', authenticate, (req, res) => {
  const topItems = getAll(`
    SELECT description, SUM(amount) as total
    FROM entries WHERE entry_type = 'main'
    GROUP BY description ORDER BY total DESC LIMIT 6
  `);

  const cashOutByPerson = getAll(`
    SELECT description, SUM(amount) as total
    FROM entries WHERE entry_type = 'cashout'
    GROUP BY description ORDER BY total DESC
  `);

  res.json({ topItems, cashOutByPerson });
});

// ─── Reports ────────────────────────────────────────────────────

router.get('/reports/daily', authenticate, (req, res) => {
  const { date } = req.query;
  const reportDate = (date && isValidDate(date)) ? date : getLocalDate();

  const settingsRow = getOne('SELECT value FROM settings WHERE key = ?', ['opening_balance']);
  const openingBalance = settingsRow ? parseFloat(settingsRow.value) : 0;

  const mainEntries = getAll(
    `SELECT e.*, u.display_name as created_by_name
     FROM entries e LEFT JOIN users u ON e.created_by = u.id
     WHERE e.entry_date = ? AND e.entry_type = 'main' ORDER BY e.id ASC`, [reportDate]
  );

  const cashOutEntries = getAll(
    `SELECT e.*, u.display_name as created_by_name
     FROM entries e LEFT JOIN users u ON e.created_by = u.id
     WHERE e.entry_date = ? AND e.entry_type = 'cashout' ORDER BY e.id ASC`, [reportDate]
  );

  const mainTotal = roundAmount(mainEntries.reduce((s, e) => s + e.amount, 0));
  const cashOutTotal = roundAmount(cashOutEntries.reduce((s, e) => s + e.amount, 0));

  res.json({
    date: reportDate,
    openingBalance,
    mainEntries,
    cashOutEntries,
    mainTotal,
    cashOutTotal,
    netTotal: roundAmount(openingBalance + mainTotal - cashOutTotal)
  });
});

module.exports = router;
