const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const { getOne, getAll, qRun, maxId, backupDb, listBackups, restoreFromBackup, checkIntegrity, exportAllData, saveExportJson, importFromData, getLocalDate, isValidDate, roundAmount } = require('./db');
const { generateToken, authenticate, adminOnly, requirePermission, getUserPermissions, ALL_PERMISSIONS } = require('./middleware');

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

  const permissions = user.role === 'admin' ? ALL_PERMISSIONS : getUserPermissions(user.id);
  const token = generateToken(user);
  res.json({
    token,
    user: { id: user.id, username: user.username, role: user.role, display_name: user.display_name, permissions }
  });
});

// ─── User Management ────────────────────────────────────────────

router.get('/users', authenticate, adminOnly, (req, res) => {
  const users = getAll('SELECT id, username, display_name, role, permissions, created_at FROM users ORDER BY id ASC');
  res.json(users.map(u => ({
    ...u,
    permissions: u.role === 'admin' ? ALL_PERMISSIONS : (u.permissions ? u.permissions.split(',').filter(Boolean) : [])
  })));
});

router.post('/users', authenticate, adminOnly, (req, res) => {
  const { username, password, display_name, role, permissions } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  const existing = getOne('SELECT id FROM users WHERE username = ?', [username]);
  if (existing) {
    return res.status(409).json({ error: 'Username already exists' });
  }
  const hash = bcrypt.hashSync(password, 10);
  const userRole = role === 'admin' ? 'admin' : 'staff';
  const perms = userRole === 'admin' ? '' : (Array.isArray(permissions) ? permissions.join(',') : '');
  qRun('INSERT INTO users (username, password_hash, display_name, role, permissions) VALUES (?, ?, ?, ?, ?)',
    [username, hash, display_name || username, userRole, perms]);
  res.status(201).json({ id: maxId('users'), username, display_name: display_name || username, role: userRole });
});

router.put('/users/:id', authenticate, adminOnly, (req, res) => {
  const { display_name, role, permissions, password } = req.body;
  const userId = parseInt(req.params.id);
  if (userId === 1) return res.status(400).json({ error: 'Cannot modify primary admin' });

  const user = getOne('SELECT * FROM users WHERE id = ?', [userId]);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (password) {
    const hash = bcrypt.hashSync(password, 10);
    qRun('UPDATE users SET password_hash = ? WHERE id = ?', [hash, userId]);
  }
  if (display_name !== undefined) {
    qRun('UPDATE users SET display_name = ? WHERE id = ?', [display_name, userId]);
  }
  if (role !== undefined) {
    const userRole = role === 'admin' ? 'admin' : 'staff';
    qRun('UPDATE users SET role = ? WHERE id = ?', [userRole, userId]);
  }
  if (permissions !== undefined && Array.isArray(permissions)) {
    qRun('UPDATE users SET permissions = ? WHERE id = ?', [permissions.join(','), userId]);
  }
  res.json({ success: true });
});

router.delete('/users/:id', authenticate, adminOnly, (req, res) => {
  const userId = parseInt(req.params.id);
  if (userId === 1) return res.status(400).json({ error: 'Cannot delete primary admin' });
  const result = qRun('DELETE FROM users WHERE id = ?', [userId]);
  if (result.changes === 0) return res.status(404).json({ error: 'User not found' });
  res.json({ success: true });
});

router.get('/permissions', authenticate, adminOnly, (req, res) => {
  res.json(ALL_PERMISSIONS);
});

router.get('/auth/me', authenticate, (req, res) => {
  const permissions = req.user.role === 'admin' ? ALL_PERMISSIONS : getUserPermissions(req.user.id);
  res.json({ ...req.user, permissions });
});

// ─── Settings ───────────────────────────────────────────────────

router.get('/settings', authenticate, (req, res) => {
  const rows = getAll('SELECT key, value FROM settings');
  const map = {};
  rows.forEach(s => map[s.key] = s.value);
  res.json(map);
});

router.put('/settings', authenticate, requirePermission('change_settings'), (req, res) => {
  const { opening_balance, currency_symbol, shop_name, contact_phone, contact_email, contact_address } = req.body;
  if (opening_balance !== undefined) {
    qRun('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', ['opening_balance', String(opening_balance)]);
  }
  if (currency_symbol !== undefined) {
    qRun('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', ['currency_symbol', String(currency_symbol)]);
  }
  if (shop_name !== undefined) {
    qRun('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', ['shop_name', String(shop_name)]);
  }
  if (contact_phone !== undefined) {
    qRun('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', ['contact_phone', String(contact_phone)]);
  }
  if (contact_email !== undefined) {
    qRun('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', ['contact_email', String(contact_email)]);
  }
  if (contact_address !== undefined) {
    qRun('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', ['contact_address', String(contact_address)]);
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

router.post('/entries', authenticate, requirePermission('add_sale'), (req, res) => {
  let { entry_date, description, notes, amount, entry_type, customer_type, client_name, customer_id } = req.body;

  if (!description || !amount || !entry_type) {
    return res.status(400).json({ error: 'Description, amount, and entry_type required' });
  }
  if (!['main', 'cashout'].includes(entry_type)) {
    return res.status(400).json({ error: 'entry_type must be "main" or "cashout"' });
  }

  customer_type = customer_type || 'walkin';
  if (!['walkin', 'market'].includes(customer_type)) {
    return res.status(400).json({ error: 'customer_type must be "walkin" or "market"' });
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
    'INSERT INTO entries (entry_date, description, notes, amount, entry_type, customer_type, client_name, customer_id, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [entry_date, description, notes || '', amount, entry_type, customer_type, client_name || '', customer_id || null, req.user.id]
  );

  const entry = getOne('SELECT * FROM entries WHERE id = ?', [maxId('entries')]);
  res.status(201).json(entry);
});

router.delete('/entries/:id', authenticate, requirePermission('delete_entries'), (req, res) => {
  const result = qRun('DELETE FROM entries WHERE id = ?', [req.params.id]);
  if (result.changes === 0) return res.status(404).json({ error: 'Entry not found' });
  res.json({ success: true });
});

router.post('/market-sale', authenticate, requirePermission('add_sale'), (req, res) => {
  let { entry_date, customer_id, client_name, description, notes, amount, paid_now } = req.body;

  if (!client_name || !description || !amount) {
    return res.status(400).json({ error: 'Client name, description, and amount required' });
  }

  entry_date = entry_date || getLocalDate();
  if (!isValidDate(entry_date)) {
    return res.status(400).json({ error: 'Invalid date format. Use YYYY-MM-DD' });
  }

  amount = roundAmount(parseFloat(amount));
  paid_now = roundAmount(parseFloat(paid_now) || 0);
  if (isNaN(amount) || amount <= 0) {
    return res.status(400).json({ error: 'Amount must be a positive number' });
  }
  if (paid_now < 0 || paid_now > amount) {
    return res.status(400).json({ error: 'Paid amount must be between 0 and total' });
  }

  if (paid_now > 0) {
      qRun(
        'INSERT INTO entries (entry_date, description, notes, amount, entry_type, customer_type, client_name, customer_id, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [entry_date, client_name + ' (Market Sale)', notes || 'Market Sale', paid_now, 'main', 'market', client_name, customer_id || null, req.user.id]
      );
  }

  const due_amount = roundAmount(amount - paid_now);
  if (due_amount > 0) {
    qRun(
      'INSERT INTO dues (client_name, amount, note, created_by) VALUES (?, ?, ?, ?)',
      [client_name, due_amount, 'Market Sale: ' + description + (notes ? ' - ' + notes : ''), req.user.id]
    );
  }

  res.status(201).json({
    success: true,
    sale_amount: amount,
    paid: paid_now,
    due: due_amount,
    message: due_amount > 0
      ? 'Sale recorded. Due: Tk ' + due_amount + ' added for ' + client_name
      : 'Sale recorded. Full payment received.'
  });
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

router.post('/dues', authenticate, requirePermission('add_due'), (req, res) => {
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

router.post('/dues/:id/collect', authenticate, requirePermission('collect_due'), (req, res) => {
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

// ─── Suppliers CRUD ────────────────────────────────────────────

router.get('/suppliers', authenticate, (req, res) => {
  const suppliers = getAll(`
    SELECT s.*,
      COALESCE((SELECT SUM(sp.amount) FROM supplier_payments sp WHERE sp.supplier_id = s.id), 0) as total_payable,
      COALESCE((SELECT SUM(pr.amount) FROM supplier_pay_records pr JOIN supplier_payments sp ON pr.supplier_payment_id = sp.id WHERE sp.supplier_id = s.id), 0) as total_paid
    FROM suppliers s
    ORDER BY s.name ASC
  `);
  suppliers.forEach(s => { s.pending = s.total_payable - s.total_paid; });
  res.json(suppliers);
});

router.post('/suppliers', authenticate, (req, res) => {
  const { name, phone, address, email, note } = req.body;
  if (!name) return res.status(400).json({ error: 'Supplier name required' });
  const existing = getOne('SELECT id FROM suppliers WHERE name = ?', [name]);
  if (existing) return res.status(409).json({ error: 'Supplier name already exists' });
  qRun('INSERT INTO suppliers (name, phone, address, email, note, created_by) VALUES (?, ?, ?, ?, ?, ?)',
    [name, phone || '', address || '', email || '', note || '', req.user.id]);
  const supplier = getOne('SELECT * FROM suppliers WHERE id = ?', [maxId('suppliers')]);
  res.status(201).json(supplier);
});

router.put('/suppliers/:id', authenticate, (req, res) => {
  const { name, phone, address, email, note } = req.body;
  const sid = parseInt(req.params.id);
  const supplier = getOne('SELECT * FROM suppliers WHERE id = ?', [sid]);
  if (!supplier) return res.status(404).json({ error: 'Supplier not found' });
  qRun('UPDATE suppliers SET name=?, phone=?, address=?, email=?, note=? WHERE id=?',
    [name || supplier.name, phone !== undefined ? phone : supplier.phone,
     address !== undefined ? address : supplier.address,
     email !== undefined ? email : supplier.email,
     note !== undefined ? note : supplier.note, sid]);
  res.json(getOne('SELECT * FROM suppliers WHERE id = ?', [sid]));
});

router.delete('/suppliers/:id', authenticate, adminOnly, (req, res) => {
  const sid = parseInt(req.params.id);
  const payments = getOne('SELECT COUNT(*) as cnt FROM supplier_payments WHERE supplier_id = ?', [sid]);
  if (payments && payments.cnt > 0) {
    return res.status(400).json({ error: 'Cannot delete supplier with existing payments. Delete payments first.' });
  }
  const result = qRun('DELETE FROM suppliers WHERE id = ?', [sid]);
  if (result.changes === 0) return res.status(404).json({ error: 'Supplier not found' });
  res.json({ success: true });
});

router.get('/suppliers/select', authenticate, (req, res) => {
  res.json(getAll('SELECT id, name FROM suppliers ORDER BY name ASC'));
});

// ─── Customers CRUD ────────────────────────────────────────────

router.get('/customers', authenticate, (req, res) => {
  const customers = getAll('SELECT c.*, (SELECT COUNT(*) FROM entries e WHERE e.customer_id = c.id) as total_sales FROM customers c ORDER BY c.name ASC');
  res.json(customers);
});

router.post('/customers', authenticate, (req, res) => {
  const { name, phone, address, email, note } = req.body;
  if (!name) return res.status(400).json({ error: 'Customer name required' });
  const existing = getOne('SELECT id FROM customers WHERE name = ?', [name]);
  if (existing) return res.status(409).json({ error: 'Customer name already exists' });
  qRun('INSERT INTO customers (name, phone, address, email, note, created_by) VALUES (?, ?, ?, ?, ?, ?)',
    [name, phone || '', address || '', email || '', note || '', req.user.id]);
  const customer = getOne('SELECT * FROM customers WHERE id = ?', [maxId('customers')]);
  res.status(201).json(customer);
});

router.put('/customers/:id', authenticate, (req, res) => {
  const { name, phone, address, email, note } = req.body;
  const cid = parseInt(req.params.id);
  const customer = getOne('SELECT * FROM customers WHERE id = ?', [cid]);
  if (!customer) return res.status(404).json({ error: 'Customer not found' });
  qRun('UPDATE customers SET name=?, phone=?, address=?, email=?, note=? WHERE id=?',
    [name || customer.name, phone !== undefined ? phone : customer.phone,
     address !== undefined ? address : customer.address,
     email !== undefined ? email : customer.email,
     note !== undefined ? note : customer.note, cid]);
  res.json(getOne('SELECT * FROM customers WHERE id = ?', [cid]));
});

router.delete('/customers/:id', authenticate, adminOnly, (req, res) => {
  const cid = parseInt(req.params.id);
  const entries = getOne('SELECT COUNT(*) as cnt FROM entries WHERE customer_id = ?', [cid]);
  if (entries && entries.cnt > 0) {
    return res.status(400).json({ error: 'Cannot delete customer with existing entries. Remove entries first.' });
  }
  const result = qRun('DELETE FROM customers WHERE id = ?', [cid]);
  if (result.changes === 0) return res.status(404).json({ error: 'Customer not found' });
  res.json({ success: true });
});

router.get('/customers/select', authenticate, (req, res) => {
  res.json(getAll('SELECT id, name, phone FROM customers ORDER BY name ASC'));
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
  const { supplier_name, supplier_id, amount: rawAmount, note } = req.body;
  if (!supplier_name || !rawAmount) {
    return res.status(400).json({ error: 'supplier_name and amount required' });
  }

  const amount = roundAmount(parseFloat(rawAmount));
  if (isNaN(amount) || amount <= 0) {
    return res.status(400).json({ error: 'Amount must be a positive number' });
  }

  const sid = supplier_id ? parseInt(supplier_id) : null;

  qRun('INSERT INTO supplier_payments (supplier_id, supplier_name, amount, note, created_by) VALUES (?, ?, ?, ?, ?)',
    [sid, supplier_name, amount, note || '', req.user.id]);

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

  const totalSuppliers = getOne('SELECT COUNT(*) as cnt FROM suppliers');
  const totalCustomers = getOne('SELECT COUNT(*) as cnt FROM customers');

  res.json({
    openingBalance: roundAmount(openingBalance),
    mainLedgerTotal: roundAmount(mainTotal),
    cashOutTotal: roundAmount(cashOutTotal),
    netLedgerTotal: roundAmount(openingBalance + mainTotal - cashOutTotal),
    totalDues: roundAmount(totalDues),
    totalCollectedToday: roundAmount(collectedRow.total),
    totalSuppliers: totalSuppliers ? totalSuppliers.cnt : 0,
    totalCustomers: totalCustomers ? totalCustomers.cnt : 0
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

  const walkinEntries = mainEntries.filter(e => (e.customer_type || 'walkin') === 'walkin');
  const marketEntries = mainEntries.filter(e => e.customer_type === 'market');
  const walkinTotal = roundAmount(walkinEntries.reduce((s, e) => s + e.amount, 0));
  const marketTotal = roundAmount(marketEntries.reduce((s, e) => s + e.amount, 0));

  res.json({
    date: reportDate,
    openingBalance,
    mainEntries,
    cashOutEntries,
    mainTotal,
    cashOutTotal,
    walkinTotal,
    marketTotal,
    netTotal: roundAmount(openingBalance + mainTotal - cashOutTotal)
  });
});

// ─── Backup & Recovery ─────────────────────────────────────────

router.get('/backup/check', authenticate, requirePermission('backup_recovery'), (req, res) => {
  const result = checkIntegrity();
  res.json(result);
});

router.post('/backup/create', authenticate, requirePermission('backup_recovery'), (req, res) => {
  try {
    const file = backupDb('manual');
    if (file) res.json({ success: true, file: path.basename(file) });
    else res.status(500).json({ error: 'Backup failed' });
  } catch (e) {
    console.error('Backup create error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

router.get('/backup/list', authenticate, requirePermission('backup_recovery'), (req, res) => {
  res.json(listBackups());
});

router.post('/backup/restore', authenticate, adminOnly, (req, res) => {
  const { filename } = req.body;
  if (!filename) return res.status(400).json({ error: 'filename required' });
  const backupFile = path.join(__dirname, 'data', 'backups', filename);
  restoreFromBackup(backupFile).then(result => {
    if (result.ok) res.json(result);
    else res.status(400).json(result);
  }).catch(e => {
    console.error('Restore error:', e.message);
    res.status(500).json({ error: e.message });
  });
});

router.post('/backup/export', authenticate, adminOnly, (req, res) => {
  const filePath = saveExportJson();
  if (filePath) res.json({ success: true, file: require('path').basename(filePath) });
  else res.status(500).json({ error: 'Export failed' });
});

router.get('/backup/export/download', authenticate, adminOnly, (req, res) => {
  const data = exportAllData();
  if (!data) return res.status(500).json({ error: 'Export failed' });
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="satelcom-export-${getLocalDate()}.json"`);
  res.json(data);
});

router.post('/backup/import', authenticate, adminOnly, (req, res) => {
  const { data } = req.body;
  if (!data || typeof data !== 'object') return res.status(400).json({ error: 'data object required' });
  const result = importFromData(data);
  res.json(result);
});

router.delete('/admin/clear-data', authenticate, adminOnly, (req, res) => {
  qRun('DELETE FROM collections');
  qRun('DELETE FROM supplier_pay_records');
  qRun('DELETE FROM supplier_payments');
  qRun('DELETE FROM entries');
  qRun('DELETE FROM dues');
  qRun('DELETE FROM suppliers');
  qRun('DELETE FROM customers');
  qRun('DELETE FROM google_tokens');
  qRun('DELETE FROM settings');
  qRun("INSERT OR IGNORE INTO settings (key, value) VALUES ('opening_balance', '4300')");
  qRun("INSERT OR IGNORE INTO settings (key, value) VALUES ('currency_symbol', 'OMR')");
  qRun("INSERT OR IGNORE INTO settings (key, value) VALUES ('shop_name', 'S.A TELECOM')");
  qRun("INSERT OR IGNORE INTO settings (key, value) VALUES ('contact_phone', '')");
  qRun("INSERT OR IGNORE INTO settings (key, value) VALUES ('contact_email', '')");
  qRun("INSERT OR IGNORE INTO settings (key, value) VALUES ('contact_address', '')");
  const hash = require('bcryptjs').hashSync(process.env.ADMIN_PASSWORD || 'admin123', 10);
  qRun("UPDATE users SET password_hash=? WHERE id=1", [hash]);
  res.json({ success: true, message: 'All data cleared. Admin user preserved with default password. Settings reset to defaults.' });
});

// ─── Activity Feed ───────────────────────────────────────────────

router.get('/activity', authenticate, (req, res) => {
  const items = [];

  const recentEntries = getAll(`
    SELECT description, amount, entry_type, customer_type, client_name, e.created_at, u.display_name as user_name
    FROM entries e LEFT JOIN users u ON e.created_by = u.id
    ORDER BY e.id DESC LIMIT 15
  `);
  recentEntries.forEach(e => {
    const type = e.entry_type === 'cashout' ? 'Cash Out' : 'Sale';
    const name = e.customer_type === 'market' ? (e.client_name || e.description) : e.description;
    items.push({
      action: 'entry_added',
      message: `${e.user_name || 'User'} added ${type}: ${name} (+Tk ${e.amount.toLocaleString()})`,
      created_at: e.created_at
    });
  });

  const recentDues = getAll(`
    SELECT d.client_name, d.amount, d.created_at, u.display_name as user_name
    FROM dues d LEFT JOIN users u ON d.created_by = u.id
    ORDER BY d.id DESC LIMIT 10
  `);
  recentDues.forEach(d => {
    items.push({
      action: 'due_added',
      message: `${d.user_name || 'User'} added due: ${d.client_name} (Tk ${d.amount.toLocaleString()})`,
      created_at: d.created_at
    });
  });

  const recentCollections = getAll(`
    SELECT d.client_name, c.amount, c.collected_at, u.display_name as user_name
    FROM collections c
    LEFT JOIN dues d ON c.due_id = d.id
    LEFT JOIN users u ON c.collected_by = u.id
    ORDER BY c.id DESC LIMIT 10
  `);
  recentCollections.forEach(c => {
    items.push({
      action: 'due_collected',
      message: `${c.user_name || 'User'} collected Tk ${c.amount.toLocaleString()} from ${c.client_name || 'Client'}`,
      created_at: c.collected_at
    });
  });

  const recentSupplierRegistrations = getAll(`
    SELECT s.name, s.created_at, u.display_name as user_name
    FROM suppliers s LEFT JOIN users u ON s.created_by = u.id
    ORDER BY s.id DESC LIMIT 10
  `);
  recentSupplierRegistrations.forEach(s => {
    items.push({
      action: 'supplier_registered',
      message: `${s.user_name || 'User'} registered supplier: ${s.name}`,
      created_at: s.created_at
    });
  });

  const recentCustomerRegistrations = getAll(`
    SELECT c.name, c.created_at, u.display_name as user_name
    FROM customers c LEFT JOIN users u ON c.created_by = u.id
    ORDER BY c.id DESC LIMIT 10
  `);
  recentCustomerRegistrations.forEach(c => {
    items.push({
      action: 'customer_registered',
      message: `${c.user_name || 'User'} registered customer: ${c.name}`,
      created_at: c.created_at
    });
  });

  const recentSupplierPayments = getAll(`
    SELECT sp.supplier_name, sp.amount, sp.created_at, u.display_name as user_name
    FROM supplier_payments sp LEFT JOIN users u ON sp.created_by = u.id
    ORDER BY sp.id DESC LIMIT 10
  `);
  recentSupplierPayments.forEach(p => {
    items.push({
      action: 'supplier_added',
      message: `${p.user_name || 'User'} added supplier payable: ${p.supplier_name} (Tk ${p.amount.toLocaleString()})`,
      created_at: p.created_at
    });
  });

  const recentSupplierPayRecords = getAll(`
    SELECT sp.supplier_name, pr.amount, pr.paid_at, u.display_name as user_name
    FROM supplier_pay_records pr
    LEFT JOIN supplier_payments sp ON pr.supplier_payment_id = sp.id
    LEFT JOIN users u ON pr.paid_by = u.id
    ORDER BY pr.id DESC LIMIT 10
  `);
  recentSupplierPayRecords.forEach(r => {
    items.push({
      action: 'supplier_paid',
      message: `${r.user_name || 'User'} paid Tk ${r.amount.toLocaleString()} to ${r.supplier_name || 'Supplier'}`,
      created_at: r.paid_at
    });
  });

  items.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  res.json(items.slice(0, 20));
});

// ─── Google Drive Cloud Backup ───────────────────────────────────

const { google } = require('googleapis');

function resolveRedirectUri(req) {
  if (process.env.GOOGLE_REDIRECT_URI) return process.env.GOOGLE_REDIRECT_URI;
  const host = req ? req.get('host') : (process.env.BASE_URL || `localhost:${process.env.PORT || 3000}`);
  const proto = req && req.get('x-forwarded-proto') ? 'https' : (host?.includes('localhost') ? 'http' : 'https');
  return `${proto}://${host}/api/auth/google/callback`;
}

function getGoogleClient() {
  const row = getOne('SELECT * FROM google_tokens ORDER BY id DESC LIMIT 1');
  if (!row) return null;
  const oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET
  );
  oauth2Client.setCredentials({
    access_token: row.access_token,
    refresh_token: row.refresh_token,
    expiry_date: row.token_expiry ? new Date(row.token_expiry).getTime() : null
  });
  return oauth2Client;
}

async function refreshTokenIfNeeded() {
  const client = getGoogleClient();
  if (!client) return null;
  try {
    const token = await client.getAccessToken();
    const row = getOne('SELECT * FROM google_tokens ORDER BY id DESC LIMIT 1');
    if (row) {
      qRun('UPDATE google_tokens SET access_token=?, token_expiry=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
        [token.token, new Date(client.credentials.expiry_date).toISOString(), row.id]);
    }
    return client;
  } catch {
    return null;
  }
}

async function ensureDriveFolder(drive) {
  const res = await drive.files.list({
    q: "name='LedgerPro Backups' and mimeType='application/vnd.google-apps.folder' and trashed=false",
    fields: 'files(id,name)',
    spaces: 'drive'
  });
  if (res.data.files && res.data.files.length > 0) return res.data.files[0].id;
  const folder = await drive.files.create({
    requestBody: { name: 'LedgerPro Backups', mimeType: 'application/vnd.google-apps.folder' },
    fields: 'id'
  });
  return folder.data.id;
}

async function listDriveBackups(drive, folderId) {
  const res = await drive.files.list({
    q: `'${folderId}' in parents and name contains '.json' and trashed=false`,
    fields: 'files(id,name,size,createdTime,modifiedTime)',
    orderBy: 'modifiedTime desc',
    spaces: 'drive'
  });
  return res.data.files || [];
}

router.get('/auth/google', authenticate, (req, res) => {
  if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
    return res.status(400).json({ error: 'Google Drive not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.' });
  }
  const redirectUri = resolveRedirectUri(req);
  const oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    redirectUri
  );
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: ['https://www.googleapis.com/auth/drive.file'],
    prompt: 'consent'
  });
  res.redirect(url);
});

router.get('/auth/google/callback', authenticate, async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) return res.redirect('/?error=google_no_code');
    const redirectUri = resolveRedirectUri(req);
    const oauth2Client = new google.auth.OAuth2(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET,
      redirectUri
    );
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);

    // Get user email
    const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
    const userInfo = await oauth2.userinfo.get();
    const email = userInfo.data.email || '';

    // Delete old tokens and save new ones
    qRun('DELETE FROM google_tokens');
    qRun('INSERT INTO google_tokens (access_token, refresh_token, token_expiry, google_email) VALUES (?, ?, ?, ?)',
      [tokens.access_token, tokens.refresh_token || '', new Date(tokens.expiry_date).toISOString(), email]);

    // Try to create/reuse Drive folder on connect
    try {
      const drive = google.drive({ version: 'v3', auth: oauth2Client });
      await ensureDriveFolder(drive);
    } catch {}

    res.redirect('/?google_connected=1');
  } catch (e) {
    console.error('Google OAuth error:', e.message);
    res.redirect('/?error=google_auth_failed');
  }
});

router.get('/cloud/status', authenticate, async (req, res) => {
  const row = getOne('SELECT google_email FROM google_tokens ORDER BY id DESC LIMIT 1');
  const autoBackup = getOne("SELECT value FROM settings WHERE key='google_auto_backup'");
  const lastBackup = getOne("SELECT value FROM settings WHERE key='last_google_backup'");
  if (!row) return res.json({ connected: false, email: null, autoBackup: false, lastBackup: null });
  res.json({
    connected: true,
    email: row.google_email,
    autoBackup: autoBackup ? autoBackup.value === '1' : false,
    lastBackup: lastBackup ? lastBackup.value : null
  });
});

router.post('/cloud/backup', authenticate, async (req, res) => {
  const client = await refreshTokenIfNeeded();
  if (!client) return res.status(400).json({ error: 'Google Drive not connected. Go to Backup tab and connect your Google account.' });
  try {
    const drive = google.drive({ version: 'v3', auth: client });
    const folderId = await ensureDriveFolder(drive);

    // Export data
    const data = exportAllData();
    if (!data) return res.status(500).json({ error: 'Failed to export data' });

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const shopName = (getOne("SELECT value FROM settings WHERE key='shop_name'") || {}).value || 'Ledger';
    const fileName = `Ledger_${shopName.replace(/\s+/g, '_')}_${timestamp}.json`;
    const fileContent = JSON.stringify(data, null, 2);

    // Upload to Drive
    const response = await drive.files.create({
      requestBody: { name: fileName, parents: [folderId] },
      media: { mimeType: 'application/json', body: fileContent }
    });

    // Update last backup time
    qRun("INSERT OR REPLACE INTO settings (key, value) VALUES ('last_google_backup', ?)", [new Date().toISOString()]);

    // Cleanup old backups (keep last 30)
    const backups = await listDriveBackups(drive, folderId);
    if (backups.length > 30) {
      const toDelete = backups.slice(30);
      for (const b of toDelete) {
        try { await drive.files.delete({ fileId: b.id }); } catch {}
      }
    }

    res.json({ success: true, message: 'Backup uploaded to Google Drive!', file: fileName });
  } catch (e) {
    console.error('Drive backup error:', e.message);
    res.status(500).json({ error: 'Backup failed: ' + e.message });
  }
});

router.get('/cloud/backups', authenticate, async (req, res) => {
  const client = await refreshTokenIfNeeded();
  if (!client) return res.status(400).json({ error: 'Google Drive not connected.' });
  try {
    const drive = google.drive({ version: 'v3', auth: client });
    const folderId = await ensureDriveFolder(drive);
    const files = await listDriveBackups(drive, folderId);
    res.json(files.map(f => ({
      id: f.id,
      name: f.name,
      size: f.size ? parseInt(f.size) : 0,
      createdTime: f.createdTime,
      modifiedTime: f.modifiedTime
    })));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/cloud/restore', authenticate, async (req, res) => {
  const client = await refreshTokenIfNeeded();
  if (!client) return res.status(400).json({ error: 'Google Drive not connected.' });
  const { fileId } = req.body;
  if (!fileId) return res.status(400).json({ error: 'fileId required' });
  try {
    const drive = google.drive({ version: 'v3', auth: client });
    const response = await drive.files.get({ fileId, alt: 'media' }, { responseType: 'json' });
    const data = response.data;

    const result = importFromData(data);
    if (result.ok) {
      res.json({ success: true, message: 'Data restored from Google Drive backup!' });
    } else {
      res.status(500).json({ error: result.error });
    }
  } catch (e) {
    res.status(500).json({ error: 'Restore failed: ' + e.message });
  }
});

router.post('/cloud/auto', authenticate, (req, res) => {
  const { enabled } = req.body;
  qRun("INSERT OR REPLACE INTO settings (key, value) VALUES ('google_auto_backup', ?)", [enabled ? '1' : '0']);
  // Restart the auto-backup timer
  if (typeof restartGoogleAutoBackup === 'function') restartGoogleAutoBackup();
  res.json({ success: true, autoBackup: !!enabled });
});

router.delete('/cloud/disconnect', authenticate, (req, res) => {
  qRun('DELETE FROM google_tokens');
  qRun("INSERT OR REPLACE INTO settings (key, value) VALUES ('google_auto_backup', '0')");
  qRun("INSERT OR REPLACE INTO settings (key, value) VALUES ('last_google_backup', '')");
  res.json({ success: true, message: 'Google account disconnected.' });
});

// ─── Google Auto-Backup Timer ────────────────────────────────────

let googleBackupTimer = null;

async function runGoogleAutoBackup() {
  try {
    const setting = getOne("SELECT value FROM settings WHERE key='google_auto_backup'");
    if (!setting || setting.value !== '1') return;
    const token = getOne('SELECT id FROM google_tokens LIMIT 1');
    if (!token) return;

    const client = await refreshTokenIfNeeded();
    if (!client) return;
    const drive = google.drive({ version: 'v3', auth: client });
    const folderId = await ensureDriveFolder(drive);
    const data = exportAllData();
    if (!data) return;
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const shopName = (getOne("SELECT value FROM settings WHERE key='shop_name'") || {}).value || 'Ledger';
    const fileName = `Ledger_${shopName.replace(/\s+/g, '_')}_${timestamp}.json`;
    await drive.files.create({
      requestBody: { name: fileName, parents: [folderId] },
      media: { mimeType: 'application/json', body: JSON.stringify(data, null, 2) }
    });
    qRun("INSERT OR REPLACE INTO settings (key, value) VALUES ('last_google_backup', ?)", [new Date().toISOString()]);

    // Cleanup old backups
    const backups = await listDriveBackups(drive, folderId);
    if (backups.length > 30) {
      const toDelete = backups.slice(30);
      for (const b of toDelete) {
        try { await drive.files.delete({ fileId: b.id }); } catch {}
      }
    }
  } catch (e) {
    console.error('[Google Auto-Backup]', e.message);
  }
}

function restartGoogleAutoBackup() {
  if (googleBackupTimer) clearInterval(googleBackupTimer);
  googleBackupTimer = setInterval(runGoogleAutoBackup, 5 * 60 * 1000);
  // Also run once after 30 seconds
  setTimeout(runGoogleAutoBackup, 30000);
}

// Start auto-backup timer after module loads
setTimeout(restartGoogleAutoBackup, 5000);

module.exports = router;
