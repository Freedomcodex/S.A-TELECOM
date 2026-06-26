const jwt = require('jsonwebtoken');
const { getOne } = require('./db');

const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production';

const ALL_PERMISSIONS = [
  'add_sale',
  'add_due',
  'collect_due',
  'view_report',
  'search_customer',
  'view_dashboard',
  'backup_recovery',
  'delete_entries',
  'change_settings',
  'view_profit',
  'manage_users',
  'manage_suppliers'
];

function generateToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role, display_name: user.display_name },
    JWT_SECRET,
    { expiresIn: '24h' }
  );
}

function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

function requirePermission(perm) {
  return (req, res, next) => {
    if (req.user.role === 'admin') return next();
    const user = getOne('SELECT permissions FROM users WHERE id = ?', [req.user.id]);
    const perms = user && user.permissions ? user.permissions.split(',').filter(Boolean) : [];
    if (perms.includes(perm)) return next();
    return res.status(403).json({ error: 'Permission denied: ' + perm });
  };
}

function getUserPermissions(userId) {
  const user = getOne('SELECT permissions FROM users WHERE id = ?', [userId]);
  if (!user) return [];
  return user.permissions ? user.permissions.split(',').filter(Boolean) : [];
}

module.exports = { generateToken, authenticate, adminOnly, requirePermission, getUserPermissions, ALL_PERMISSIONS, JWT_SECRET };
