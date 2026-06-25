const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');
const { initDb, backupDb } = require('./db');
const routes = require('./routes');

const app = express();
const PORT = process.env.PORT || 3000;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || `http://localhost:${PORT}`;

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

app.use(cors({
  origin: ALLOWED_ORIGIN,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.use('/api', routes);

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

initDb().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`S.A TELECOM Ledger System running at http://localhost:${PORT}`);
    console.log(`Access from other devices: http://<your-ip>:${PORT}`);
    console.log('Default login: admin / admin123');
  });
}).catch(err => {
  console.error('Failed to initialize database:', err);
  process.exit(1);
});

process.on('SIGINT', () => { backupDb(); process.exit(0); });
process.on('SIGTERM', () => { backupDb(); process.exit(0); });
