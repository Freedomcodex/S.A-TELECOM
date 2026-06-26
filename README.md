# S.A TELECOM — Ledger Management System

A production-ready, multi-user ledger management system built for small telecom shops. Tracks daily sales, cash distributions, client dues, supplier payments, and generates financial reports with real-time dashboards.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Node.js + Express |
| Database | SQLite via sql.js (pure WASM — no native build tools needed) |
| Auth | JWT (JSON Web Tokens) + bcrypt password hashing |
| Frontend | Vanilla HTML/CSS/JS + Tailwind CSS + Chart.js |
| Security | Helmet headers, CORS restriction, input validation |

## Features

- **Dashboard** — Real-time overview with opening balance, totals, charts, outstanding dues
- **Sell Entry** — Record main ledger entries and cash-out transactions with date, description, notes
- **Reports** — Daily financial summaries with CSV export and print support
- **Dues & Collection** — Track client credits, collect partial payments
- **Supplier Payments** — Manage supplier payables with partial payment tracking
- **POS Mode** — Add due during sale (auto-creates ledger entry + due record)
- **Multi-user** — Admin and staff roles with JWT authentication
- **Bulletproof Backup** — Auto-backup every 5 minutes, hourly + daily rotation, startup integrity check, auto-recovery from corruption

## Quick Start

```bash
npm install
node server.js
```

Open `http://localhost:3000` in your browser.

Default login: **admin** / **admin123**

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Server port |
| `JWT_SECRET` | (built-in) | Secret key for JWT tokens — change in production |
| `ALLOWED_ORIGIN` | `http://localhost:3000` | CORS allowed origin — set `*` for ngrok/public access |

## Project Structure

```
SATELECOM/
├── server.js           # Express entry point, CORS, helmet, shutdown hooks
├── db.js               # SQLite wrapper, schema, backup/recovery system
├── routes.js           # All REST API endpoints
├── middleware.js        # JWT auth, admin role check
├── package.json
├── public/
│   └── index.html      # Full SPA frontend (login, dashboard, entry, reports, dues, backup)
└── data/
    ├── satelcom.db     # SQLite database (auto-created, gitignored)
    ├── backups/        # Auto-backups (hourly + daily + startup)
    └── exports/        # JSON data exports
```

## API Endpoints

### Auth
- `POST /api/auth/login` — Login, returns JWT
- `GET /api/auth/me` — Get current user

### Entries
- `GET /api/entries` — List all entries
- `POST /api/entries` — Create entry (main or cashout)

### Dues
- `GET /api/dues` — List dues with pending amounts
- `POST /api/dues` — Add new due
- `POST /api/dues/:id/collect` — Collect payment

### Supplier Payments
- `GET /api/supplier-payments` — List supplier payables
- `POST /api/supplier-payments` — Add payable
- `POST /api/supplier-payments/:id/pay` — Record payment

### Dashboard & Reports
- `GET /api/dashboard/summary` — Dashboard totals
- `GET /api/dashboard/charts` — Chart data
- `GET /api/reports/daily?date=YYYY-MM-DD` — Daily report

### Backup & Recovery
- `GET /api/backup/check` — Database integrity check
- `POST /api/backup/create` — Manual backup
- `GET /api/backup/list` — List all backups
- `POST /api/backup/restore` — Restore from backup
- `GET /api/backup/export/download` — Export all data as JSON
- `POST /api/backup/import` — Import data from JSON

## Backup System

- **Auto-backup on startup** + every 5 min (hourly) + daily at midnight
- **Integrity check** on every server boot via `PRAGMA integrity_check`
- **Auto-recovery** — If the database is corrupted, automatically restores from the latest valid backup
- **Keeps** 12 hourly, 30 daily, 24 auto backups
- **Export/Import** — Full data export to JSON, restore from JSON

## Running on Multiple Devices (LAN)

```bash
set ALLOWED_ORIGIN=*
node server.js
```

Access from any device on your network: `http://<your-local-ip>:3000`

## Public Access via Ngrok

```bash
ngrok http 3000
```

Use the public URL provided by ngrok to access from anywhere.

## License

Private — S.A TELECOM
