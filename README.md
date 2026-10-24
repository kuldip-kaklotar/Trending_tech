# VoltTrack backend (Node.js + Express + PostgreSQL) - customers first

## What you have
- `server.js` API: `/api/health`, `/api/auth/login`, `/api/customers` (GET/POST/PUT/DELETE, restore, import)
- `migrate.js` + `migrations/001_init.sql`: creates tables on every start (idempotent)
- Login (JWT, 12 h), roles `admin` and `staff`. Staff can view/add/edit; only admin can archive, restore, import.
- Delete = archive (soft delete), so invoices and warranties never lose their customer.

## Deploy on Render
1. Put this folder in your GitHub repo as `backend/` (keep the website's `index.html` where it is).
2. Render -> New -> Web Service -> select the repo.
   - Root Directory: `backend`  - Build Command: `npm install`  - Start Command: `npm start`
   - Region: same as `volttrack-db`  - Health Check Path: `/api/health`
3. Environment variables (Environment tab):
   - `DATABASE_URL` = the **Internal Database URL** of `volttrack-db` (Render dashboard -> volttrack-db -> Connections)
   - `JWT_SECRET` = 32+ random characters
   - `FRONTEND_ORIGIN` = `https://kk-dev-app.onrender.com`
   - `ADMIN_EMAIL` and `ADMIN_PASSWORD` (10+ chars) = your first admin login
4. Deploy. Open `https://YOUR-API.onrender.com/api/health`, expect `{"status":"ok","db":"up",...}`.
5. In the website's `index.html` set one line: `const API_URL='https://YOUR-API.onrender.com';`, commit, let the static site redeploy.
6. Open the site, sign in as the admin, go to Customers and click **Import customers saved in this browser**. Do this on the browser that holds your current data, before clearing site data. It never creates duplicates (matches by customer ID and bike registration number) and can be run again safely.

## Security notes
- The database URL exists only in Render's environment, never in the website.
- Passwords are bcrypt-hashed; login is rate-limited; all customer routes need a valid token; queries are parameterized; CORS allows only `FRONTEND_ORIGIN`.
- The token is kept in the browser tab's sessionStorage and cleared when the tab closes.
- Creating more staff users has no screen yet. Insert a row in `users` with a bcrypt hash and role `staff`, or ask for a user-admin screen.
- Render free web services sleep when idle; the first request after a pause can take about a minute.

## Not migrated yet (by design)
Batteries, purchases, invoices, warranty and SMS data still live in each browser's localStorage. Purchases keep a snapshot of the customer, so old invoices still print correctly.
