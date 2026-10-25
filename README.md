# VoltTrack backend (Node.js + Express + PostgreSQL)

## Files (flat layout, all in the repo root next to package.json)
| File | Purpose |
|---|---|
| `server.js` | API server, customers API, health check |
| `auth.js` | **new** login, roles/permissions, profile, user management |
| `migrate.js` | runs the numbered SQL files once each |
| `001_init.sql` | users + customers tables (already applied on your database) |
| `002_users.sql` | **new** adds name, active, token_version, last_login to `users` (additive, keeps all data) |
| `package.json` | dependencies and `npm start` |

## Roles
- **Admin** (`admin` in PostgreSQL): everything, including Users, Settings, Suppliers, archive/restore/import customers.
- **Normal User** (`staff` in PostgreSQL): Dashboard, Customers (view/add/edit), Battery Products and Stock (view only, no cost prices), Purchases, Invoices, Warranty, Reports, My Profile.
- The role is read from the database on every request. The token holds only the user id and a version number, so a role change, deactivation or password reset takes effect immediately and old tokens stop working. A client can never choose or send a role.
- There is no public sign-up. Only an admin can create accounts. A user cannot change their own role, email or active state.

## Environment variables (Render -> web service -> Environment)
`DATABASE_URL` (internal URL of volttrack-db), `JWT_SECRET` (32+ chars), `FRONTEND_ORIGIN` (`https://trending-tech.onrender.com`),
`ADMIN_EMAIL` + `ADMIN_PASSWORD` (10+ chars), optional `STAFF_EMAIL` + `STAFF_PASSWORD` (10+ chars, different email).
Passwords: set `ADMIN_RESET=true` / `STAFF_RESET=true` for one deploy to overwrite a password, then delete the variable.
After the first admin exists you can create further users from the app (Users page) and no longer need the STAFF_* variables.

## Deploy
1. Add `auth.js` and `002_users.sql` to the repo root, replace `server.js`, commit and push. Render deploys automatically.
2. Logs should show `applied: 002_users.sql`, then `VoltTrack API listening`.
3. Open `/api/health` on the service: `{"status":"ok","db":"up"}`.

## Security notes
- Passwords are bcrypt-hashed (cost 12), 10+ characters. Login and password change are rate-limited. Wrong email and wrong password give the same message.
- All queries are parameterized. CORS allows only `FRONTEND_ORIGIN`. API responses are not cacheable.
- Batteries, purchases, invoices, warranty and SMS data still live in each browser, so for those modules the Normal User limits are screen-level only. Server-side enforcement applies to customers and users now, and will cover the other modules as they move to PostgreSQL.
