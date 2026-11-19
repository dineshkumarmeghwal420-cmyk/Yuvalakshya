# Yuva Lakshya — Backend Starter

This is a **working local starter project**, not a deployed website. It provides:
- Express backend and SQLite database
- Admin login with bcrypt password hashing
- Server-side sessions stored in SQLite
- HttpOnly, SameSite session cookie (Secure in production)
- Login rate limiting
- CSRF token checks on state-changing admin requests
- Draft / Published job and education posts
- Public homepage reads only published posts
- Admin dashboard for creating, editing, deleting and publishing posts

## Requirements
- Node.js 20 or newer
- npm

## Run locally
1. Extract the ZIP.
2. Open a terminal in the extracted `yuva_lakshya_backend_starter` folder.
3. Run `npm install`.
4. Copy `.env.example` to `.env`.
5. Edit `.env` and set:
   - a long random `SESSION_SECRET` (at least 32 characters)
   - your own `ADMIN_EMAIL`
   - a unique `ADMIN_PASSWORD` of at least 14 characters
6. Run `npm start`.
7. Open `http://localhost:3000` for the public site.
8. Open `http://localhost:3000/admin.html` for the admin login.

## Important security / deployment notes
- Do not upload `.env`, `data/`, or `node_modules/` to a public repository.
- Use HTTPS in production. Set `NODE_ENV=production` behind a correctly configured HTTPS reverse proxy.
- Use a strong unique admin password and keep it private.
- Back up the `data/` directory securely.
- SQLite is suitable for a small initial deployment. For larger traffic, consider managed PostgreSQL.
- Before public launch, configure hosting, domain DNS, HTTPS, automated backups, monitoring, and a password-reset/admin-recovery procedure.
- The starter creates the first admin only when that email does not already exist. Changing `.env` later does not reset an existing admin password.
- Do not publish a recruitment notice until the official notification, eligibility, fee, dates, and application link have been verified.

## API overview
- `GET /api/posts` — public published posts
- `GET /api/csrf` — obtain CSRF token
- `POST /api/auth/login` — admin login
- `GET /api/auth/me` — session check
- `POST /api/auth/logout` — logout
- `GET /api/admin/posts` — admin list
- `POST /api/admin/posts` — create
- `PUT /api/admin/posts/:id` — update
- `DELETE /api/admin/posts/:id` — delete

This starter has no public registration, no email delivery, no file/PDF upload, no automated job scraping, and no live government feed.
