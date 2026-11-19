require("dotenv").config();

const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("node:crypto");
const path = require("node:path");
const fs = require("node:fs");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === "production";
const sessionSecret = process.env.SESSION_SECRET || "";

if (sessionSecret.length < 32) {
  console.error("SESSION_SECRET must be at least 32 characters. Set it in .env.");
  process.exit(1);
}
if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD ||
    process.env.ADMIN_PASSWORD.length < 14) {
  console.error("Set ADMIN_EMAIL and an ADMIN_PASSWORD of at least 14 characters in .env.");
  process.exit(1);
}

const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, "yuva-lakshya.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'All India',
    department TEXT NOT NULL DEFAULT '',
    qualification TEXT NOT NULL DEFAULT '',
    last_date TEXT NOT NULL DEFAULT '',
    official_url TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','published')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

const adminEmail = process.env.ADMIN_EMAIL.trim().toLowerCase();
const existingAdmin = db.prepare("SELECT id FROM admins WHERE email = ?").get(adminEmail);
if (!existingAdmin) {
  const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);
  db.prepare("INSERT INTO admins (email, password_hash) VALUES (?, ?)").run(adminEmail, hash);
  console.log(`Initial admin created for ${adminEmail}`);
} else {
  console.log(`Admin account already exists for ${adminEmail}; password was not reset.`);
}

app.disable("x-powered-by");
if (isProduction) app.set("trust proxy", 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: isProduction ? [] : null
    }
  }
}));
app.use(express.json({ limit: "30kb" }));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));

app.use(session({
  name: "yl.sid",
  store: new SQLiteStore({ db: "sessions.sqlite", dir: dataDir, table: "sessions" }),
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: isProduction,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 8
  }
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 8,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "बहुत अधिक प्रयास हुए। 15 मिनट बाद फिर कोशिश करें।" }
});

const categories = new Set([
  "सरकारी नौकरी", "एडमिट कार्ड", "रिजल्ट", "एडमिशन",
  "स्कॉलरशिप", "स्टडी मटेरियल", "अन्य अपडेट"
]);

function csrfToken(req) {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  return req.session.csrfToken;
}
function csrfGuard(req, res, next) {
  const sent = req.get("x-csrf-token") || "";
  const saved = req.session.csrfToken || "";
  const valid = sent.length === saved.length && saved.length > 0 &&
    crypto.timingSafeEqual(Buffer.from(sent), Buffer.from(saved));
  if (!valid) return res.status(403).json({ error: "सुरक्षा टोकन अमान्य है। पेज रीफ्रेश करें।" });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.adminId) return res.status(401).json({ error: "कृपया पहले लॉगिन करें।" });
  next();
}
function cleanText(value, max) {
  return typeof value === "string" ? value.trim().slice(0, max) : "";
}
function validatePost(body) {
  const post = {
    category: cleanText(body.category, 40),
    title: cleanText(body.title, 140),
    state: cleanText(body.state, 60) || "All India",
    department: cleanText(body.department, 80),
    qualification: cleanText(body.qualification, 80),
    last_date: cleanText(body.last_date, 60),
    official_url: cleanText(body.official_url, 500),
    details: cleanText(body.details, 3000),
    status: body.status === "published" ? "published" : "draft"
  };
  if (!categories.has(post.category)) return { error: "कैटेगरी सही नहीं है।" };
  if (post.title.length < 3) return { error: "शीर्षक कम से कम 3 अक्षरों का होना चाहिए।" };
  if (post.official_url) {
    try {
      const u = new URL(post.official_url);
      if (!["http:", "https:"].includes(u.protocol)) throw new Error();
    } catch { return { error: "आधिकारिक लिंक सही URL होना चाहिए।" }; }
  }
  return { post };
}

app.get("/api/csrf", (req, res) => res.json({ token: csrfToken(req) }));

app.post("/api/auth/login", loginLimiter, csrfGuard, async (req, res) => {
  const email = cleanText(req.body.email, 254).toLowerCase();
  const password = typeof req.body.password === "string" ? req.body.password : "";
  const admin = db.prepare("SELECT id, email, password_hash FROM admins WHERE email = ?").get(email);
  const ok = admin ? await bcrypt.compare(password, admin.password_hash) : false;
  if (!ok) return res.status(401).json({ error: "ईमेल या पासवर्ड सही नहीं है।" });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "लॉगिन नहीं हो सका।" });
    req.session.adminId = admin.id;
    req.session.adminEmail = admin.email;
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
    res.json({ ok: true, email: admin.email, csrfToken: req.session.csrfToken });
  });
});

app.get("/api/auth/me", (req, res) => {
  if (!req.session.adminId) return res.status(401).json({ authenticated: false });
  res.json({ authenticated: true, email: req.session.adminEmail, csrfToken: csrfToken(req) });
});

app.post("/api/auth/logout", requireAdmin, csrfGuard, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("yl.sid", { httpOnly: true, sameSite: "strict", secure: isProduction });
    res.json({ ok: true });
  });
});

app.get("/api/posts", (req, res) => {
  const rows = db.prepare(`SELECT id, category, title, state, department, qualification,
    last_date, official_url, details, created_at FROM posts
    WHERE status = 'published' ORDER BY created_at DESC`).all();
  res.json(rows);
});

app.get("/api/admin/posts", requireAdmin, (req, res) => {
  res.json(db.prepare("SELECT * FROM posts ORDER BY updated_at DESC, id DESC").all());
});

app.post("/api/admin/posts", requireAdmin, csrfGuard, (req, res) => {
  const result = validatePost(req.body);
  if (result.error) return res.status(400).json({ error: result.error });
  const p = result.post;
  const info = db.prepare(`INSERT INTO posts
    (category,title,state,department,qualification,last_date,official_url,details,status)
    VALUES (@category,@title,@state,@department,@qualification,@last_date,@official_url,@details,@status)`).run(p);
  res.status(201).json({ id: info.lastInsertRowid, ...p });
});

app.put("/api/admin/posts/:id", requireAdmin, csrfGuard, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: "ID सही नहीं है।" });
  const result = validatePost(req.body);
  if (result.error) return res.status(400).json({ error: result.error });
  const p = result.post;
  const info = db.prepare(`UPDATE posts SET category=@category,title=@title,state=@state,
    department=@department,qualification=@qualification,last_date=@last_date,
    official_url=@official_url,details=@details,status=@status,updated_at=CURRENT_TIMESTAMP
    WHERE id=@id`).run({ ...p, id });
  if (!info.changes) return res.status(404).json({ error: "पोस्ट नहीं मिली।" });
  res.json({ ok: true });
});

app.delete("/api/admin/posts/:id", requireAdmin, csrfGuard, (req, res) => {
  const id = Number(req.params.id);
  const info = db.prepare("DELETE FROM posts WHERE id = ?").run(id);
  if (!info.changes) return res.status(404).json({ error: "पोस्ट नहीं मिली।" });
  res.json({ ok: true });
});

app.use(express.static(path.join(__dirname, "public")));
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.listen(PORT, () => console.log(`Yuva Lakshya running at http://localhost:${PORT}`));
