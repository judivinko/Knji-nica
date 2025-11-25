// ONLINE KNJIZNICA • Full Server (Express + better-sqlite3)
// =================================================================================
const express = require("express");
const http = require("http");
const path = require("path");
const fs = require("fs");
const Database = require("better-sqlite3");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// ----------------- CONFIG -----------------
const PORT = parseInt(process.env.PORT || "3000", 10);
const HOST = process.env.HOST || "0.0.0.0";
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const ADMIN_KEY = process.env.ADMIN_KEY || "dev-admin-key";
const TOKEN_NAME = "token";
const DEFAULT_ADMIN_EMAIL = (process.env.DEFAULT_ADMIN_EMAIL || "judi.vinko81@gmail.com").toLowerCase();

// PROMJENA → koristimo knjižnica.db umjesto artefact.db
const DB_FILE = process.env.DB_PATH || path.join(__dirname, "data", "knjiznica.db");
fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });

// ----------------- PAYPAL -----------------
const USD_TO_GOLD = 1000;
const MIN_USD = 1;
const PAYPAL_MODE = (process.env.PAYPAL_MODE || "sandbox").toLowerCase(); // "live" | "sandbox"
const PAYPAL_BASE = PAYPAL_MODE === "live" ? "https://api-m.paypal.com" : "https://api-m.sandbox.paypal.com";
const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID || "";
const PAYPAL_SECRET = process.env.PAYPAL_SECRET || "";

// ----------------- STARTUP: cleanup '0*' images -----------------
function deleteFilesStartingWith0(rootDir) {
  try {
    if (!fs.existsSync(rootDir)) return { checked: 0, deleted: 0, found: [] };
    const stack = [rootDir];
    let deleted = 0, checked = 0;
    const found = [];
    while (stack.length) {
      const dir = stack.pop();
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const ent of entries) {
        const full = path.join(dir, ent.name);
        if (ent.isDirectory()) stack.push(full);
        else {
          checked++;
          if (ent.name.startsWith("0")) {
            found.push(full);
            try { fs.unlinkSync(full); deleted++; } catch (e) {}
          }
        }
      }
    }
    return { checked, deleted, found };
  } catch (e) {
    return { checked: 0, deleted: 0, found: [] };
  }
}

(() => {
  const dirImages = path.join(__dirname, "public", "images");
  const dirPublic = path.join(__dirname, "public");
  const r1 = deleteFilesStartingWith0(dirImages);
  let r = r1;
  if (r1.deleted === 0 && r1.checked === 0) {
    const r2 = deleteFilesStartingWith0(dirPublic);
    r = {
      checked: r1.checked + r2.checked,
      deleted: r1.deleted + r2.deleted,
      found: [...r1.found, ...r2.found]
    };
  }
  console.log(`[CLEANUP] Pregledano: ${r.checked}, obrisano: ${r.deleted}`);
})();

// ----------------- APP -----------------
const app = express();
const server = http.createServer(app);
app.set("trust proxy", 1);
app.use(express.json());
app.use(cookieParser());

// Static + pages
app.use(express.static(path.join(__dirname, "public")));
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/admin", (_req, res) => res.sendFile(path.join(__dirname, "public", "admin.html")));

// ----------------- DB -----------------
const db = new Database(DB_FILE);
db.pragma("journal_mode = WAL");

// ----------------- MIGRATIONS helper -----------------
function ensure(sql) {
  db.exec(sql);
}

// -------- Helpers --------
const nowISO = () => new Date().toISOString();
function isEmail(x){ return typeof x==="string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(x); }
function isPass(x){ return typeof x==="string" && x.length>=6; }
function signToken(u){ return jwt.sign({ uid:u.id, email:u.email }, JWT_SECRET, { expiresIn:"7d" }); }
function readToken(req){
  const t = req.cookies && req.cookies[TOKEN_NAME];
  if(!t) return null;
  try{ return jwt.verify(t, JWT_SECRET); }catch{ return null; }
}
function verifyTokenFromCookies(req) {
  const tok = readToken(req);
  if (!tok) return null;
  return { uid: tok.uid, email: tok.email };
}
function requireAuth(req) {
  const tok = readToken(req);
  if (!tok) throw new Error("Not logged in.");
  const u = db.prepare("SELECT id,is_disabled FROM users WHERE id=?").get(tok.uid);
  if (!u || u.is_disabled) throw new Error("Account disabled");
  return u.id;
}
function isAdmin(req) {
  const hdr = String(req.headers["x-admin-key"] || "");
  if (hdr && hdr === ADMIN_KEY) return true;

  const tok = readToken(req);
  if (!tok) return false;

  const r = db.prepare("SELECT is_admin, is_disabled FROM users WHERE id=?").get(tok.uid);
  return !!(r && r.is_admin === 1 && r.is_disabled !== 1);
}

// helper za HTTPS
function isReqSecure(req){
  return !!(req.secure || String(req.headers['x-forwarded-proto']||'').toLowerCase()==='https');
}

// -------- PayPal helpers --------
const fetch = global.fetch || ((...args) => import("node-fetch").then(({ default: f }) => f(...args)));
async function paypalToken(){
  const res = await fetch(PAYPAL_BASE + "/v1/oauth2/token", {
    method: "POST",
    headers: {
      "Authorization": "Basic " + Buffer.from(PAYPAL_CLIENT_ID + ":" + PAYPAL_SECRET).toString("base64"),
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: "grant_type=client_credentials"
  });
  const data = await res.json();
  if(!res.ok) throw new Error("PayPal token fail: " + JSON.stringify(data));
  return data.access_token;
}
async function paypalGetOrder(accessToken, orderId){
  const res = await fetch(PAYPAL_BASE + "/v2/checkout/orders/" + encodeURIComponent(orderId), {
    headers: { "Authorization": "Bearer " + accessToken }
  });
  const data = await res.json();
  if(!res.ok) throw new Error("PayPal order fail: " + JSON.stringify(data));
  return data;
}

// ----------------- PAYPAL config + create-order -----------------
app.get("/api/paypal/config", (_req, res) => {
  try {
    const configured = !!PAYPAL_CLIENT_ID;
    return res.status(200).json({
      ok: configured,
      configured,
      client_id: configured ? PAYPAL_CLIENT_ID : null,
      mode: PAYPAL_MODE,
      currency: "USD",
      min_usd: MIN_USD
    });
  } catch (e) {
    return res.status(200).json({ ok:false, configured:false, error:String(e.message||e) });
  }
});

app.post("/api/paypal/create-order", async (req, res) => {
  try{
    let uid;
    try { uid = requireAuth(req); }
    catch { return res.status(401).json({ ok:false, error:"Not logged in" }); }

    if (!PAYPAL_CLIENT_ID || !PAYPAL_SECRET){
      return res.status(400).json({ ok:false, error:"PayPal not configured" });
    }
    const amount = Number(req.body?.amount_usd);
    if (!Number.isFinite(amount) || amount < MIN_USD) {
      return res.status(400).json({ ok:false, error:`Minimum is $${MIN_USD}` });
    }

    const access = await paypalToken();
    const resp = await fetch(PAYPAL_BASE + "/v2/checkout/orders", {
      method: "POST",
      headers: {
        "Authorization": "Bearer " + access,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        intent: "CAPTURE",
        purchase_units: [
          { amount: { currency_code: "USD", value: amount.toFixed(2) } }
        ],
        application_context: {
          shipping_preference: "NO_SHIPPING",
          user_action: "PAY_NOW",
        }
      })
    });
    const data = await resp.json();
    if (!resp.ok) {
      return res.status(400).json({ ok:false, error:"Create order failed", details:data });
    }
    return res.json({ ok:true, id: data.id });
  }catch(e){
    return res.status(500).json({ ok:false, error:String(e.message||e) });
  }
});

/* ---------- CORE TABLES (knjižnica verzija) ---------- */

ensure(`
  CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    pass_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    is_disabled INTEGER NOT NULL DEFAULT 0,
    balance_silver INTEGER NOT NULL DEFAULT 0,
    last_seen TEXT
  );
`);

ensure(`
  CREATE TABLE IF NOT EXISTS books(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    grade TEXT NOT NULL,
    name TEXT NOT NULL,
    pdf_path TEXT NOT NULL,
    price_silver INTEGER NOT NULL DEFAULT 0
  );
`);

ensure(`
  CREATE TABLE IF NOT EXISTS user_books(
    user_id INTEGER NOT NULL,
    book_id INTEGER NOT NULL,
    PRIMARY KEY(user_id, book_id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(book_id) REFERENCES books(id)
  );
`);

ensure(`
  CREATE TABLE IF NOT EXISTS gold_ledger(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    delta_s INTEGER NOT NULL,
    reason TEXT NOT NULL,
    ref TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);

ensure(`
  CREATE TABLE IF NOT EXISTS paypal_payments(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    paypal_order_id TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL,
    currency TEXT NOT NULL,
    amount REAL NOT NULL,
    credited_silver INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);

/* ----------------- SEED KNJIGA ----------------- */

// Dodaj knjigu ako ne postoji
function ensureBook(name, grade, price_silver, pdf_path) {
  const row = db.prepare("SELECT id FROM books WHERE name=? AND grade=?")
                .get(name, grade);

  if (row) {
    db.prepare("UPDATE books SET price_silver=?, pdf_path=? WHERE id=?")
      .run(price_silver, pdf_path, row.id);
    return row.id;
  }

  db.prepare("INSERT INTO books(name, grade, price_silver, pdf_path) VALUES (?,?,?,?)")
    .run(name, grade, price_silver, pdf_path);

  return db.prepare("SELECT id FROM books WHERE name=? AND grade=?")
    .get(name, grade).id;
}

/* ---------- DODAJ PRIMJER KNJIGA ---------- */

// 1. razred
ensureBook("Matematika 1", "1", 0, "/pdf/1/matematika1.pdf");
ensureBook("Bosanski jezik 1", "1", 0, "/pdf/1/bosanski1.pdf");
ensureBook("Moja okolina 1", "1", 0, "/pdf/1/okolina1.pdf");

// 2. razred
ensureBook("Matematika 2", "2", 0, "/pdf/2/matematika2.pdf");
ensureBook("Bosanski jezik 2", "2", 0, "/pdf/2/bosanski2.pdf");

// 1. srednja (1s)
ensureBook("Matematika 1s", "1s", 150, "/pdf/1s/matematika1s.pdf");
ensureBook("Engleski 1s", "1s", 120, "/pdf/1s/engleski1s.pdf");

// Ostalo
ensureBook("Programiranje JS", "ostalo", 500, "/pdf/ostalo/js.pdf");

// ----------------- AUTH -----------------
app.post("/api/register", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const rawEmail = String(email || "").trim().toLowerCase();

    if (!isEmail(rawEmail)) return res.status(400).json({ ok:false, error:"Bad email" });
    if (!isPass(password))  return res.status(400).json({ ok:false, error:"Password too short" });

    const exists = db.prepare(
      "SELECT id FROM users WHERE lower(email)=lower(?)"
    ).get(rawEmail);

    if (exists) return res.status(409).json({ ok:false, error:"Email taken" });

    const hash = bcrypt.hashSync(password, 10);

    db.prepare(`
      INSERT INTO users(email,pass_hash,created_at,is_admin,is_disabled,balance_silver,last_seen)
      VALUES (?,?,?,?,?,?,?)
    `).run(
      rawEmail,
      hash,
      nowISO(),
      0,
      0,
      0,
      nowISO()
    );

    return res.json({ ok:true });
  } catch (e) {
    return res.status(500).json({ ok:false, error:"Register failed" });
  }
});

// ----------------- LOGIN -----------------
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const rawEmail = String(email || "").trim().toLowerCase();

    if (!isEmail(rawEmail)) return res.status(400).json({ ok:false, error:"Bad email" });

    const u = db.prepare(
      "SELECT * FROM users WHERE lower(email)=lower(?)"
    ).get(rawEmail);

    if (!u) return res.status(404).json({ ok:false, error:"User not found" });
    if (u.is_disabled) return res.status(403).json({ ok:false, error:"Account disabled" });

    const ok = bcrypt.compareSync(password || "", u.pass_hash);
    if (!ok) return res.status(401).json({ ok:false, error:"Wrong password" });

    const token = signToken(u);

    res.cookie(TOKEN_NAME, token, {
      httpOnly: true,
      sameSite: "lax",
      secure: isReqSecure(req),
      path: "/",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    db.prepare("UPDATE users SET last_seen=? WHERE id=?").run(nowISO(), u.id);

    return res.json({ ok:true, user:{ id: u.id, email: u.email } });
  } catch (e) {
    return res.status(500).json({ ok:false, error:"Login failed" });
  }
});

// ----------------- LOGOUT -----------------
app.get("/api/logout", (req, res) => {
  const tok = readToken(req);
  if (tok) {
    try { db.prepare("UPDATE users SET last_seen=? WHERE id=?").run(nowISO(), tok.uid); } catch {}
  }

  res.clearCookie(TOKEN_NAME, {
    httpOnly: true,
    sameSite: "lax",
    secure: isReqSecure(req),
    path: "/"
  });

  return res.json({ ok:true });
});

// ----------------- ADMIN: BOOK MANAGEMENT -----------------

// Lista svih knjiga (admin)
app.get("/api/admin/books", (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ ok:false, error:"Unauthorized" });

  const rows = db.prepare(`
    SELECT id, name, grade, pdf_path, price_silver
    FROM books
    ORDER BY grade, name
  `).all();

  res.json({ ok:true, books: rows });
});

// Dodaj ili uredi knjigu (admin)
app.post("/api/admin/books/save", (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ ok:false, error:"Unauthorized" });

  const { id, name, grade, pdf_path, price_silver } = req.body || {};

  if (!name || !grade || !pdf_path) {
    return res.status(400).json({ ok:false, error:"Missing fields" });
  }

  const price = Math.max(0, parseInt(price_silver || 0, 10));

  if (id) {
    db.prepare(`
      UPDATE books
         SET name         = ?,
             grade        = ?,
             pdf_path     = ?,
             price_silver = ?
       WHERE id = ?
    `).run(String(name), String(grade), String(pdf_path), price, parseInt(id, 10));
  } else {
    db.prepare(`
      INSERT INTO books(name, grade, pdf_path, price_silver)
      VALUES (?,?,?,?)
    `).run(String(name), String(grade), String(pdf_path), price);
  }

  res.json({ ok:true });
});

// Obriši knjigu (admin) — sigurnija verzija
app.post("/api/admin/books/delete", (req, res) => {
  try {
    if (!isAdmin(req)) {
      return res.status(401).json({ ok: false, error: "Unauthorized" });
    }

    const bid = Number(req.body && req.body.id);
    if (!Number.isInteger(bid) || bid <= 0) {
      return res.status(400).json({ ok: false, error: "Bad id" });
    }

    // prvo obriši user_books, pa books (ako su uključeni foreign_keys)
    const tx = db.transaction((id) => {
      db.prepare("DELETE FROM user_books WHERE book_id=?").run(id);
      db.prepare("DELETE FROM books WHERE id=?").run(id);
    });

    tx(bid);

    return res.json({ ok: true });
  } catch (e) {
    console.error("[/api/admin/books/delete] error:", e);
    return res.status(500).json({ ok: false, error: String(e.message || e) });
  }
});

// ----------------- PAYPAL CONFIRM (KNJIŽNICA VERZIJA — BEZ BONUS CODE) -----------------
app.post("/api/paypal/confirm", async (req, res) => {
  try{
    let uid;
    try { uid = requireAuth(req); }
    catch { return res.status(401).json({ ok:false, error:"Not logged in" }); }

    if (!PAYPAL_CLIENT_ID || !PAYPAL_SECRET){
      return res.status(400).json({ ok:false, error:"PayPal not configured" });
    }

    const { orderId } = req.body || {};
    if (!orderId) return res.status(400).json({ ok:false, error:"orderId required" });

    const already = db.prepare(
      "SELECT credited_silver FROM paypal_payments WHERE paypal_order_id=?"
    ).get(String(orderId));

    if (already){
      const bal = db.prepare("SELECT balance_silver FROM users WHERE id=?").get(uid)?.balance_silver ?? 0;
      return res.json({ ok:true, balance_silver: bal, note:"already processed" });
    }

    const token = await paypalToken();
    const order = await paypalGetOrder(token, orderId);
    if (!order || order.status !== "COMPLETED"){
      return res.status(400).json({ ok:false, error:"Payment not completed", status: order?.status || "UNKNOWN" });
    }

    const pu         = order?.purchase_units?.[0];
    const captureAmt = pu?.payments?.captures?.[0]?.amount;
    const orderAmt   = pu?.amount;
    const amt        = captureAmt || orderAmt;

    const currency = amt?.currency_code;
    const paid     = Number(amt?.value);

    if (currency !== "USD" || !Number.isFinite(paid)) {
      return res.status(400).json({ ok:false, error: "Unsupported currency or invalid amount" });
    }
    if (paid < MIN_USD) {
      return res.status(400).json({ ok:false, error: `Minimum is $${MIN_USD}` });
    }

    const baseSilver = Math.floor(paid * USD_TO_GOLD * 100);

    const newBal = db.transaction(() => {
      const dupe = db.prepare("SELECT 1 FROM paypal_payments WHERE paypal_order_id=?").get(String(orderId));
      if (dupe) {
        const cur = db.prepare("SELECT balance_silver FROM users WHERE id=?").get(uid);
        return cur?.balance_silver ?? 0;
      }

      db.prepare(`
        INSERT INTO paypal_payments(paypal_order_id,user_id,currency,amount,credited_silver,created_at)
        VALUES (?,?,?,?,?,?)
      `).run(String(orderId), uid, String(currency), paid, baseSilver, nowISO());

      const cur = db.prepare("SELECT balance_silver FROM users WHERE id=?").get(uid);
      if (!cur) throw new Error("User not found");

      const updated = cur.balance_silver + baseSilver;
      db.prepare("UPDATE users SET balance_silver=? WHERE id=?").run(updated, uid);

      db.prepare(`
        INSERT INTO gold_ledger(user_id,delta_s,reason,ref,created_at)
        VALUES (?,?,?,?,?)
      `).run(uid, baseSilver, "PAYPAL_TOPUP", String(orderId), nowISO());

      return updated;
    })();

    return res.json({ ok:true, balance_silver: newBal });

  }catch(e){
    console.error("[/api/paypal/confirm] error:", e);
    return res.status(500).json({ ok:false, error:String(e.message || e) });
  }
});

//-----------------------------------------------------
// /api/me  (vraća podatke korisnika)
//-----------------------------------------------------
app.get("/api/me", (req, res) => {
  const tok = readToken(req);
  if (!tok) {
    return res.status(401).json({ ok:false });
  }

  const u = db.prepare(`
    SELECT id, email, is_admin, is_disabled, balance_silver, created_at, last_seen
    FROM users
    WHERE id=?
  `).get(tok.uid);

  if (!u) {
    res.clearCookie(TOKEN_NAME, { httpOnly:true, sameSite:"lax", secure:isReqSecure(req), path:"/" });
    return res.status(401).json({ ok:false });
  }

  return res.json({
    ok:true,
    user:{
      id: u.id,
      email: u.email,
      is_admin: !!u.is_admin,
      is_disabled: !!u.is_disabled,
      balance_silver: u.balance_silver,
      gold: Math.floor(u.balance_silver/100),
      silver: u.balance_silver % 100,
      created_at: u.created_at,
      last_seen: u.last_seen
    }
  });
});

//-----------------------------------------------------
// LISTA KNJIGA ZA RAZRED
// GET /api/books/:grade
//-----------------------------------------------------
app.get("/api/books/:grade", (req, res) => {
  try {
    const uid = requireAuth(req);
    const grade = String(req.params.grade);

    const rows = db.prepare(`
      SELECT
        b.id,
        b.name,
        b.grade,
        b.price_silver,
        b.pdf_path,
        (SELECT 1 FROM user_books ub WHERE ub.user_id = ? AND ub.book_id = b.id) AS owned
      FROM books b
      WHERE b.grade = ?
      ORDER BY b.name ASC
    `).all(uid, grade);

    return res.json({ ok:true, books: rows });
  } catch(e) {
    return res.status(401).json({ ok:false, error:"Unauthorized" });
  }
});

//-----------------------------------------------------
// KUPI KNJIGU
// POST /api/books/buy  { book_id }
//-----------------------------------------------------
app.post("/api/books/buy", (req, res) => {
  try {
    const uid = requireAuth(req);
    const { book_id } = req.body || {};
    const bid = parseInt(book_id, 10);

    if (!Number.isFinite(bid)) {
      return res.status(400).json({ ok:false, error:"Bad book_id" });
    }

    const b = db.prepare("SELECT * FROM books WHERE id=?").get(bid);
    if (!b) return res.status(404).json({ ok:false, error:"Book not found" });

    const owned = db.prepare("SELECT 1 FROM user_books WHERE user_id=? AND book_id=?").get(uid, bid);
    if (owned) {
      return res.json({ ok:true, owned:true, message:"already owned" });
    }

    const u = db.prepare("SELECT balance_silver FROM users WHERE id=?").get(uid);
    const bal = u.balance_silver|0;
    const price = b.price_silver|0;

    if (price === 0) {
      db.prepare("INSERT INTO user_books(user_id, book_id) VALUES (?,?)").run(uid, bid);
      return res.json({ ok:true, balance_silver:bal });
    }

    if (bal < price) {
      return res.status(400).json({ ok:false, error:"Not enough silver" });
    }

    const newBal = bal - price;

    const tx = db.transaction(() => {
      db.prepare("UPDATE users SET balance_silver=? WHERE id=?").run(newBal, uid);
      db.prepare("INSERT INTO user_books(user_id, book_id) VALUES (?,?)").run(uid, bid);
      db.prepare("INSERT INTO gold_ledger(user_id, delta_s, reason, ref, created_at) VALUES (?,?,?,?,?)")
        .run(uid, -price, "BUY_BOOK", String(bid), nowISO());
    });

    tx();

    return res.json({ ok:true, balance_silver:newBal });
  } catch (e) {
    return res.status(401).json({ ok:false, error:"Unauthorized" });
  }
});

//-----------------------------------------------------
// OTVORI KNJIGU (PDF link)
// GET /api/books/open/:id
//-----------------------------------------------------
app.get("/api/books/open/:id", (req, res) => {
  try {
    const uid = requireAuth(req);
    const bid = parseInt(req.params.id,10);

    const owned = db.prepare("SELECT 1 FROM user_books WHERE user_id=? AND book_id=?").get(uid, bid);
    if (!owned) return res.status(403).json({ ok:false, error:"You do not own this book" });

    const b = db.prepare("SELECT pdf_path FROM books WHERE id=?").get(bid);
    if (!b) return res.status(404).json({ ok:false, error:"Book not found" });

    return res.json({ ok:true, pdf: b.pdf_path });
  } catch(e) {
    return res.status(401).json({ ok:false });
  }
});

// ----------------- USER INVENTORY -----------------
app.get("/api/my/books", (req, res) => {
  let uid;
  try { uid = requireAuth(req); }
  catch { return res.status(401).json({ ok:false, error:"Not logged in" }); }

  const rows = db.prepare(`
    SELECT b.id, b.name, b.grade, b.pdf_path
    FROM user_books ub
    JOIN books b ON b.id = ub.book_id
    WHERE ub.user_id = ?
    ORDER BY b.grade, b.name
  `).all(uid);

  res.json({ ok:true, books: rows });
});

// ----------------- OPEN PDF (secure) -----------------
app.get("/api/book/pdf/:id", (req, res) => {
  let uid;
  try { uid = requireAuth(req); }
  catch { return res.status(401).json({ ok:false, error:"Not logged in" }); }

  const bid = parseInt(req.params.id, 10);
  if (!bid) return res.status(400).json({ ok:false, error:"Bad book id" });

  const owned = db.prepare(`
    SELECT 1 FROM user_books WHERE user_id=? AND book_id=?
  `).get(uid, bid);

  if (!owned)
    return res.status(403).json({ ok:false, error:"Not owned" });

  const row = db.prepare(`
    SELECT pdf_path FROM books WHERE id=?
  `).get(bid);

  if (!row) return res.status(404).json({ ok:false, error:"Book not found" });

  const file = path.join(__dirname, "public", row.pdf_path);

  if (!fs.existsSync(file))
    return res.status(404).json({ ok:false, error:"PDF missing" });

  res.sendFile(file);
});

// ----------------- DEFAULT ADMIN USER (optional) -----------------
(function ensureDefaultAdmin(){
  if (!DEFAULT_ADMIN_EMAIL) return;

  const have = db.prepare(
    "SELECT id, is_admin FROM users WHERE lower(email)=lower(?)"
  ).get(DEFAULT_ADMIN_EMAIL);

  if (!have) {
    const hash = bcrypt.hashSync("changeme", 10);

    db.prepare(`
      INSERT INTO users(email, pass_hash, created_at, is_admin, is_disabled, balance_silver, last_seen)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      DEFAULT_ADMIN_EMAIL,
      hash,
      nowISO(),
      1,
      0,
      0,
      nowISO()
    );

    console.log("[seed] created default admin:", DEFAULT_ADMIN_EMAIL);

  } else if (!have.is_admin) {
    db.prepare("UPDATE users SET is_admin=1 WHERE id=?").run(have.id);
    console.log("[seed] elevated admin:", DEFAULT_ADMIN_EMAIL);
  }
})();

// ----------------- HEALTH CHECK -----------------
app.get("/health", (_req, res) =>
  res.json({ ok: true, ts: Date.now() })
);

// ----------------- CATCH-ALL (Front-end) -----------------
app.get(/^\/(?!api\/).*/, (_req, res) =>
  res.sendFile(path.join(__dirname, "public", "index.html"))
);

// ----------------- START SERVER -----------------
server.listen(PORT, HOST, () => {
  console.log(`Online Knjižnica server listening at http://${HOST}:${PORT}`);
});
