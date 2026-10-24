var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/schema.js
var initializedIsolate = false;
var SCHEMA_STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS shop_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS branches (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT, updated_at INTEGER NOT NULL, data TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'branch', branch TEXT NOT NULL DEFAULT 'all', branch_name TEXT, privileges TEXT NOT NULL DEFAULT '[]', updated_at INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, user_agent TEXT)`,
  `CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_sessions_exp ON sessions(expires_at)`,
  `CREATE TABLE IF NOT EXISTS categories (id TEXT PRIMARY KEY, name TEXT NOT NULL, type TEXT, updated_at INTEGER NOT NULL, data TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS products (id TEXT PRIMARY KEY, branch_id TEXT, category_id TEXT, name TEXT NOT NULL, sku TEXT, stock REAL NOT NULL DEFAULT 0, cost_price REAL NOT NULL DEFAULT 0, sell_price REAL NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL, data TEXT NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS idx_products_branch ON products(branch_id)`,
  `CREATE INDEX IF NOT EXISTS idx_products_cat ON products(category_id)`,
  `CREATE INDEX IF NOT EXISTS idx_products_sku ON products(sku)`,
  `CREATE TABLE IF NOT EXISTS customers (id TEXT PRIMARY KEY, branch_id TEXT, name TEXT NOT NULL, phone TEXT, updated_at INTEGER NOT NULL, data TEXT NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS idx_customers_branch ON customers(branch_id)`,
  `CREATE TABLE IF NOT EXISTS transactions (id TEXT PRIMARY KEY, branch_id TEXT, product_id TEXT, customer_id TEXT, type TEXT NOT NULL, total REAL NOT NULL DEFAULT 0, tx_date TEXT, updated_at INTEGER NOT NULL, data TEXT NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS idx_tx_branch ON transactions(branch_id)`,
  `CREATE INDEX IF NOT EXISTS idx_tx_customer ON transactions(customer_id)`,
  `CREATE INDEX IF NOT EXISTS idx_tx_date ON transactions(tx_date)`,
  `CREATE TABLE IF NOT EXISTS credits (id TEXT PRIMARY KEY, customer_id TEXT NOT NULL, branch_id TEXT, product_id TEXT, type TEXT NOT NULL, amount REAL NOT NULL DEFAULT 0, cr_date TEXT, updated_at INTEGER NOT NULL, data TEXT NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS idx_credits_customer ON credits(customer_id)`,
  `CREATE INDEX IF NOT EXISTS idx_credits_branch ON credits(branch_id)`,
  `CREATE TABLE IF NOT EXISTS transfers (id TEXT PRIMARY KEY, from_branch_id TEXT, to_branch_id TEXT, product_id TEXT, status TEXT, updated_at INTEGER NOT NULL, data TEXT NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS idx_transfers_status ON transfers(status)`,
  `CREATE TABLE IF NOT EXISTS payment_receipts (id TEXT PRIMARY KEY, customer_id TEXT NOT NULL, branch_id TEXT, bank TEXT, status TEXT NOT NULL DEFAULT 'pending', submitted_at TEXT, updated_at INTEGER NOT NULL, data TEXT NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS idx_receipts_customer ON payment_receipts(customer_id)`,
  `CREATE INDEX IF NOT EXISTS idx_receipts_branch ON payment_receipts(branch_id)`,
  `CREATE INDEX IF NOT EXISTS idx_receipts_status ON payment_receipts(status)`,
  `CREATE TABLE IF NOT EXISTS parked_sales (id TEXT PRIMARY KEY, branch_id TEXT, updated_at INTEGER NOT NULL, data TEXT NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS idx_parked_branch ON parked_sales(branch_id)`,
  `CREATE TABLE IF NOT EXISTS stocktakes (scope_key TEXT PRIMARY KEY, branch_id TEXT, updated_at INTEGER NOT NULL, data TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS stocktake_history (id TEXT PRIMARY KEY, branch_id TEXT, completed_at TEXT, updated_at INTEGER NOT NULL, data TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS audit_log (id TEXT PRIMARY KEY, actor TEXT, branch_id TEXT, action TEXT NOT NULL, target TEXT, detail TEXT, ts TEXT NOT NULL, created_at INTEGER NOT NULL, data TEXT NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC)`,
  `CREATE TABLE IF NOT EXISTS applied_ops (op_id TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS idx_applied_ops_time ON applied_ops(applied_at)`,
  `CREATE TABLE IF NOT EXISTS media_blobs (id TEXT PRIMARY KEY, mime_type TEXT NOT NULL, filename TEXT, byte_size INTEGER NOT NULL, storage TEXT NOT NULL DEFAULT 'd1', r2_key TEXT, bytes BLOB, created_at INTEGER NOT NULL)`
];
async function ensureSchema(db) {
  if (initializedIsolate) return;
  await db.batch(SCHEMA_STATEMENTS.map((sql) => db.prepare(sql)));
  initializedIsolate = true;
}
__name(ensureSchema, "ensureSchema");

// src/auth.js
var PBKDF2_ITERATIONS = 1e5;
var SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1e3;
var COOKIE_NAME = "ss_session";
var ALL_PRIVILEGES = [
  "Dashboard",
  "Products",
  "Sales",
  "Restock",
  "Transfers",
  "Customers",
  "History",
  "Categories",
  "Expenses",
  "Alerts",
  "Settings",
  "Branches",
  "Users"
];
function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
__name(bytesToHex, "bytesToHex");
function hexToBytes(hex) {
  const clean = String(hex || "");
  if (clean.length % 2 !== 0) return new Uint8Array(0);
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return out;
}
__name(hexToBytes, "hexToBytes");
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}
__name(timingSafeEqual, "timingSafeEqual");
async function sha256Hex(input) {
  const data = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const digest = await crypto.subtle.digest("SHA-256", data);
  return bytesToHex(new Uint8Array(digest));
}
__name(sha256Hex, "sha256Hex");
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(String(password)),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const derived = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    keyMaterial,
    256
  );
  return `pbkdf2_sha256$${PBKDF2_ITERATIONS}$${bytesToHex(salt)}$${bytesToHex(new Uint8Array(derived))}`;
}
__name(hashPassword, "hashPassword");
async function verifyPassword(password, storedHash) {
  if (!storedHash || typeof storedHash !== "string") return false;
  const parts = storedHash.split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2_sha256") return false;
  const iterations = parseInt(parts[1], 10);
  if (!iterations || iterations < 1e3 || iterations > 1e5) return false;
  const salt = hexToBytes(parts[2]);
  const expected = hexToBytes(parts[3]);
  if (!salt.length || !expected.length) return false;
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(String(password)),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const derived = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256"
    },
    keyMaterial,
    expected.length * 8
  );
  return timingSafeEqual(new Uint8Array(derived), expected);
}
__name(verifyPassword, "verifyPassword");
function sanitizeUser(row) {
  if (!row) return null;
  let privileges = [];
  try {
    privileges = Array.isArray(row.privileges) ? row.privileges : JSON.parse(row.privileges || "[]");
  } catch {
    privileges = ["Dashboard"];
  }
  return {
    id: row.id,
    username: row.username,
    role: row.role || "branch",
    branch: row.branch || "all",
    branchName: row.branch_name || row.branchName || (row.role === "admin" ? "All Branches" : "Branch"),
    privileges
  };
}
__name(sanitizeUser, "sanitizeUser");
async function ensureSeedData(db) {
  const now = Date.now();
  const metaRows = await db.prepare(`SELECT key FROM shop_meta WHERE key IN ('settings', 'sync_seq')`).all();
  const existingKeys = new Set((metaRows.results || []).map((r) => r.key));
  const batch = [];
  if (!existingKeys.has("settings")) {
    batch.push(
      db.prepare(`INSERT OR IGNORE INTO shop_meta (key, value, updated_at) VALUES ('settings', ?, ?)`).bind(
        JSON.stringify({ shopName: "My Shop", currency: "Br", lowStock: 10 }),
        now
      )
    );
  }
  if (!existingKeys.has("sync_seq")) {
    batch.push(
      db.prepare(`INSERT OR IGNORE INTO shop_meta (key, value, updated_at) VALUES ('sync_seq', '1', ?)`).bind(now)
    );
  }
  const branchCount = await db.prepare(`SELECT COUNT(*) AS cnt FROM branches`).first();
  if (!branchCount || Number(branchCount.cnt) === 0) {
    const defaultBranch = {
      id: "branch_main",
      name: "Main Branch",
      createdAt: new Date(now).toISOString()
    };
    batch.push(
      db.prepare(`INSERT OR IGNORE INTO branches (id, name, created_at, updated_at, data) VALUES (?, ?, ?, ?, ?)`).bind(defaultBranch.id, defaultBranch.name, defaultBranch.createdAt, now, JSON.stringify(defaultBranch))
    );
  }
  const userCount = await db.prepare(`SELECT COUNT(*) AS cnt FROM users`).first();
  if (!userCount || Number(userCount.cnt) === 0) {
    const adminHash = await hashPassword("admin123");
    batch.push(
      db.prepare(
        `INSERT OR IGNORE INTO users (id, username, password_hash, role, branch, branch_name, privileges, updated_at)
           VALUES ('admin', 'admin', ?, 'admin', 'all', 'All Branches', ?, ?)`
      ).bind(adminHash, JSON.stringify(ALL_PRIVILEGES), now)
    );
  }
  if (batch.length > 0) {
    await db.batch(batch);
  }
}
__name(ensureSeedData, "ensureSeedData");
function extractTokenFromRequest(request) {
  const authHeader = request.headers.get("Authorization") || "";
  if (authHeader.startsWith("Bearer ")) {
    const bearer = authHeader.slice(7).trim();
    if (bearer) return bearer;
  }
  const cookieHeader = request.headers.get("Cookie") || "";
  for (const part of cookieHeader.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k === COOKIE_NAME && v) return decodeURIComponent(v);
  }
  return null;
}
__name(extractTokenFromRequest, "extractTokenFromRequest");
async function createSession(db, userId, request) {
  const rawBytes = crypto.getRandomValues(new Uint8Array(32));
  const rawToken = bytesToHex(rawBytes);
  const tokenHash = await sha256Hex(rawToken);
  const now = Date.now();
  const expiresAt = now + SESSION_TTL_MS;
  const ua = (request.headers.get("User-Agent") || "").slice(0, 250);
  await db.prepare(
    `INSERT INTO sessions (token_hash, user_id, expires_at, created_at, user_agent) VALUES (?, ?, ?, ?, ?)`
  ).bind(tokenHash, userId, expiresAt, now, ua).run();
  await db.prepare(`DELETE FROM sessions WHERE expires_at < ?`).bind(now).run();
  const isHttps = new URL(request.url).protocol === "https:";
  const sameSite = isHttps ? "SameSite=None; Secure" : "SameSite=Lax";
  const cookie = `${COOKIE_NAME}=${rawToken}; HttpOnly; Path=/; Max-Age=${Math.floor(SESSION_TTL_MS / 1e3)}; ${sameSite}`;
  return { token: rawToken, cookie, expiresAt };
}
__name(createSession, "createSession");
async function getSessionUser(db, request) {
  const rawToken = extractTokenFromRequest(request);
  if (!rawToken) return null;
  const tokenHash = await sha256Hex(rawToken);
  const now = Date.now();
  const row = await db.prepare(
    `SELECT u.id, u.username, u.role, u.branch, u.branch_name, u.privileges, s.expires_at
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = ? AND s.expires_at > ?`
  ).bind(tokenHash, now).first();
  if (!row) return null;
  return sanitizeUser(row);
}
__name(getSessionUser, "getSessionUser");
async function revokeSession(db, request) {
  const rawToken = extractTokenFromRequest(request);
  if (rawToken) {
    const tokenHash = await sha256Hex(rawToken);
    await db.prepare(`DELETE FROM sessions WHERE token_hash = ?`).bind(tokenHash).run();
  }
  const isHttps = new URL(request.url).protocol === "https:";
  const sameSite = isHttps ? "SameSite=None; Secure" : "SameSite=Lax";
  return `${COOKIE_NAME}=; HttpOnly; Path=/; Max-Age=0; ${sameSite}`;
}
__name(revokeSession, "revokeSession");

// src/media.js
var MAX_MEDIA_BYTES = 6 * 1024 * 1024;
function base64ToUint8Array(b64) {
  const clean = b64.replace(/\s+/g, "");
  const binStr = atob(clean);
  const bytes = new Uint8Array(binStr.length);
  for (let i = 0; i < binStr.length; i++) {
    bytes[i] = binStr.charCodeAt(i);
  }
  return bytes;
}
__name(base64ToUint8Array, "base64ToUint8Array");
function uint8ArrayToBase64(bytes) {
  let binary = "";
  const chunk = 32768;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}
__name(uint8ArrayToBase64, "uint8ArrayToBase64");
function normalizeBlobBytes(raw) {
  if (!raw) return null;
  if (raw instanceof Uint8Array) return raw;
  if (raw instanceof ArrayBuffer) return new Uint8Array(raw);
  if (ArrayBuffer.isView(raw)) return new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength);
  if (Array.isArray(raw)) return new Uint8Array(raw);
  return null;
}
__name(normalizeBlobBytes, "normalizeBlobBytes");
async function externalizeDataUrl(env, value, filenameHint = "") {
  if (!value || typeof value !== "string" || !value.startsWith("data:")) {
    return value;
  }
  const commaIdx = value.indexOf(",");
  if (commaIdx === -1) return value;
  const header = value.slice(5, commaIdx);
  const isBase64 = header.includes(";base64");
  const mimeType = (header.split(";")[0] || "application/octet-stream").trim();
  const payload = value.slice(commaIdx + 1);
  let bytes;
  try {
    bytes = isBase64 ? base64ToUint8Array(payload) : new TextEncoder().encode(decodeURIComponent(payload));
  } catch {
    return value;
  }
  if (bytes.byteLength === 0) return value;
  if (bytes.byteLength > MAX_MEDIA_BYTES) {
    const sizeErr = new Error(`Attachment exceeds maximum allowed size (${Math.round(MAX_MEDIA_BYTES / 1024 / 1024)}MB).`);
    sizeErr.status = 413;
    throw sizeErr;
  }
  const hash = await sha256Hex(bytes);
  const mediaId = `med_${hash.slice(0, 28)}`;
  const urlPath = `/api/media/${mediaId}`;
  const existing = await env.DB.prepare(`SELECT id FROM media_blobs WHERE id = ?`).bind(mediaId).first();
  if (existing) {
    return urlPath;
  }
  const now = Date.now();
  const safeName = String(filenameHint || "").replace(/[^\w.\- ()]/g, "_").slice(0, 120) || mediaId;
  if (env.MEDIA_BUCKET && typeof env.MEDIA_BUCKET.put === "function") {
    const r2Key = `media/${mediaId}/${safeName}`;
    await env.MEDIA_BUCKET.put(r2Key, bytes, {
      httpMetadata: { contentType: mimeType }
    });
    await env.DB.prepare(
      `INSERT OR IGNORE INTO media_blobs (id, mime_type, filename, byte_size, storage, r2_key, bytes, created_at)
       VALUES (?, ?, ?, ?, 'r2', ?, NULL, ?)`
    ).bind(mediaId, mimeType, safeName, bytes.byteLength, r2Key, now).run();
  } else {
    const ab = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    await env.DB.prepare(
      `INSERT OR IGNORE INTO media_blobs (id, mime_type, filename, byte_size, storage, r2_key, bytes, created_at)
       VALUES (?, ?, ?, ?, 'd1', NULL, ?, ?)`
    ).bind(mediaId, mimeType, safeName, bytes.byteLength, ab, now).run();
  }
  return urlPath;
}
__name(externalizeDataUrl, "externalizeDataUrl");
async function serveMedia(env, mediaId, request) {
  const cleanId = String(mediaId || "").replace(/[^a-zA-Z0-9_]/g, "");
  if (!cleanId) {
    return new Response("Not found", { status: 404 });
  }
  const etag = `"${cleanId}"`;
  if (request.headers.get("If-None-Match") === etag) {
    return new Response(null, {
      status: 304,
      headers: {
        ETag: etag,
        "Cache-Control": "public, max-age=31536000, immutable"
      }
    });
  }
  const row = await env.DB.prepare(
    `SELECT id, mime_type, filename, storage, r2_key, bytes FROM media_blobs WHERE id = ?`
  ).bind(cleanId).first();
  if (!row) {
    return new Response("Media not found", { status: 404 });
  }
  const safeMime = row.mime_type && /^(image\/|application\/pdf|text\/plain)/i.test(row.mime_type) ? row.mime_type : "application/octet-stream";
  const headers = {
    "Content-Type": safeMime,
    ETag: etag,
    "Cache-Control": "public, max-age=31536000, immutable",
    "X-Content-Type-Options": "nosniff",
    "Content-Disposition": `inline; filename="${String(row.filename || cleanId).replace(/"/g, "")}"`
  };
  if (row.storage === "r2" && row.r2_key && env.MEDIA_BUCKET) {
    const obj = await env.MEDIA_BUCKET.get(row.r2_key);
    if (!obj) return new Response("Media missing from R2", { status: 404 });
    return new Response(obj.body, { status: 200, headers });
  }
  const bytes = normalizeBlobBytes(row.bytes);
  if (!bytes) {
    return new Response("Empty media", { status: 404 });
  }
  return new Response(bytes, { status: 200, headers });
}
__name(serveMedia, "serveMedia");
async function inlineMediaIfInternal(env, url) {
  if (!url || typeof url !== "string" || !url.startsWith("/api/media/")) {
    return url;
  }
  const mediaId = url.slice("/api/media/".length).trim();
  const row = await env.DB.prepare(
    `SELECT mime_type, storage, r2_key, bytes FROM media_blobs WHERE id = ?`
  ).bind(mediaId).first();
  if (!row) return url;
  let bytes = null;
  if (row.storage === "r2" && row.r2_key && env.MEDIA_BUCKET) {
    const obj = await env.MEDIA_BUCKET.get(row.r2_key);
    if (obj) bytes = new Uint8Array(await obj.arrayBuffer());
  } else {
    bytes = normalizeBlobBytes(row.bytes);
  }
  if (!bytes) return url;
  return `data:${row.mime_type || "application/octet-stream"};base64,${uint8ArrayToBase64(bytes)}`;
}
__name(inlineMediaIfInternal, "inlineMediaIfInternal");

// src/sync.js
function roundStock(n) {
  const v = Number(n) || 0;
  return Math.round(v * 1e4) / 1e4;
}
__name(roundStock, "roundStock");
function safeParseJson(raw, fallback = null) {
  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}
__name(safeParseJson, "safeParseJson");
async function getSyncSeq(db) {
  const row = await db.prepare(`SELECT value FROM shop_meta WHERE key = 'sync_seq'`).first();
  return row ? parseInt(row.value, 10) || 1 : 1;
}
__name(getSyncSeq, "getSyncSeq");
async function bumpSyncSeq(db) {
  const now = Date.now();
  await db.prepare(
    `INSERT INTO shop_meta (key, value, updated_at) VALUES ('sync_seq', '2', ?)
       ON CONFLICT(key) DO UPDATE SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT), updated_at = excluded.updated_at`
  ).bind(now).run();
  return getSyncSeq(db);
}
__name(bumpSyncSeq, "bumpSyncSeq");
async function getShopSettings(db) {
  const row = await db.prepare(`SELECT value FROM shop_meta WHERE key = 'settings'`).first();
  const parsed = row ? safeParseJson(row.value, {}) : {};
  return {
    shopName: "My Shop",
    currency: "Br",
    lowStock: 10,
    ...parsed && typeof parsed === "object" ? parsed : {}
  };
}
__name(getShopSettings, "getShopSettings");
async function loadFullState(db) {
  const [
    metaRes,
    branchesRes,
    catsRes,
    prodsRes,
    custsRes,
    txsRes,
    creditsRes,
    transfersRes,
    receiptsRes,
    parkedRes,
    stocktakesRes,
    stHistRes,
    auditRes,
    usersRes
  ] = await db.batch([
    db.prepare(`SELECT key, value FROM shop_meta`),
    db.prepare(`SELECT id, data FROM branches ORDER BY updated_at ASC`),
    db.prepare(`SELECT id, data FROM categories ORDER BY updated_at ASC`),
    db.prepare(`SELECT id, stock, data FROM products ORDER BY updated_at ASC`),
    db.prepare(`SELECT id, data FROM customers ORDER BY updated_at ASC`),
    db.prepare(`SELECT id, data FROM transactions ORDER BY tx_date ASC, updated_at ASC`),
    db.prepare(`SELECT id, data FROM credits ORDER BY cr_date ASC, updated_at ASC`),
    db.prepare(`SELECT id, data FROM transfers ORDER BY updated_at ASC`),
    db.prepare(`SELECT id, data FROM payment_receipts ORDER BY submitted_at DESC, updated_at DESC`),
    db.prepare(`SELECT id, data FROM parked_sales ORDER BY updated_at ASC`),
    db.prepare(`SELECT scope_key, data FROM stocktakes`),
    db.prepare(`SELECT id, data FROM stocktake_history ORDER BY completed_at ASC, updated_at ASC LIMIT 100`),
    db.prepare(`SELECT id, data FROM (SELECT id, data, created_at FROM audit_log ORDER BY created_at DESC LIMIT 1000) ORDER BY created_at ASC`),
    db.prepare(`SELECT id, username, role, branch, branch_name, privileges FROM users ORDER BY updated_at ASC`)
  ]);
  let syncSeq = 1;
  let settings = { shopName: "My Shop", currency: "Br", lowStock: 10 };
  for (const r of metaRes.results || []) {
    if (r.key === "sync_seq") syncSeq = parseInt(r.value, 10) || 1;
    if (r.key === "settings") {
      const s = safeParseJson(r.value, {});
      if (s && typeof s === "object") settings = { ...settings, ...s };
    }
  }
  const parseRows = /* @__PURE__ */ __name((res) => (res.results || []).map((r) => safeParseJson(r.data, null)).filter(Boolean), "parseRows");
  const products = (prodsRes.results || []).map((r) => {
    const obj = safeParseJson(r.data, null);
    if (!obj) return null;
    obj.stock = roundStock(r.stock);
    return obj;
  }).filter(Boolean);
  const stocktakes = {};
  for (const r of stocktakesRes.results || []) {
    const parsed = safeParseJson(r.data, null);
    if (parsed) stocktakes[r.scope_key] = parsed;
  }
  const users = (usersRes.results || []).map(sanitizeUser).filter(Boolean);
  return {
    syncSeq,
    settings,
    branches: parseRows(branchesRes),
    categories: parseRows(catsRes),
    products,
    customers: parseRows(custsRes),
    transactions: parseRows(txsRes),
    credits: parseRows(creditsRes),
    transfers: parseRows(transfersRes),
    paymentReceipts: parseRows(receiptsRes),
    parkedSales: parseRows(parkedRes),
    stocktakes,
    stocktakeHistory: parseRows(stHistRes),
    auditLog: parseRows(auditRes),
    users
  };
}
__name(loadFullState, "loadFullState");
async function upsertProductRow(db, item, now) {
  const id = String(item.id || "");
  if (!id) return;
  const stock = roundStock(item.stock);
  const clean = { ...item, id, stock };
  await db.prepare(
    `INSERT INTO products (id, branch_id, category_id, name, sku, stock, cost_price, sell_price, updated_at, data)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         branch_id = excluded.branch_id,
         category_id = excluded.category_id,
         name = excluded.name,
         sku = excluded.sku,
         stock = excluded.stock,
         cost_price = excluded.cost_price,
         sell_price = excluded.sell_price,
         updated_at = excluded.updated_at,
         data = excluded.data`
  ).bind(
    id,
    clean.branchId || null,
    clean.categoryId || null,
    String(clean.name || "Unnamed Product"),
    clean.sku || null,
    stock,
    Number(clean.costPrice) || 0,
    Number(clean.sellPrice) || 0,
    now,
    JSON.stringify(clean)
  ).run();
}
__name(upsertProductRow, "upsertProductRow");
async function upsertEntityRow(env, collection, rawItem, now) {
  const db = env.DB;
  if (!rawItem || typeof rawItem !== "object") return;
  const item = { ...rawItem };
  const id = String(item.id || (collection === "auditLog" ? `aud_${now}_${Math.random().toString(36).slice(2, 7)}` : ""));
  if (!id) return;
  item.id = id;
  switch (collection) {
    case "products":
      await upsertProductRow(db, item, now);
      break;
    case "branches":
      await db.prepare(
        `INSERT INTO branches (id, name, created_at, updated_at, data) VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET name = excluded.name, updated_at = excluded.updated_at, data = excluded.data`
      ).bind(id, String(item.name || "Branch"), item.createdAt || new Date(now).toISOString(), now, JSON.stringify(item)).run();
      break;
    case "categories":
      await db.prepare(
        `INSERT INTO categories (id, name, type, updated_at, data) VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET name = excluded.name, type = excluded.type, updated_at = excluded.updated_at, data = excluded.data`
      ).bind(id, String(item.name || "Category"), item.type || "product", now, JSON.stringify(item)).run();
      break;
    case "customers":
      await db.prepare(
        `INSERT INTO customers (id, branch_id, name, phone, updated_at, data) VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET branch_id = excluded.branch_id, name = excluded.name, phone = excluded.phone, updated_at = excluded.updated_at, data = excluded.data`
      ).bind(id, item.branchId || null, String(item.name || "Customer"), item.phone || null, now, JSON.stringify(item)).run();
      break;
    case "transactions":
      if (item.signature) {
        item.signature = await externalizeDataUrl(env, item.signature, `sig_${id}.png`);
      }
      await db.prepare(
        `INSERT INTO transactions (id, branch_id, product_id, customer_id, type, total, tx_date, updated_at, data)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET
             branch_id = excluded.branch_id,
             product_id = excluded.product_id,
             customer_id = excluded.customer_id,
             type = excluded.type,
             total = excluded.total,
             tx_date = excluded.tx_date,
             updated_at = excluded.updated_at,
             data = excluded.data`
      ).bind(
        id,
        item.branchId || null,
        item.productId || null,
        item.customerId || null,
        String(item.type || "sale"),
        Number(item.total) || 0,
        item.date || new Date(now).toISOString(),
        now,
        JSON.stringify(item)
      ).run();
      break;
    case "credits":
      if (item.signature) {
        item.signature = await externalizeDataUrl(env, item.signature, `credit_sig_${id}.png`);
      }
      await db.prepare(
        `INSERT INTO credits (id, customer_id, branch_id, product_id, type, amount, cr_date, updated_at, data)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET
             customer_id = excluded.customer_id,
             branch_id = excluded.branch_id,
             product_id = excluded.product_id,
             type = excluded.type,
             amount = excluded.amount,
             cr_date = excluded.cr_date,
             updated_at = excluded.updated_at,
             data = excluded.data`
      ).bind(
        id,
        String(item.customerId || ""),
        item.branchId || null,
        item.productId || null,
        String(item.type || "credit"),
        Number(item.amount) || 0,
        item.date || new Date(now).toISOString(),
        now,
        JSON.stringify(item)
      ).run();
      break;
    case "transfers":
      await db.prepare(
        `INSERT INTO transfers (id, from_branch_id, to_branch_id, product_id, status, updated_at, data)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET
             from_branch_id = excluded.from_branch_id,
             to_branch_id = excluded.to_branch_id,
             product_id = excluded.product_id,
             status = excluded.status,
             updated_at = excluded.updated_at,
             data = excluded.data`
      ).bind(
        id,
        item.fromBranchId || null,
        item.toBranchId || null,
        item.productId || null,
        item.status || "pending",
        now,
        JSON.stringify(item)
      ).run();
      break;
    case "paymentReceipts":
      if (item.receiptDataUrl) {
        item.receiptDataUrl = await externalizeDataUrl(env, item.receiptDataUrl, item.receiptName || `receipt_${id}`);
      }
      await db.prepare(
        `INSERT INTO payment_receipts (id, customer_id, branch_id, bank, status, submitted_at, updated_at, data)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET
             customer_id = excluded.customer_id,
             branch_id = excluded.branch_id,
             bank = excluded.bank,
             status = excluded.status,
             submitted_at = excluded.submitted_at,
             updated_at = excluded.updated_at,
             data = excluded.data`
      ).bind(
        id,
        String(item.customerId || ""),
        item.branchId || null,
        item.bank || null,
        item.status || "pending",
        item.submittedAt || new Date(now).toISOString(),
        now,
        JSON.stringify(item)
      ).run();
      break;
    case "parkedSales":
      if (item.signature) {
        item.signature = await externalizeDataUrl(env, item.signature, `parked_sig_${id}.png`);
      }
      await db.prepare(
        `INSERT INTO parked_sales (id, branch_id, updated_at, data) VALUES (?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET branch_id = excluded.branch_id, updated_at = excluded.updated_at, data = excluded.data`
      ).bind(id, item.branchId || null, now, JSON.stringify(item)).run();
      break;
    case "stocktakeHistory":
      await db.prepare(
        `INSERT INTO stocktake_history (id, branch_id, completed_at, updated_at, data) VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET branch_id = excluded.branch_id, completed_at = excluded.completed_at, updated_at = excluded.updated_at, data = excluded.data`
      ).bind(id, item.branchId || null, item.at || item.completedAt || new Date(now).toISOString(), now, JSON.stringify(item)).run();
      break;
    case "auditLog":
      await db.prepare(
        `INSERT OR IGNORE INTO audit_log (id, actor, branch_id, action, target, detail, ts, created_at, data)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        id,
        item.user || item.actor || "system",
        item.branchId || null,
        String(item.action || "event"),
        item.target || "",
        item.detail || "",
        item.ts || new Date(now).toISOString(),
        now,
        JSON.stringify(item)
      ).run();
      break;
  }
}
__name(upsertEntityRow, "upsertEntityRow");
var COLLECTION_TABLE_MAP = {
  products: "products",
  branches: "branches",
  categories: "categories",
  customers: "customers",
  transactions: "transactions",
  credits: "credits",
  transfers: "transfers",
  paymentReceipts: "payment_receipts",
  parkedSales: "parked_sales",
  stocktakeHistory: "stocktake_history"
};
async function applySyncBatch(env, user, ops) {
  const db = env.DB;
  if (!Array.isArray(ops) || ops.length === 0) {
    const syncSeq2 = await getSyncSeq(db);
    return { ok: true, syncSeq: syncSeq2, applied: 0 };
  }
  const isAdmin = user && (user.role === "admin" || user.branch === "all");
  const now = Date.now();
  let applied = 0;
  for (const op of ops) {
    if (!op || typeof op !== "object") continue;
    const opId = op.opId ? String(op.opId).slice(0, 120) : null;
    if (opId) {
      const dup = await db.prepare(`SELECT op_id FROM applied_ops WHERE op_id = ?`).bind(opId).first();
      if (dup) continue;
    }
    switch (op.type) {
      case "product_delta": {
        const id = String(op.id || "");
        if (!id) break;
        const delta = Number(op.stockDelta) || 0;
        const existing = await db.prepare(`SELECT stock, data FROM products WHERE id = ?`).bind(id).first();
        if (existing) {
          const curObj = safeParseJson(existing.data, {}) || {};
          const nextStock = roundStock((Number(existing.stock) || 0) + delta);
          const merged = {
            ...curObj,
            ...op.patch && typeof op.patch === "object" ? op.patch : {},
            id,
            stock: nextStock
          };
          await upsertProductRow(db, merged, now);
        } else if (op.fallbackItem && typeof op.fallbackItem === "object") {
          await upsertProductRow(db, { ...op.fallbackItem, id }, now);
        }
        applied++;
        break;
      }
      case "upsert": {
        const col = op.collection;
        if (col === "branches" && !isAdmin && !(user.privileges || []).includes("Branches")) {
          break;
        }
        await upsertEntityRow(env, col, op.item, now);
        applied++;
        break;
      }
      case "delete": {
        const table = COLLECTION_TABLE_MAP[op.collection];
        const id = String(op.id || "");
        if (!table || !id) break;
        if (op.collection === "branches" && !isAdmin) break;
        await db.prepare(`DELETE FROM ${table} WHERE id = ?`).bind(id).run();
        applied++;
        break;
      }
      case "settings_set": {
        if (!isAdmin && !(user.privileges || []).includes("Settings")) break;
        const cur = await getShopSettings(db);
        const merged = { ...cur, ...op.settings || {} };
        await db.prepare(
          `INSERT INTO shop_meta (key, value, updated_at) VALUES ('settings', ?, ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`
        ).bind(JSON.stringify(merged), now).run();
        applied++;
        break;
      }
      case "stocktake_set": {
        const scopeKey = String(op.scopeKey || "default");
        if (!op.session) {
          await db.prepare(`DELETE FROM stocktakes WHERE scope_key = ?`).bind(scopeKey).run();
        } else {
          await db.prepare(
            `INSERT INTO stocktakes (scope_key, branch_id, updated_at, data) VALUES (?, ?, ?, ?)
               ON CONFLICT(scope_key) DO UPDATE SET branch_id = excluded.branch_id, updated_at = excluded.updated_at, data = excluded.data`
          ).bind(scopeKey, op.session.branchId || scopeKey, now, JSON.stringify(op.session)).run();
        }
        applied++;
        break;
      }
      case "replace_all": {
        if (!isAdmin) {
          const permErr = new Error("Only administrators can import/replace or wipe shop data.");
          permErr.status = 403;
          throw permErr;
        }
        const p = op.payload || {};
        await db.batch([
          db.prepare(`DELETE FROM products`),
          db.prepare(`DELETE FROM categories`),
          db.prepare(`DELETE FROM transactions`),
          db.prepare(`DELETE FROM customers`),
          db.prepare(`DELETE FROM credits`),
          db.prepare(`DELETE FROM transfers`),
          db.prepare(`DELETE FROM payment_receipts`),
          db.prepare(`DELETE FROM parked_sales`),
          db.prepare(`DELETE FROM stocktakes`)
        ]);
        if (Array.isArray(p.branches) && p.branches.length > 0) {
          await db.prepare(`DELETE FROM branches`).run();
          for (const b of p.branches) await upsertEntityRow(env, "branches", b, now);
        } else {
          const bCnt = await db.prepare(`SELECT COUNT(*) AS cnt FROM branches`).first();
          if (!bCnt || Number(bCnt.cnt) === 0) {
            await upsertEntityRow(
              env,
              "branches",
              { id: "branch_main", name: "Main Branch", createdAt: new Date(now).toISOString() },
              now
            );
          }
        }
        for (const c of p.categories || []) await upsertEntityRow(env, "categories", c, now);
        for (const pr of p.products || []) await upsertEntityRow(env, "products", pr, now);
        for (const cu of p.customers || []) await upsertEntityRow(env, "customers", cu, now);
        for (const tx of p.transactions || []) await upsertEntityRow(env, "transactions", tx, now);
        for (const cr of p.credits || []) await upsertEntityRow(env, "credits", cr, now);
        for (const tr of p.transfers || []) await upsertEntityRow(env, "transfers", tr, now);
        for (const rc of p.paymentReceipts || []) await upsertEntityRow(env, "paymentReceipts", rc, now);
        if (p.settings && typeof p.settings === "object") {
          await db.prepare(
            `INSERT INTO shop_meta (key, value, updated_at) VALUES ('settings', ?, ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`
          ).bind(JSON.stringify(p.settings), now).run();
        }
        applied++;
        break;
      }
    }
    if (opId) {
      await db.prepare(`INSERT OR IGNORE INTO applied_ops (op_id, applied_at) VALUES (?, ?)`).bind(opId, now).run();
    }
  }
  if (Math.random() < 0.02) {
    const cutoff = now - 14 * 24 * 60 * 60 * 1e3;
    await db.prepare(`DELETE FROM applied_ops WHERE applied_at < ?`).bind(cutoff).run();
  }
  const syncSeq = applied > 0 ? await bumpSyncSeq(db) : await getSyncSeq(db);
  return { ok: true, syncSeq, applied };
}
__name(applySyncBatch, "applySyncBatch");

// src/worker.js
function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders
    }
  });
}
__name(json, "json");
function safeParseJson2(raw, fallback = null) {
  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}
__name(safeParseJson2, "safeParseJson");
async function readJsonBody(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}
__name(readJsonBody, "readJsonBody");
var worker_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname } = url;
    if (!pathname.startsWith("/api/")) {
      if (env.ASSETS && typeof env.ASSETS.fetch === "function") {
        return env.ASSETS.fetch(request);
      }
      return new Response("Static assets binding not configured", { status: 404 });
    }
    if (!env.DB) {
      return json(
        { ok: false, error: "Cloudflare D1 binding `DB` is missing. Check wrangler.jsonc." },
        500
      );
    }
    try {
      await ensureSchema(env.DB);
      await ensureSeedData(env.DB);
      if (pathname === "/api/health" && request.method === "GET") {
        const syncSeq = await getSyncSeq(env.DB);
        return json({
          ok: true,
          runtime: "cloudflare-workers",
          d1: true,
          r2: Boolean(env.MEDIA_BUCKET),
          syncSeq,
          timestamp: (/* @__PURE__ */ new Date()).toISOString()
        });
      }
      if (pathname.startsWith("/api/media/") && request.method === "GET") {
        const mediaId = pathname.slice("/api/media/".length);
        return serveMedia(env, mediaId, request);
      }
      const invoiceMatch = /^\/api\/public\/invoice\/([^/]+)(\/receipt)?$/.exec(pathname);
      if (invoiceMatch) {
        const customerId = decodeURIComponent(invoiceMatch[1]);
        const isReceiptUpload = Boolean(invoiceMatch[2]);
        const custRow = await env.DB.prepare(`SELECT id, branch_id, data FROM customers WHERE id = ?`).bind(customerId).first();
        const customer = custRow ? safeParseJson2(custRow.data, null) : null;
        if (!customer) {
          return json({ ok: false, error: "Invoice not found" }, 404);
        }
        if (!isReceiptUpload && request.method === "GET") {
          const shop = await getShopSettings(env.DB);
          const [creditsRes, receiptsRes, branchesRes] = await env.DB.batch([
            env.DB.prepare(`SELECT data FROM credits WHERE customer_id = ? ORDER BY cr_date DESC`).bind(customerId),
            env.DB.prepare(`SELECT data FROM payment_receipts WHERE customer_id = ? ORDER BY submitted_at DESC`).bind(customerId),
            env.DB.prepare(`SELECT data FROM branches ORDER BY updated_at ASC`)
          ]);
          const credits = (creditsRes.results || []).map((r) => safeParseJson2(r.data, null)).filter(Boolean);
          const receipts = (receiptsRes.results || []).map((r) => safeParseJson2(r.data, null)).filter(Boolean);
          const branches = (branchesRes.results || []).map((r) => safeParseJson2(r.data, null)).filter(Boolean);
          const prodIds = [...new Set(credits.map((c) => c.productId).filter(Boolean))];
          let products = [];
          if (prodIds.length > 0) {
            const placeholders = prodIds.map(() => "?").join(",");
            const pRes = await env.DB.prepare(
              `SELECT id, name, sell_price FROM products WHERE id IN (${placeholders})`
            ).bind(...prodIds).all();
            products = (pRes.results || []).map((p) => ({
              id: p.id,
              name: p.name,
              sellPrice: p.sell_price
            }));
          }
          return json({
            ok: true,
            shop: { shopName: shop.shopName, currency: shop.currency },
            customer: {
              id: customer.id,
              name: customer.name,
              phone: customer.phone || "",
              address: customer.address || "",
              branchId: customer.branchId || null
            },
            credits,
            products,
            receipts,
            branches
          });
        }
        if (isReceiptUpload && request.method === "POST") {
          const body = await readJsonBody(request);
          if (!body || !body.bank || !body.receiptDataUrl) {
            return json({ ok: false, error: "Bank name and receipt file are required." }, 400);
          }
          const now = Date.now();
          const receiptId = body.id && String(body.id).length < 64 ? String(body.id) : `rcp_${now.toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
          const mediaUrl = await externalizeDataUrl(
            env,
            body.receiptDataUrl,
            body.receiptName || `receipt_${receiptId}`
          );
          const receipt = {
            id: receiptId,
            customerId: customer.id,
            customerName: customer.name,
            bank: String(body.bank).trim().slice(0, 80),
            notes: String(body.notes || "").trim().slice(0, 500),
            receiptName: String(body.receiptName || "receipt").slice(0, 140),
            receiptType: String(body.receiptType || "image/png").slice(0, 80),
            receiptDataUrl: mediaUrl,
            invoiceLink: String(body.invoiceLink || `${url.origin}/?invoice=${encodeURIComponent(customer.id)}`),
            status: "pending",
            branchId: body.branchId || customer.branchId || null,
            submittedAt: new Date(now).toISOString()
          };
          await env.DB.prepare(
            `INSERT INTO payment_receipts (id, customer_id, branch_id, bank, status, submitted_at, updated_at, data)
             VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)`
          ).bind(
            receipt.id,
            receipt.customerId,
            receipt.branchId,
            receipt.bank,
            receipt.submittedAt,
            now,
            JSON.stringify(receipt)
          ).run();
          const auditItem = {
            id: `aud_${now}_${Math.random().toString(36).slice(2, 6)}`,
            ts: receipt.submittedAt,
            user: "customer-portal",
            branchId: receipt.branchId || "",
            action: "receipt.upload",
            target: customer.name,
            detail: `${receipt.bank} (${receipt.receiptName})`
          };
          await env.DB.prepare(
            `INSERT INTO audit_log (id, actor, branch_id, action, target, detail, ts, created_at, data)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
          ).bind(
            auditItem.id,
            auditItem.user,
            auditItem.branchId,
            auditItem.action,
            auditItem.target,
            auditItem.detail,
            auditItem.ts,
            now,
            JSON.stringify(auditItem)
          ).run();
          await bumpSyncSeq(env.DB);
          return json({ ok: true, receipt });
        }
        return json({ ok: false, error: "Method not allowed" }, 405);
      }
      if (pathname === "/api/auth/session" && request.method === "GET") {
        const [user2, shop] = await Promise.all([
          getSessionUser(env.DB, request),
          getShopSettings(env.DB)
        ]);
        return json({
          ok: true,
          authenticated: Boolean(user2),
          user: user2,
          shop: { shopName: shop.shopName, currency: shop.currency }
        });
      }
      if (pathname === "/api/auth/login" && request.method === "POST") {
        const body = await readJsonBody(request);
        const username = String(body?.username || "").trim();
        const password = String(body?.password || "").trim();
        if (!username || !password) {
          return json({ ok: false, error: "Username and password are required." }, 400);
        }
        const userRow = await env.DB.prepare(
          `SELECT id, username, password_hash, role, branch, branch_name, privileges
           FROM users WHERE username = ? COLLATE NOCASE`
        ).bind(username).first();
        if (!userRow) {
          return json({ ok: false, error: "Invalid username or password." }, 401);
        }
        const valid = await verifyPassword(password, userRow.password_hash);
        if (!valid) {
          return json({ ok: false, error: "Invalid username or password." }, 401);
        }
        const session = await createSession(env.DB, userRow.id, request);
        const cleanUser = sanitizeUser(userRow);
        return json(
          {
            ok: true,
            user: cleanUser,
            sessionToken: session.token
          },
          200,
          { "Set-Cookie": session.cookie }
        );
      }
      if (pathname === "/api/auth/logout" && request.method === "POST") {
        const clearCookie = await revokeSession(env.DB, request);
        return json({ ok: true }, 200, { "Set-Cookie": clearCookie });
      }
      const user = await getSessionUser(env.DB, request);
      if (!user) {
        return json({ ok: false, error: "Unauthorized. Please sign in." }, 401);
      }
      const isAdmin = user.role === "admin" || user.branch === "all";
      if (pathname === "/api/bootstrap" && request.method === "GET") {
        const state = await loadFullState(env.DB);
        return json({ ok: true, user, state });
      }
      if (pathname === "/api/pull" && request.method === "GET") {
        const since = parseInt(url.searchParams.get("since") || "0", 10) || 0;
        const currentSeq = await getSyncSeq(env.DB);
        if (currentSeq <= since) {
          return json({ ok: true, changed: false, syncSeq: currentSeq });
        }
        const state = await loadFullState(env.DB);
        return json({ ok: true, changed: true, syncSeq: state.syncSeq, state, user });
      }
      if (pathname === "/api/sync" && request.method === "POST") {
        const body = await readJsonBody(request);
        if (!body || !Array.isArray(body.ops)) {
          return json({ ok: false, error: "Invalid sync payload; expected `ops` array." }, 400);
        }
        const result = await applySyncBatch(env, user, body.ops);
        return json(result);
      }
      if (pathname === "/api/users" && request.method === "POST") {
        if (!isAdmin && !(user.privileges || []).includes("Users")) {
          return json({ ok: false, error: "Administrator privileges required to manage users." }, 403);
        }
        const body = await readJsonBody(request);
        const username = String(body?.username || "").trim();
        const password = String(body?.password || "").trim();
        const editId = body?.editId ? String(body.editId).trim() : "";
        if (!username) {
          return json({ ok: false, error: "Username is required." }, 400);
        }
        const existingByName = await env.DB.prepare(
          `SELECT id FROM users WHERE username = ? COLLATE NOCASE`
        ).bind(username).first();
        if (existingByName && existingByName.id !== editId) {
          return json({ ok: false, error: "Username already exists." }, 409);
        }
        const role = body?.role === "admin" ? "admin" : "branch";
        const branch = role === "admin" ? "all" : String(body?.branch || "all");
        const branchName = role === "admin" ? "All Branches" : String(body?.branchName || "Branch");
        const privileges = Array.isArray(body?.privileges) && body.privileges.length ? body.privileges : role === "admin" ? ALL_PRIVILEGES : ["Dashboard"];
        const now = Date.now();
        if (editId) {
          const cur = await env.DB.prepare(`SELECT id, role, password_hash FROM users WHERE id = ?`).bind(editId).first();
          if (!cur) {
            return json({ ok: false, error: "User not found." }, 404);
          }
          if (cur.role === "admin" && role !== "admin") {
            const adminCount = await env.DB.prepare(`SELECT COUNT(*) AS cnt FROM users WHERE role = 'admin'`).first();
            if (Number(adminCount?.cnt || 0) <= 1) {
              return json({ ok: false, error: "Cannot remove admin role from the last administrator." }, 400);
            }
          }
          if (password && password.length < 4) {
            return json({ ok: false, error: "Password must be at least 4 characters." }, 400);
          }
          const nextHash = password ? await hashPassword(password) : cur.password_hash;
          await env.DB.prepare(
            `UPDATE users
             SET username = ?, password_hash = ?, role = ?, branch = ?, branch_name = ?, privileges = ?, updated_at = ?
             WHERE id = ?`
          ).bind(username, nextHash, role, branch, branchName, JSON.stringify(privileges), now, editId).run();
        } else {
          if (!password || password.length < 4) {
            return json({ ok: false, error: "Password of at least 4 characters is required for new users." }, 400);
          }
          const newId = body?.id && String(body.id).length < 64 ? String(body.id) : `usr_${now.toString(36)}_${Math.random().toString(36).slice(2, 6)}`;
          const pwHash = await hashPassword(password);
          await env.DB.prepare(
            `INSERT INTO users (id, username, password_hash, role, branch, branch_name, privileges, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
          ).bind(newId, username, pwHash, role, branch, branchName, JSON.stringify(privileges), now).run();
        }
        const syncSeq = await bumpSyncSeq(env.DB);
        const uRes = await env.DB.prepare(
          `SELECT id, username, role, branch, branch_name, privileges FROM users ORDER BY updated_at ASC`
        ).all();
        return json({
          ok: true,
          syncSeq,
          users: (uRes.results || []).map(sanitizeUser)
        });
      }
      if (pathname.startsWith("/api/users/") && request.method === "DELETE") {
        if (!isAdmin && !(user.privileges || []).includes("Users")) {
          return json({ ok: false, error: "Administrator privileges required to delete users." }, 403);
        }
        const targetId = decodeURIComponent(pathname.slice("/api/users/".length));
        const target = await env.DB.prepare(`SELECT id, role FROM users WHERE id = ?`).bind(targetId).first();
        if (!target) {
          return json({ ok: false, error: "User not found." }, 404);
        }
        if (target.role === "admin") {
          const adminCount = await env.DB.prepare(`SELECT COUNT(*) AS cnt FROM users WHERE role = 'admin'`).first();
          if (Number(adminCount?.cnt || 0) <= 1) {
            return json({ ok: false, error: "Cannot delete the last remaining administrator account." }, 400);
          }
        }
        await env.DB.batch([
          env.DB.prepare(`DELETE FROM sessions WHERE user_id = ?`).bind(targetId),
          env.DB.prepare(`DELETE FROM users WHERE id = ?`).bind(targetId)
        ]);
        const syncSeq = await bumpSyncSeq(env.DB);
        const uRes = await env.DB.prepare(
          `SELECT id, username, role, branch, branch_name, privileges FROM users ORDER BY updated_at ASC`
        ).all();
        return json({
          ok: true,
          syncSeq,
          users: (uRes.results || []).map(sanitizeUser)
        });
      }
      if (pathname === "/api/backup/export" && request.method === "GET") {
        if (!isAdmin) {
          return json({ ok: false, error: "Administrator access required for full backup export." }, 403);
        }
        const state = await loadFullState(env.DB);
        const inlineMedia = url.searchParams.get("inlineMedia") === "1";
        if (inlineMedia) {
          for (const tx of state.transactions) {
            if (tx.signature) tx.signature = await inlineMediaIfInternal(env, tx.signature);
          }
          for (const cr of state.credits) {
            if (cr.signature) cr.signature = await inlineMediaIfInternal(env, cr.signature);
          }
          for (const rc of state.paymentReceipts) {
            if (rc.receiptDataUrl) rc.receiptDataUrl = await inlineMediaIfInternal(env, rc.receiptDataUrl);
          }
        }
        return json({
          ok: true,
          backup: {
            branches: state.branches,
            categories: state.categories,
            products: state.products,
            customers: state.customers,
            transactions: state.transactions,
            credits: state.credits,
            transfers: state.transfers,
            paymentReceipts: state.paymentReceipts,
            settings: state.settings,
            exportDate: (/* @__PURE__ */ new Date()).toISOString()
          }
        });
      }
      return json({ ok: false, error: `Unknown API route: ${pathname}` }, 404);
    } catch (err) {
      const status = err && Number.isInteger(err.status) ? err.status : 500;
      if (status >= 500) console.error("Worker API error:", err);
      return json(
        {
          ok: false,
          error: err && err.message ? err.message : "Internal server error"
        },
        status
      );
    }
  }
};
export {
  worker_default as default
};
//# sourceMappingURL=worker.js.map
