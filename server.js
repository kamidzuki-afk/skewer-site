const http = require("http"), fs = require("fs"), path = require("path"), crypto = require("crypto");
const { Pool } = require("pg");

const PORT = process.env.PORT || 3000;
const SECRET = process.env.SESSION_SECRET || "";
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const GH_USER = process.env.GITHUB_USER || "kamidzuki-afk";
const GH_TOPIC = process.env.PORTFOLIO_TOPIC || "portfolio";

if (!SECRET || !process.env.DATABASE_URL) {
  console.error("Нужны переменные DATABASE_URL и SESSION_SECRET");
  process.exit(1);
}

const db = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

async function init() {
  await db.query(`
    create table if not exists users(
      id serial primary key, name text not null, email text unique not null,
      salt text not null, hash text not null, ava text, created timestamptz default now());
    create table if not exists orders(
      id serial primary key, user_id int references users(id), status int not null default 0,
      sum int, service text, contact text, brief text,
      created timestamptz default now(), hist jsonb not null default '[]');
  `);
}

// ---------- утилиты ----------
const scrypt = (p, s) => new Promise((ok, no) => crypto.scrypt(p, s, 64, (e, k) => e ? no(e) : ok(k.toString("hex"))));
const sha = x => crypto.createHash("sha256").update(String(x)).digest();
const same = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const sign = p => {
  const b = Buffer.from(JSON.stringify(p)).toString("base64url");
  return b + "." + crypto.createHmac("sha256", SECRET).update(b).digest("base64url");
};
const unsign = t => {
  if (!t) return null;
  const [b, m] = t.split(".");
  if (!b || !m) return null;
  const e = crypto.createHmac("sha256", SECRET).update(b).digest("base64url");
  if (m.length !== e.length || !crypto.timingSafeEqual(Buffer.from(m), Buffer.from(e))) return null;
  try { const p = JSON.parse(Buffer.from(b, "base64url")); return p.exp > Date.now() ? p : null; } catch { return null; }
};
const session = req => {
  const c = (req.headers.cookie || "").split(";").map(s => s.trim()).find(s => s.startsWith("sk="));
  return c ? unsign(c.slice(3)) : null;
};
const setSession = (res, p) => res.setHeader("Set-Cookie",
  `sk=${sign({ ...p, exp: Date.now() + 30 * 864e5 })}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000`);
const clearSession = res => res.setHeader("Set-Cookie", "sk=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0");

const send = (res, code, obj) => {
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(JSON.stringify(obj));
};
const readBody = req => new Promise((ok, no) => {
  let n = 0; const ch = [];
  req.on("data", c => { n += c.length; if (n > 300000) { no(new Error("big")); req.destroy(); } else ch.push(c); });
  req.on("end", () => { try { ok(JSON.parse(Buffer.concat(ch).toString() || "{}")); } catch { no(new Error("json")); } });
});

const tries = new Map();
const blocked = ip => { const t = tries.get(ip); return t && t.n >= 10 && Date.now() - t.t < 9e5; };
const fail = ip => { const t = tries.get(ip); tries.set(ip, { n: t && Date.now() - t.t < 9e5 ? t.n + 1 : 1, t: Date.now() }); };

async function notify(text) {
  if (!process.env.BOT_TOKEN || !process.env.OWNER_ID) return;
  try {
    await fetch(`https://api.telegram.org/bot${process.env.BOT_TOKEN}/sendMessage`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ chat_id: process.env.OWNER_ID, text })
    });
  } catch {}
}

let cache = { t: 0, data: [] };
async function portfolio() {
  if (Date.now() - cache.t < 6e5) return cache.data;
  try {
    const q = encodeURIComponent(`user:${GH_USER} topic:${GH_TOPIC}`);
    const h = { "User-Agent": "skewer-site", Accept: "application/vnd.github+json" };
    if (process.env.GITHUB_TOKEN) h.Authorization = "Bearer " + process.env.GITHUB_TOKEN;
    const r = await fetch(`https://api.github.com/search/repositories?q=${q}&sort=updated&per_page=30`, { headers: h });
    if (!r.ok) throw new Error("gh " + r.status);
    const j = await r.json();
    cache = { t: Date.now(), data: (j.items || []).map(x => ({
      name: x.name, description: x.description || "", url: x.homepage || x.html_url,
      repo: x.html_url, lang: x.language || "", updated: x.pushed_at })) };
  } catch (e) { console.error(e.message); cache.t = Date.now() - 5.5e5; }
  return cache.data;
}

// ---------- API ----------
async function api(req, res, url) {
  const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
  const m = req.method, p = url.pathname;
  if (m !== "GET" && !(req.headers["content-type"] || "").includes("application/json")) return send(res, 415, { error: "json" });
  const S = session(req);

  if (p === "/api/portfolio" && m === "GET") return send(res, 200, await portfolio());

  if (p === "/api/me" && m === "GET") {
    if (!S) return send(res, 200, { user: null });
    if (S.admin) return send(res, 200, { user: { admin: true, name: "Иван (Skewer)", email: ADMIN_EMAIL } });
    const r = await db.query("select id,name,email,ava from users where id=$1", [S.uid]);
    return send(res, 200, { user: r.rows[0] || null });
  }

  if (p === "/api/register" && m === "POST") {
    const b = await readBody(req);
    const name = String(b.name || "").trim().slice(0, 60), email = String(b.email || "").trim().toLowerCase().slice(0, 120), pw = String(b.password || "");
    if (name.length < 2) return send(res, 400, { error: "Введите имя." });
    if (!/^\S+@\S+\.\S+$/.test(email)) return send(res, 400, { error: "Введите корректную почту." });
    if (pw.length < 6 || pw.length > 100) return send(res, 400, { error: "Пароль — минимум 6 символов." });
    if (email === ADMIN_EMAIL) return send(res, 400, { error: "Эта почта недоступна." });
    const salt = crypto.randomBytes(16).toString("hex");
    try {
      const r = await db.query("insert into users(name,email,salt,hash) values($1,$2,$3,$4) returning id", [name, email, salt, await scrypt(pw, salt)]);
      setSession(res, { uid: r.rows[0].id });
      return send(res, 200, { ok: true });
    } catch (e) {
      if (e.code === "23505") return send(res, 400, { error: "Аккаунт с такой почтой уже есть. Войдите." });
      throw e;
    }
  }

  if (p === "/api/login" && m === "POST") {
    if (blocked(ip)) return send(res, 429, { error: "Слишком много попыток. Попробуйте позже." });
    const b = await readBody(req);
    const email = String(b.email || "").trim().toLowerCase(), pw = String(b.password || "");
    if (ADMIN_EMAIL && ADMIN_PASSWORD && email === ADMIN_EMAIL) {
      if (!same(pw, ADMIN_PASSWORD)) { fail(ip); return send(res, 401, { error: "Неверная почта или пароль." }); }
      setSession(res, { admin: true });
      return send(res, 200, { ok: true });
    }
    const r = await db.query("select id,salt,hash from users where email=$1", [email]);
    const u = r.rows[0];
    if (!u || !same(await scrypt(pw, u.salt), u.hash)) { fail(ip); return send(res, 401, { error: "Неверная почта или пароль." }); }
    setSession(res, { uid: u.id });
    return send(res, 200, { ok: true });
  }

  if (p === "/api/logout" && m === "POST") { clearSession(res); return send(res, 200, { ok: true }); }

  if (!S) return send(res, 401, { error: "Войдите в аккаунт." });

  if (p === "/api/avatar" && m === "POST" && S.uid) {
    const b = await readBody(req), a = String(b.ava || "");
    if (!/^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/.test(a) || a.length > 150000) return send(res, 400, { error: "Фото не подходит." });
    await db.query("update users set ava=$2 where id=$1", [S.uid, a]);
    return send(res, 200, { ok: true });
  }

  if (p === "/api/orders" && m === "POST" && S.uid) {
    const b = await readBody(req);
    const service = String(b.service || "").slice(0, 200), contact = String(b.contact || "").trim().slice(0, 200), brief = String(b.brief || "").trim().slice(0, 6000);
    if (!contact || !brief) return send(res, 400, { error: "Заполните контакт и ТЗ." });
    const hist = JSON.stringify([{ st: 0, date: new Date().toISOString() }]);
    const r = await db.query("insert into orders(user_id,service,contact,brief,hist) values($1,$2,$3,$4,$5) returning id", [S.uid, service, contact, brief, hist]);
    notify(`Новый заказ №${1000 + r.rows[0].id}. Проверь сайт.`);
    return send(res, 200, { ok: true, id: r.rows[0].id });
  }

  if (p === "/api/orders" && m === "GET") {
    if (S.admin) {
      const r = await db.query("select o.id,o.status,o.sum,o.service,o.contact,o.brief,o.created,o.hist,u.name,u.email from orders o join users u on u.id=o.user_id order by o.id desc");
      return send(res, 200, r.rows);
    }
    const r = await db.query("select id,status,sum,created,hist from orders where user_id=$1 order by id desc", [S.uid]);
    return send(res, 200, r.rows);
  }

  const mo = p.match(/^\/api\/orders\/(\d+)$/);
  if (mo && m === "PATCH" && S.admin) {
    const b = await readBody(req), st = Number(b.status);
    if (![0, 1, 2].includes(st)) return send(res, 400, { error: "Неверный статус." });
    const sum = b.sum === undefined || b.sum === null || b.sum === "" ? null : Math.max(0, Math.round(Number(b.sum)));
    if (sum !== null && !Number.isFinite(sum)) return send(res, 400, { error: "Неверная сумма." });
    const r = await db.query(
      `update orders set
         hist = case when status <> $2::int then hist || jsonb_build_array(jsonb_build_object('st',$2::int,'date',now())) else hist end,
         status = $2::int, sum = coalesce($3::int, sum)
       where id = $1 returning id`, [mo[1], st, sum]);
    return send(res, r.rowCount ? 200 : 404, r.rowCount ? { ok: true } : { error: "Не найден." });
  }

  return send(res, 404, { error: "Не найдено." });
}

// ---------- сервер ----------
const HEAD = {
  "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  "X-Content-Type-Options": "nosniff", "Referrer-Policy": "strict-origin-when-cross-origin",
  "Strict-Transport-Security": "max-age=31536000"
};

http.createServer(async (req, res) => {
  for (const k in HEAD) res.setHeader(k, HEAD[k]);
  try {
    const url = new URL(req.url, "http://x");
    if (url.pathname.startsWith("/api/")) return await api(req, res, url);
    if (url.pathname === "/" && req.method === "GET") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      return res.end(fs.readFileSync(path.join(__dirname, "index.html")));
    }
    res.writeHead(404); res.end("Not found");
  } catch (e) {
    console.error(e.message);
    if (!res.headersSent) send(res, 500, { error: "Ошибка сервера." }); else res.end();
  }
}).listen(PORT, () => console.log("Сайт запущен на порту " + PORT));

init().catch(e => { console.error("Ошибка базы:", e.message); process.exit(1); });
