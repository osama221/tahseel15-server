// Tahseel15 API: users + permissions, collections with mandatory receipt photo, follow-ups, client requests.
const crypto = require('crypto');
const store = process.env.LOCAL_STORE ? require('../local-store') : blobStore();

function blobStore() {
  const B = require('@vercel/blob');
  return {
    // forWrite: take the ETag from the store's metadata API. The ETag on a downloaded body can be a weak one
    // (W/"...") when the response was compressed in transit, and a weak ETag never matches a conditional write.
    async read(path, forWrite) {
      let r = null, h = null;
      const meta = forWrite ? B.head(path).catch(() => null) : null;
      try { r = await B.get(path, { access: 'private', useCache: false }); } catch (e) { if (!(e instanceof B.BlobNotFoundError)) throw e; }
      if (meta) h = await meta;
      if (!r || r.statusCode !== 200) return { v: null, etag: null };
      const v = JSON.parse(await new Response(r.stream).text());
      return { v, etag: (h && h.etag) || String(r.blob.etag || '').replace(/^W\//, ''), raw: r.blob.etag };
    },
    async write(path, v, etag) {
      const o = { access: 'private', contentType: 'application/json', addRandomSuffix: false };
      if (etag) o.ifMatch = etag;
      try { await B.put(path, JSON.stringify(v), o); }
      catch (e) { if (e instanceof B.BlobPreconditionFailedError || (!etag && /already exists/i.test(String(e.message)))) { const c = new Error('conflict'); c.conflict = true; throw c; } throw e; }
    },
    async putFile(path, buf, type) { await B.put(path, buf, { access: 'private', contentType: type, addRandomSuffix: false }); },
    async getFile(path) {
      const r = await B.get(path, { access: 'private' });
      if (!r || r.statusCode !== 200) return null;
      return { buf: Buffer.from(await new Response(r.stream).arrayBuffer()), type: r.blob.contentType };
    },
  };
}

const MAIN = 'db/main.json', USERS = 'db/users.json';
const PERMS = ['viewAll', 'dashboard', 'contact', 'collect', 'edit', 'requests', 'export'];
const SECRET = process.env.AUTH_SECRET || '';
class Err extends Error { constructor(code, msg) { super(msg); this.code = code; } }
const bad = (m, c) => { throw new Err(c || 400, m); };
const today = () => new Intl.DateTimeFormat('en-CA', { timeZone: 'Africa/Cairo' }).format(new Date());
const rid = n => crypto.randomBytes(n).toString('hex');
const str = (v, max) => String(v == null ? '' : v).trim().slice(0, max || 200);
const isDate = s => /^\d{4}-\d{2}-\d{2}$/.test(s || '');

async function mutate(path, fn) {
  for (let i = 0; ; i++) {
    const { v, etag } = await store.read(path, true);
    const out = await fn(v);
    if (out.skip) return out;
    try { await store.write(path, out.v, etag); return out; }
    catch (e) { if (!e.conflict) throw e; if (i >= 5) bad('السيرفر مشغول، حاول مرة أخرى', 503); await new Promise(r => setTimeout(r, 60 * (i + 1) * Math.random())); }
  }
}

/* ---------- users & auth ---------- */
function hashPw(pw, salt) { return crypto.scryptSync(String(pw), salt, 32).toString('hex'); }
function setPw(u, pw) { u.salt = rid(16); u.hash = hashPw(pw, u.salt); u.pv = (u.pv || 0) + 1; }
function sign(body) { return crypto.createHmac('sha256', SECRET).update(body).digest('base64url'); }
function token(u) { const b = Buffer.from(JSON.stringify({ u: u.id, pv: u.pv, e: Date.now() + 30 * 864e5 })).toString('base64url'); return b + '.' + sign(b); }
async function loadUsers() {
  let { v } = await store.read(USERS);
  if (v) return v;
  const init = process.env.ADMIN_INIT_PASSWORD;
  if (!init || !SECRET) bad('server not configured', 500);
  const a = { id: 'u1', username: 'admin', name: 'الأدمن', role: 'admin', perms: {}, active: true, mustChange: true };
  setPw(a, init);
  try { await store.write(USERS, { users: [a], seq: 1 }, null); } catch (e) { if (!e.conflict) throw e; }
  return (await store.read(USERS)).v;
}
function can(u, p) { return u.role === 'admin' || !!(u.perms && u.perms[p]); }
function need(u, p) { if (!can(u, p)) bad('ليس لديك صلاحية لهذا الإجراء', 403); }
function pub(u) { return { id: u.id, username: u.username, name: u.name, role: u.role, perms: u.perms || {}, active: u.active, mustChange: !!u.mustChange }; }
async function auth(req) {
  const h = String(req.headers.authorization || ''), t = h.startsWith('Bearer ') ? h.slice(7) : '';
  const [b, s] = t.split('.');
  if (!b || !s || !SECRET) bad('auth', 401);
  const x = sign(b);
  if (x.length !== s.length || !crypto.timingSafeEqual(Buffer.from(x), Buffer.from(s))) bad('auth', 401);
  const p = JSON.parse(Buffer.from(b, 'base64url').toString());
  if (p.e < Date.now()) bad('auth', 401);
  const us = await loadUsers(), u = us.users.find(z => z.id === p.u);
  if (!u || !u.active || u.pv !== p.pv) bad('auth', 401);
  return { u, us };
}
async function login(b) {
  const name = str(b.username, 60).toLowerCase(); let res;
  await loadUsers();
  await mutate(USERS, us => {
    const u = us.users.find(z => z.username === name);
    if (!u || !u.active) { res = null; return { skip: true }; }
    if (u.lock && u.lock > Date.now()) { res = 'lock'; return { skip: true }; }
    if (hashPw(b.password, u.salt) === u.hash) { res = u; if (!u.fails) return { skip: true }; u.fails = 0; u.lock = 0; return { v: us }; }
    u.fails = (u.fails || 0) + 1; if (u.fails >= 8) { u.lock = Date.now() + 10 * 6e4; u.fails = 0; }
    res = null; return { v: us };
  });
  if (res === 'lock') bad('تم إيقاف الدخول مؤقتاً لكثرة المحاولات، جرّب بعد 10 دقائق', 429);
  if (!res) bad('اسم المستخدم أو كلمة السر غير صحيحة', 401);
  return { token: token(res), me: pub(res) };
}

/* ---------- data views ---------- */
const empty = () => ({ rev: 0, contracts: [], payments: [], followups: [], requests: [], log: [], seq: { pay: 0, fu: 0, req: 0 } });
const pending = (p, cm) => p.st !== 'done' && cm[p.c] && cm[p.c].st === 'active';
function view(m, u, us) {
  m = m || empty();
  const T = today(), cm = {}; m.contracts.forEach(c => cm[c.id] = c);
  const all = can(u, 'viewAll'), contact = can(u, 'contact'), reqs = can(u, 'requests');
  let pays = m.payments;
  if (!all) pays = pays.filter(p => pending(p, cm) && p.due < T);
  const seen = {}; pays.forEach(p => seen[p.c] = 1);
  const strip = c => { const o = Object.assign({}, c); if (!contact) delete o.phone; if (!reqs) delete o.ptok; return o; };
  const cons = m.contracts.filter(c => all || seen[c.id]).map(strip);
  const out = { rev: m.rev, today: T, me: pub(u), empty: !m.contracts.length, contracts: cons, payments: pays,
    followups: contact || all ? m.followups.filter(f => all || seen[f.c]) : [],
    requests: reqs ? m.requests : [] };
  if (reqs && !all) out.cidx = m.contracts.filter(c => c.st === 'active').map(c => ({ id: c.id, client: c.client, unit: c.unit }));
  if (u.role === 'admin') { out.users = us.users.map(pub); out.log = m.log.slice(-200).reverse(); }
  return out;
}

/* ---------- operations ---------- */
function clean(o) { Object.keys(o).forEach(k => { if (o[k] === '' || o[k] == null) delete o[k]; }); return o; }
async function savePhoto(b64, id) {
  if (!b64) return null;
  const buf = Buffer.from(String(b64).replace(/^data:[^,]*,/, ''), 'base64');
  const jpg = buf[0] === 0xFF && buf[1] === 0xD8, png = buf[0] === 0x89 && buf[1] === 0x50;
  if (!(jpg || png) || buf.length < 2000) bad('صورة المستند غير صالحة');
  if (buf.length > 3.5e6) bad('حجم الصورة كبير جداً');
  const k = 'docs/' + id + '-' + Date.now() + '-' + rid(6) + (jpg ? '.jpg' : '.png');
  await store.putFile(k, buf, jpg ? 'image/jpeg' : 'image/png');
  return k;
}
const TYPES = ['dp', 'inst', 'maint'], METH = ['chq', 'trf', 'cash', 'rcpt'], RT = ['finish', 'handover', 'issue'], RS = ['new', 'progress', 'done', 'rejected'];
async function op(u, b) {
  const t = b.t, at = new Date().toISOString(), T = today();
  let doc = null;
  if (t === 'pay.collect' || t === 'pay.doc') {
    need(u, 'collect');
    if (!b.photo) bad('صورة مستند التحصيل إجبارية');
    doc = { k: await savePhoto(b.photo, 'p' + (+b.id || 0)), at, by: u.name };
  }
  const r = await mutate(MAIN, m => {
    m = m || empty();
    const P = id => m.payments.find(p => p.id === +id) || bad('الدفعة غير موجودة', 404);
    const C = id => m.contracts.find(c => c.id === id) || bad('العقد غير موجود', 404);
    let d = '';
    if (t === 'pay.collect') {
      const p = P(b.id), amt = +b.amt, c = C(p.c);
      if (p.st === 'done') bad('الدفعة مسجلة محصّلة بالفعل');
      if (!(amt > 0) || amt > p.amt + 0.001) bad('المبلغ غير صحيح');
      if (!isDate(b.cdate) || b.cdate > T) bad('تاريخ التحصيل غير صحيح');
      if (amt < p.amt) { const rest = Object.assign({}, p, { id: ++m.seq.pay, amt: Math.round((p.amt - amt) * 100) / 100, note: [p.note, 'باقي دفعة محصّلة جزئياً'].filter(Boolean).join(' · ') }); delete rest.docs; m.payments.push(rest); p.amt = amt; }
      Object.assign(p, { st: 'done', cdate: b.cdate, cacc: str(b.cacc, 60), rcpt: str(b.rcpt, 40), cby: u.name, cat: at }); clean(p);
      p.docs = (p.docs || []).concat(doc);
      d = 'تحصيل ' + amt + ' من ' + c.client;
    } else if (t === 'pay.doc') { const p = P(b.id); p.docs = (p.docs || []).concat(doc); d = 'إضافة مستند لدفعة ' + C(p.c).client; }
    else if (t === 'pay.uncollect') { need(u, 'edit'); const p = P(b.id); p.st = p.m === 'chq' ? 'safe' : 'wait'; ['cdate', 'cacc', 'rcpt', 'cby', 'cat'].forEach(k => delete p[k]); d = 'تراجع عن تحصيل ' + p.amt + ' · ' + C(p.c).client; }
    else if (t === 'pay.status') { need(u, 'edit'); const p = P(b.id); if (p.st === 'done' || !['safe', 'wait', 'bounced'].includes(b.st)) bad('حالة غير صحيحة'); p.st = b.st; d = 'تغيير حالة دفعة ' + C(p.c).client + ' إلى ' + b.st; }
    else if (t === 'pay.save') {
      need(u, 'edit');
      const p = b.id ? P(b.id) : { id: ++m.seq.pay, c: C(b.c).id, st: 'wait' };
      if (!(+b.amt > 0) || !isDate(b.due) || !TYPES.includes(b.type) || !METH.includes(b.m)) bad('بيانات الدفعة غير مكتملة');
      if (p.st !== 'done' && ['safe', 'wait', 'bounced'].includes(b.st)) p.st = b.st;
      Object.assign(p, { amt: +b.amt, due: b.due, type: b.type, m: b.m, chq: str(b.chq, 40), bank: str(b.bank, 60), note: str(b.note, 300) }); clean(p);
      if (!b.id) m.payments.push(p);
      d = (b.id ? 'تعديل' : 'إضافة') + ' دفعة ' + p.amt + ' · ' + C(p.c).client;
    } else if (t === 'pay.del') { need(u, 'edit'); const p = P(b.id); m.payments = m.payments.filter(x => x !== p); d = 'حذف دفعة ' + p.amt + ' · ' + C(p.c).client; }
    else if (t === 'con.save') {
      need(u, 'edit');
      if (!str(b.client)) bad('اسم العميل مطلوب');
      let c;
      if (b.id) c = C(b.id); else { const n = m.contracts.reduce((a, x) => Math.max(a, parseInt(String(x.id).replace(/\D/g, ''), 10) || 0), 0) + 1; c = { id: 'cn' + String(n).padStart(4, '0'), st: 'active', ptok: rid(12) }; m.contracts.push(c); }
      Object.assign(c, { client: str(b.client, 120), unit: str(b.unit, 60), phone: str(b.phone, 80), date: isDate(b.date) ? b.date : '', floor: str(b.floor, 30), sales: str(b.sales, 60), broker: str(b.broker, 60), note: str(b.note, 300), value: +b.value || 0, maint: +b.maint || 0 }); clean(c);
      d = (b.id ? 'تعديل' : 'إضافة') + ' عقد ' + c.client;
    } else if (t === 'con.cancel' || t === 'con.revive') { need(u, 'edit'); const c = C(b.id); if (t === 'con.cancel') { c.st = 'cancelled'; c.cancelDate = T; } else { c.st = 'active'; delete c.cancelDate; } d = (t === 'con.cancel' ? 'فسخ' : 'إعادة تفعيل') + ' عقد ' + c.client; }
    else if (t === 'fu.add') {
      need(u, 'contact'); const c = C(b.c);
      if (!str(b.result)) bad('نتيجة المتابعة مطلوبة');
      m.followups.push(clean({ id: ++m.seq.fu, c: c.id, at, by: u.name, kind: str(b.kind, 20), result: str(b.result, 40), promise: isDate(b.promise) ? b.promise : '', note: str(b.note, 500) }));
      d = 'متابعة ' + c.client + ': ' + str(b.result, 40);
    } else if (t === 'req.add') {
      need(u, 'requests'); const c = C(b.c);
      if (!RT.includes(b.type) || !str(b.text)) bad('نوع الطلب والتفاصيل مطلوبان');
      m.requests.push({ id: ++m.seq.req, c: c.id, type: b.type, text: str(b.text, 1000), st: 'new', at, src: 'staff', by: u.name });
      d = 'طلب جديد للعميل ' + c.client;
    } else if (t === 'req.update') {
      need(u, 'requests'); const q = m.requests.find(x => x.id === +b.id) || bad('الطلب غير موجود', 404);
      if (!RS.includes(b.st)) bad('حالة غير صحيحة');
      Object.assign(q, { st: b.st, reply: str(b.reply, 1000), uat: at, uby: u.name }); clean(q);
      d = 'تحديث طلب #' + q.id + ' إلى ' + b.st;
    } else if (t === 'import') {
      if (u.role !== 'admin') bad('للأدمن فقط', 403);
      if (m.contracts.length && !b.force) bad('الداتابيز فيها بيانات بالفعل');
      if (!Array.isArray(b.contracts) || !Array.isArray(b.payments) || !b.contracts.length) bad('بيانات غير صالحة');
      const old = {}; m.contracts.forEach(c => old[c.id] = c.ptok);
      m.contracts = b.contracts.map(c => Object.assign({}, c, { ptok: old[c.id] || rid(12) }));
      const docs = {}; m.payments.forEach(p => { if (p.docs) docs[p.id] = p.docs; });
      m.payments = b.payments.map(p => Object.assign({}, p, docs[p.id] ? { docs: docs[p.id] } : {}));
      m.seq.pay = m.payments.reduce((a, p) => Math.max(a, +p.id || 0), 0);
      d = 'رفع بيانات: ' + m.contracts.length + ' عقد و' + m.payments.length + ' دفعة';
    } else bad('عملية غير معروفة');
    m.rev = (m.rev || 0) + 1;
    m.log.push({ at, by: u.name, d }); if (m.log.length > 400) m.log = m.log.slice(-400);
    return { v: m };
  });
  return r.v;
}
async function userOp(u, b) {
  if (u.role !== 'admin') bad('للأدمن فقط', 403);
  await mutate(USERS, us => {
    const name = str(b.username, 60).toLowerCase();
    if (!/^[a-z0-9._-]{3,}$/.test(name)) bad('اسم المستخدم: حروف إنجليزية وأرقام فقط (3 على الأقل)');
    if (us.users.some(z => z.username === name && z.id !== b.id)) bad('اسم المستخدم مستخدم بالفعل');
    let x;
    if (b.id) x = us.users.find(z => z.id === b.id) || bad('المستخدم غير موجود', 404);
    else { if (String(b.password || '').length < 6) bad('كلمة السر 6 حروف على الأقل'); x = { id: 'u' + (++us.seq), mustChange: true }; us.users.push(x); }
    const perms = {}; PERMS.forEach(p => { if (b.perms && b.perms[p]) perms[p] = true; });
    Object.assign(x, { username: name, name: str(b.name, 60) || name, role: b.role === 'admin' ? 'admin' : 'user', perms, active: b.active !== false });
    if (b.password) { if (String(b.password).length < 6) bad('كلمة السر 6 حروف على الأقل'); setPw(x, b.password); x.mustChange = x.id !== u.id; }
    if (!us.users.some(z => z.role === 'admin' && z.active)) bad('لازم يفضل أدمن واحد مفعّل على الأقل');
    return { v: us };
  });
}
async function changePw(u, b) {
  if (String(b.password || '').length < 6) bad('كلمة السر 6 حروف على الأقل');
  let out;
  await mutate(USERS, us => {
    const x = us.users.find(z => z.id === u.id);
    if (hashPw(b.old, x.salt) !== x.hash) bad('كلمة السر الحالية غير صحيحة');
    setPw(x, b.password); x.mustChange = false; out = x; return { v: us };
  });
  return { token: token(out), me: pub(out) };
}

/* ---------- client portal ---------- */
function portal(m, tok) {
  const c = tok && tok.length >= 16 && m && m.contracts.find(x => x.ptok === tok);
  if (!c) bad('الرابط غير صحيح', 404);
  const T = today(), ps = m.payments.filter(p => p.c === c.id).sort((a, b) => a.due < b.due ? -1 : 1);
  const paid = ps.filter(p => p.st === 'done').reduce((a, p) => a + p.amt, 0);
  return { client: c.client, unit: c.unit, floor: c.floor || '', active: c.st === 'active', value: c.value || 0, maint: c.maint || 0, paid, today: T,
    payments: ps.map(p => ({ due: p.due, amt: p.amt, type: p.type, st: p.st === 'done' ? 'done' : (c.st === 'active' && p.due < T ? 'late' : 'due') })),
    requests: m.requests.filter(q => q.c === c.id).map(q => ({ id: q.id, type: q.type, text: q.text, st: q.st, at: q.at, reply: q.reply || '' })).reverse() };
}
async function portalAdd(b) {
  if (!RT.includes(b.type) || str(b.text).length < 3) bad('اكتب تفاصيل الطلب');
  const r = await mutate(MAIN, m => {
    const c = b.tok && String(b.tok).length >= 16 && m && m.contracts.find(x => x.ptok === b.tok);
    if (!c) bad('الرابط غير صحيح', 404);
    if (m.requests.filter(q => q.c === c.id && (q.st === 'new' || q.st === 'progress')).length >= 5) bad('لديك طلبات مفتوحة بالفعل، برجاء انتظار الرد عليها');
    m.requests.push(clean({ id: ++m.seq.req, c: c.id, type: b.type, text: str(b.text, 1000), phone: str(b.phone, 30), st: 'new', at: new Date().toISOString(), src: 'client' }));
    m.rev++; return { v: m };
  });
  return portal(r.v, b.tok);
}

/* ---------- http ---------- */
async function body(req) {
  if (req.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body)) return req.body;
  const ch = []; for await (const c of req) ch.push(c);
  const s = Buffer.concat(ch).toString(); return s ? JSON.parse(s) : {};
}
module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Cache-Control', 'no-store');
  if (req.method === 'OPTIONS') { res.statusCode = 204; return res.end(); }
  const send = (code, o) => { res.statusCode = code; res.setHeader('Content-Type', 'application/json; charset=utf-8'); res.end(JSON.stringify(o)); };
  try {
    const url = new URL(req.url, 'http://x'), q = url.searchParams;
    const r = q.get('r') || url.pathname.replace(/^\/api\/?/, '');
    const b = req.method === 'POST' ? await body(req) : {};
    if (r === 'health') {
      const k = 'db/health.json', n = Date.now(); let cas = false;
      const env = { secret: !!SECRET, admin: !!process.env.ADMIN_INIT_PASSWORD, blob: !!process.env.BLOB_READ_WRITE_TOKEN, today: today() };
      try {
        const a = await store.read(k); await store.write(k, { n }, a.etag);
        const c = await store.read(k);
        try { await store.write(k, { n: 0 }, a.etag || '"stale"'); } catch (e) { cas = !!e.conflict; }
        // same round trip with a document the size of the real database
        const kb = 'db/health-big.json', pad = 'تحصيل '.repeat(30000); let big = 'fail', etags = '';
        try {
          const b0 = await store.read(kb, true); await store.write(kb, { n, pad }, b0.etag);
          const b1 = await store.read(kb, true); etags = b1.raw + ' / ' + b1.etag;
          await store.write(kb, { n: n + 1, pad }, b1.etag);
          const b2 = await store.read(kb, true); big = b2.v && b2.v.n === n + 1 ? 'ok' : 'stale';
        } catch (e) { big = 'fail: ' + String(e && e.message).slice(0, 80); }
        return send(200, Object.assign({ ok: !!(c.v && c.v.n === n), cas, big, etags }, env));
      } catch (e) { return send(200, Object.assign({ ok: false, storage: String(e && e.message).slice(0, 200) }, env)); }
    }
    if (r === 'login') return send(200, await login(b));
    if (r === 'client') return send(200, req.method === 'POST' ? await portalAdd(b) : portal((await store.read(MAIN)).v, q.get('tok')));
    const { u, us } = await auth(req);
    if (r === 'password') return send(200, await changePw(u, b));
    if (u.mustChange) bad('يجب تغيير كلمة السر أولاً', 428);
    if (r === 'data') { const m = (await store.read(MAIN)).v; return send(200, view(m, u, us)); }
    if (r === 'op') return send(200, view(await op(u, b), u, us));
    if (r === 'user') { await userOp(u, b); return send(200, view((await store.read(MAIN)).v, u, await loadUsers())); }
    if (r === 'doc') {
      const k = q.get('k') || '', m = (await store.read(MAIN)).v || empty();
      if (!view(m, u, us).payments.some(p => (p.docs || []).some(d => d.k === k))) bad('غير موجود', 404);
      const f = await store.getFile(k); if (!f) bad('غير موجود', 404);
      res.statusCode = 200; res.setHeader('Content-Type', f.type); res.setHeader('X-Content-Type-Options', 'nosniff'); return res.end(f.buf);
    }
    bad('not found', 404);
  } catch (e) {
    if (e instanceof Err) return send(e.code, { error: e.message });
    console.error(e); send(500, { error: 'حدث خطأ في السيرفر' });
  }
};
