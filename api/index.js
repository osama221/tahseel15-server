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
    async list(prefix) {
      const out = []; let cursor;
      do { const r = await B.list({ prefix, cursor, limit: 1000 }); r.blobs.forEach(b => out.push({ path: b.pathname, size: b.size, at: b.uploadedAt })); cursor = r.hasMore ? r.cursor : null; } while (cursor);
      return out;
    },
    async del(paths) { if (paths.length) await B.del(paths); },
    async putText(path, text) { await B.put(path, text, { access: 'private', contentType: 'application/json', addRandomSuffix: false, allowOverwrite: true }); },
    async getText(path) {
      const r = await B.get(path, { access: 'private', useCache: false });
      return r && r.statusCode === 200 ? await new Response(r.stream).text() : null;
    },
    async getFile(path) {
      const r = await B.get(path, { access: 'private' });
      if (!r || r.statusCode !== 200) return null;
      return { buf: Buffer.from(await new Response(r.stream).arrayBuffer()), type: r.blob.contentType };
    },
  };
}

const MAIN = 'db/main.json', USERS = 'db/users.json';
const PERMS = ['viewAll', 'dashboard', 'contact', 'collect', 'edit', 'requests', 'export', 'treasury'];
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
function pub(u) { return { id: u.id, username: u.username, name: u.name, role: u.role, perms: u.perms || {}, projs: u.projs || [], active: u.active, mustChange: !!u.mustChange }; }
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

/* ---------- treasury ---------- */
// The cash balance = opening balance + cash collections + other cash in − expenses − cash deposited to the bank,
// counting only movements on or after the treasury start date (older cash collections from the sheets are not in the box).
// Added to the revision the phones see: raising it makes every phone reload the full data once (after new data such as the treasury is added to the view).
const DATA_FMT = 1e6;
const TR_START = '2026-10-15', TRK = ['in', 'exp', 'dep'];
const isCash = p => p.st === 'done' && !!p.cdate && (!!p.tr || /cash|كاش|نقد|خزن/i.test(p.cacc || ''));
const trConf = m => Object.assign({ start: TR_START, open: 0 }, m.trc || {}, { set: !!m.trc });
const ccList = m => m.ccs || projects(m).map(p => ({ id: 'cc-' + p.id, name: 'مشروع ' + p.name }))
  .concat([{ id: 'cc-adm', name: 'مصاريف إدارية عامة' }, { id: 'cc-sal', name: 'رواتب وأجور' }, { id: 'cc-mkt', name: 'تسويق وعمولات' }, { id: 'cc-misc', name: 'نثريات' }]);
// Bank accounts: a collection lands on an account when its collection account text matches the account's name or one of its other names.
const BTK = ['in', 'exp', 'out', 'wd', 'xfer'];
const nk = s => String(s || '').toLowerCase().replace(/[\s._\-\/]+/g, '');
const banks = m => m.banks || [];
function bankOf(m) {
  const k = {}; banks(m).forEach(b => [b.name].concat(b.keys || []).forEach(x => { if (nk(x)) k[nk(x)] = b; }));
  return p => (p.bk && banks(m).find(b => b.id === p.bk)) || k[nk(p.cacc)];
}
function trView(m) {
  const cf = trConf(m), cm = {}; m.contracts.forEach(c => cm[c.id] = c);
  const bo = bankOf(m), bcol = [], accs = {};
  m.payments.forEach(p => {
    if (p.st !== 'done' || !p.cdate) return;
    if (p.cacc) { const a = accs[nk(p.cacc)] || (accs[nk(p.cacc)] = { n: 0, v: {} }); a.n++; a.v[p.cacc] = (a.v[p.cacc] || 0) + 1; }
    if (isCash(p) || !cm[p.c]) return;
    const b = bo(p);
    if (b && p.cdate >= b.start && !(b.stmt && p.cdate <= b.stmt)) bcol.push({ p: p.id, bank: b.id, date: p.cdate, amt: p.amt, client: cm[p.c].client, unit: cm[p.c].unit || '', acc: p.cacc || '', by: p.cby || '', at: p.cat || '' });
  });
  const cash = m.payments.filter(p => isCash(p) && p.cdate >= cf.start && cm[p.c])
    .map(p => ({ p: p.id, date: p.cdate, amt: p.amt, client: cm[p.c].client, unit: cm[p.c].unit || '', by: p.cby || '', at: p.cat || '' }));
  return { conf: cf, ccs: ccList(m), items: m.tr || [], cash, banks: banks(m), bt: m.bt || [], bcol,
    accs: Object.values(accs).sort((a, b) => b.n - a.n).slice(0, 40).map(a => ({ name: Object.keys(a.v).sort((x, y) => a.v[y] - a.v[x])[0], n: a.n })) };
}

/* ---------- data views ---------- */
const empty = () => ({ rev: 0, contracts: [], payments: [], followups: [], requests: [], log: [], seq: { pay: 0, fu: 0, req: 0 } });
const S15 = { id: 's15', name: '15 شقة' }, NEW_PROJECTS = ['pc', 'ph', 'pk', 'i350', 'i389'];
const PREFIX = { s15: '', pc: 'C-', ph: 'H-', pk: 'PK-', i350: 'I350-', i389: 'I389-' };
const projects = m => (m.projects && m.projects.length ? m.projects : [S15]);
const projOf = c => c.proj || 's15';
// a user may be limited to some projects (empty list = all projects)
const inScope = (u, c) => u.role === 'admin' || !(u.projs && u.projs.length) || u.projs.includes(projOf(c));
const pending = (p, cm) => p.st !== 'done' && cm[p.c] && cm[p.c].st === 'active';
function view(m, u, us) {
  m = m || empty();
  const T = today(), cm = {}; m.contracts.forEach(c => { if (inScope(u, c)) cm[c.id] = c; });
  const all = can(u, 'viewAll'), contact = can(u, 'contact'), reqs = can(u, 'requests');
  let pays = m.payments.filter(p => cm[p.c]);
  if (!all) pays = pays.filter(p => pending(p, cm) && p.due < T);
  const seen = {}; pays.forEach(p => seen[p.c] = 1);
  const strip = c => { const o = Object.assign({}, c, { proj: projOf(c) }); if (!contact) delete o.phone; if (!reqs) delete o.ptok; return o; };
  const cons = m.contracts.filter(c => cm[c.id] && (all || seen[c.id])).map(strip);
  const out = { rev: (m.rev || 0) + DATA_FMT, today: T, me: pub(u), empty: !m.contracts.length, contracts: cons, payments: pays,
    projects: projects(m).filter(p => inScope(u, { proj: p.id })),
    followups: contact || all ? m.followups.filter(f => cm[f.c] && (all || seen[f.c])) : [],
    requests: reqs ? m.requests.filter(q => cm[q.c]) : [] };
  if (reqs && !all) out.cidx = m.contracts.filter(c => cm[c.id] && c.st === 'active').map(c => ({ id: c.id, client: c.client, unit: c.unit, proj: projOf(c) }));
  if (can(u, 'treasury')) out.tr = trView(m);
  if (u.role === 'admin') { out.users = us.users.map(pub); out.log = m.log.slice(-200).reverse(); out.canAdd = NEW_PROJECTS.some(id => !projects(m).some(p => p.id === id)); }
  return out;
}

// App versions before 2.2 do not know about projects or the newer payment types: they keep seeing "15 شقة" only.
function forClient(m, q) {
  if (!m || q.get('v')) return m;
  const keep = new Set(m.contracts.filter(c => projOf(c) === 's15').map(c => c.id));
  return Object.assign({}, m, { projects: [S15], contracts: m.contracts.filter(c => keep.has(c.id)), payments: m.payments.filter(p => keep.has(p.c)),
    followups: m.followups.filter(f => keep.has(f.c)), requests: m.requests.filter(x => keep.has(x.c)) });
}

// Sheet updates prepared on the server. Each is applied once, the next time an admin opens the app.
const UPDATES = [{ id: 'pk-2026-10-04', need: 'pk', load: () => require('../data/update-pk-20261004.json') },
  { id: 'ohm-837-2026-09', run: m => importStatement(m, require('../data/bank-ohm837-202609.json')) },
  { id: 'raya-203-2025-2026', run: m => importStatement(m, require('../data/bank-raya203-2025-2026.json')) }];
// A bank statement: sets the account's opening balance at the statement start and adds every line as a bank movement.
// Collections recorded in the app up to the statement end are then not counted again (the statement already has them).
function importStatement(m, s) {
  m.seq = m.seq || {};
  const l = banks(m).map(x => Object.assign({}, x));
  let bk = l.find(x => [x.name].concat(x.keys || []).some(k => s.match.includes(nk(k))) || x.no === s.no);
  if (!bk) { bk = { id: 'bk' + rid(6), name: s.name, keys: [] }; l.push(bk); }
  bk.keys = [...new Set((bk.keys || []).concat(s.keys).filter(k => nk(k) !== nk(bk.name)))];
  Object.assign(bk, { no: s.no, start: s.start, open: s.open, stmt: s.end });
  m.banks = l;
  if (s.cc && !ccList(m).some(c => c.id === s.cc.id)) m.ccs = ccList(m).concat(s.cc);
  const have = new Set((m.bt || []).map(e => e.src).filter(Boolean));
  let n = 0;
  m.bt = (m.bt || []).concat(s.tx.filter(t => !have.has(t.src)).map((t, i) => { n++; return clean(Object.assign({ id: (m.seq.bt = (m.seq.bt || 0) + 1), bank: bk.id, by: 'كشف البنك', at: new Date(Date.parse(t.date + 'T06:00:00Z') + i * 1000).toISOString() }, t)); }));
  return 'استيراد كشف ' + bk.name + ' من ' + s.start + ' إلى ' + s.end + ': ' + n + ' حركة · رصيد أول ' + s.open + ' · رصيد آخر ' + s.close;
}
const pendingUpdates = m => !m ? [] : UPDATES.filter(x => !(m.applied || []).includes(x.id) && (!x.need || projects(m).some(p => p.id === x.need)));
// A summary sheet gives only each client's collected total: mark the oldest unpaid instalments as collected until the total matches.
function settle(m, upd) {
  let n = 0, sum = 0, cons = 0;
  const r2 = v => Math.round(v * 100) / 100;
  for (const it of upd.items) {
    const ps = m.payments.filter(p => p.c === it.c);
    let need = r2(it.coll - ps.filter(p => p.st === 'done').reduce((a, p) => a + p.amt, 0));
    if (need < 1) continue;
    cons++;
    for (const p of ps.filter(x => x.st !== 'done').sort((a, b) => a.due < b.due ? -1 : a.due > b.due ? 1 : a.id - b.id)) {
      if (need < 1) break;
      if (p.amt > need + 0.001) { const rest = Object.assign({}, p, { id: ++m.seq.pay, amt: r2(p.amt - need) }); delete rest.docs; m.payments.push(rest); p.amt = need; }
      Object.assign(p, { st: 'done', cdate: upd.date, cby: upd.by, note: [p.note, upd.note].filter(Boolean).join(' · ') });
      need = r2(need - p.amt); n++; sum += p.amt;
    }
  }
  return { n, sum, cons };
}
async function applyUpdates() {
  return (await mutate(MAIN, m => {
    const todo = pendingUpdates(m);
    if (!todo.length) return { skip: true, v: m };
    for (const x of todo) {
      m.applied = (m.applied || []).concat(x.id);
      if (x.run) { m.log.push({ at: new Date().toISOString(), by: 'تحديث', d: x.run(m) }); continue; }
      const upd = x.load(), r = settle(m, upd);
      m.log.push({ at: new Date().toISOString(), by: upd.by, d: 'تحديث ' + x.id + ': ' + r.n + ' قسط اتسجل محصّل لـ ' + r.cons + ' عميل بإجمالي ' + Math.round(r.sum) });
    }
    m.rev = (m.rev || 0) + 1;
    return { v: m };
  })).v;
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
const TYPES = ['dp', 'inst', 'maint', 'elev', 'other'], METH = ['chq', 'trf', 'cash', 'rcpt'], RT = ['finish', 'handover', 'issue'], RS = ['new', 'progress', 'done', 'rejected'];
async function op(u, b) {
  const t = b.t, at = new Date().toISOString(), T = today();
  let doc = null;
  if (t === 'pay.collect' || t === 'pay.doc') {
    need(u, 'collect');
    if (!b.photo) bad('صورة مستند التحصيل إجبارية');
    doc = { k: await savePhoto(b.photo, 'p' + (+b.id || 0)), at, by: u.name };
  }
  if (/^(tr|bt)\.(add|edit)$/.test(t) && b.photo) { need(u, 'treasury'); doc = { k: await savePhoto(b.photo, t.slice(0, 2)), at, by: u.name }; }
  const r = await mutate(MAIN, m => {
    m = m || empty();
    const P = id => { const p = m.payments.find(x => x.id === +id) || bad('الدفعة غير موجودة', 404); C(p.c); return p; };
    const C = id => { const c = m.contracts.find(x => x.id === id) || bad('العقد غير موجود', 404); if (!inScope(u, c)) bad('المشروع ده خارج صلاحياتك', 403); return c; };
    let d = '';
    if (t === 'pay.collect') {
      const p = P(b.id), amt = +b.amt, c = C(p.c);
      if (p.st === 'done') bad('الدفعة مسجلة محصّلة بالفعل');
      if (!(amt > 0) || amt > p.amt + 0.001) bad('المبلغ غير صحيح');
      if (!isDate(b.cdate) || b.cdate > T) bad('تاريخ التحصيل غير صحيح');
      if (amt < p.amt) { const rest = Object.assign({}, p, { id: ++m.seq.pay, amt: Math.round((p.amt - amt) * 100) / 100, note: [p.note, 'باقي دفعة محصّلة جزئياً'].filter(Boolean).join(' · ') }); delete rest.docs; m.payments.push(rest); p.amt = amt; }
      Object.assign(p, { st: 'done', cdate: b.cdate, cacc: str(b.cacc, 60), rcpt: str(b.rcpt, 40), cby: u.name, cat: at }); clean(p);
      if (b.cash) { p.tr = 1; if (!p.cacc) p.cacc = 'cash'; }
      else if (b.bank) { const bk = banks(m).find(x => x.id === b.bank && !x.off); if (bk) { p.bk = bk.id; if (!p.cacc) p.cacc = bk.name; } }
      p.docs = (p.docs || []).concat(doc);
      d = 'تحصيل ' + amt + ' من ' + c.client;
    } else if (t === 'pay.doc') { const p = P(b.id); p.docs = (p.docs || []).concat(doc); d = 'إضافة مستند لدفعة ' + C(p.c).client; }
    else if (t === 'pay.uncollect') { need(u, 'edit'); const p = P(b.id); p.st = p.m === 'chq' ? 'safe' : 'wait'; ['cdate', 'cacc', 'rcpt', 'cby', 'cat', 'tr', 'bk'].forEach(k => delete p[k]); d = 'تراجع عن تحصيل ' + p.amt + ' · ' + C(p.c).client; }
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
      if (b.id) c = C(b.id);
      else {
        const pj = projects(m).find(p => p.id === b.proj) || projects(m)[0];
        if (!inScope(u, { proj: pj.id })) bad('المشروع ده خارج صلاحياتك', 403);
        const pre = PREFIX[pj.id] != null ? PREFIX[pj.id] : pj.id.toUpperCase() + '-';
        const n = m.contracts.filter(x => projOf(x) === pj.id).reduce((a, x) => Math.max(a, parseInt(String(x.id).replace(/^.*cn/i, ''), 10) || 0), 0) + 1;
        c = { id: pre + 'cn' + String(n).padStart(4, '0'), proj: pj.id, st: 'active', ptok: rid(12) }; m.contracts.push(c);
      }
      Object.assign(c, { client: str(b.client, 120), unit: str(b.unit, 60), phone: str(b.phone, 80), date: isDate(b.date) ? b.date : '', floor: str(b.floor, 30), sales: str(b.sales, 60), broker: str(b.broker, 60), note: str(b.note, 300), org: str(b.org, 30), value: +b.value || 0, maint: +b.maint || 0, elev: +b.elev || 0 }); clean(c); if (!c.elev) delete c.elev;
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
    } else if (t === 'tr.add' || t === 'tr.edit') {
      need(u, 'treasury');
      const old = t === 'tr.edit' ? (need(u, 'edit'), (m.tr || []).find(x => x.id === +b.id) || bad('القيد غير موجود', 404)) : null;
      if (old) b.k = old.k;
      const amt = Math.round(+b.amt * 100) / 100, desc = str(b.desc, 200);
      if (!TRK.includes(b.k) || !(amt > 0)) bad('بيانات القيد غير مكتملة');
      if (!isDate(b.date) || b.date > T) bad('تاريخ القيد غير صحيح');
      if (b.date < trConf(m).start) bad('التاريخ قبل بداية حساب الخزنة');
      if (!desc) bad('البيان مطلوب');
      const cc = b.k === 'exp' ? (ccList(m).find(x => x.id === b.cc && !x.off) || bad('اختار مركز التكلفة')) : null;
      let bk = null;
      if (b.k === 'dep') {
        bk = banks(m).find(x => x.id === b.bank && !x.off) || bad('اختار حساب البنك اللي اتعمل فيه الإيداع');
        if (!doc && !(old && old.docs && old.docs.length)) bad('صورة إيصال الإيداع إجبارية');
        if (b.date < bk.start) bad('التاريخ قبل بداية حساب البنك');
      }
      const f = { date: b.date, k: b.k, amt, desc, cc: cc ? cc.id : '', bank: bk ? bk.id : '', who: str(b.who, 80), ref: str(b.ref, 40) };
      if (old) {
        ['cc', 'bank', 'who', 'ref'].forEach(k => delete old[k]); Object.assign(old, f, { eby: u.name, eat: at }); clean(old);
        if (doc) old.docs = (old.docs || []).concat(doc);
      } else {
        m.seq.tr = (m.seq.tr || 0) + 1;
        const e = clean(Object.assign({ id: m.seq.tr }, f, { by: u.name, at }));
        if (doc) e.docs = [doc];
        m.tr = (m.tr || []).concat(e);
      }
      d = (old ? 'تعديل قيد خزنة: ' : '') + (b.k === 'in' ? 'وارد للخزنة ' : b.k === 'dep' ? 'إيداع من الخزنة في ' + bk.name + ' ' : 'مصروف ') + amt + ' · ' + desc + (cc ? ' · ' + cc.name : '');
    } else if (t === 'tr.del') {
      need(u, 'treasury'); need(u, 'edit');
      const e = (m.tr || []).find(x => x.id === +b.id) || bad('القيد غير موجود', 404);
      m.tr = m.tr.filter(x => x !== e);
      d = 'حذف قيد خزنة ' + e.amt + ' · ' + e.desc;
    } else if (t === 'cc.save') {
      need(u, 'treasury');
      const name = str(b.name, 60), l = ccList(m).map(x => Object.assign({}, x));
      if (!name) bad('اسم مركز التكلفة مطلوب');
      if (l.some(x => x.name === name && x.id !== b.id)) bad('الاسم ده موجود بالفعل');
      if (b.id) {
        if (u.role !== 'admin') bad('تعديل مراكز التكلفة للأدمن فقط', 403);
        const x = l.find(z => z.id === b.id) || bad('مركز التكلفة غير موجود', 404);
        x.name = name; if (b.off) x.off = true; else delete x.off;
      } else l.push({ id: 'cc' + rid(6), name });
      m.ccs = l;
      d = (b.id ? 'تعديل' : 'إضافة') + ' مركز تكلفة: ' + name + (b.off ? ' (موقوف)' : '');
    } else if (t === 'bank.save') {
      if (u.role !== 'admin') bad('للأدمن فقط', 403);
      const name = str(b.name, 60), open = Math.round(+b.open * 100) / 100;
      if (!name) bad('اسم الحساب مطلوب');
      if (!isDate(b.start) || b.start > T || !isFinite(open)) bad('تاريخ البداية أو الرصيد غير صحيح');
      const l = banks(m).map(x => Object.assign({}, x));
      const keys = (Array.isArray(b.keys) ? b.keys : String(b.keys || '').split(/[,،\n]/)).map(x => str(x, 60)).filter(Boolean).slice(0, 20);
      const taken = {}; l.forEach(x => { if (x.id !== b.id) [x.name].concat(x.keys || []).forEach(k => taken[nk(k)] = x.name); });
      const clash = [name].concat(keys).find(k => taken[nk(k)]);
      if (clash) bad('«' + clash + '» مستخدم بالفعل لحساب ' + taken[nk(clash)]);
      let x;
      if (b.id) x = l.find(z => z.id === b.id) || bad('الحساب غير موجود', 404);
      else { x = { id: 'bk' + rid(6) }; l.push(x); }
      Object.assign(x, { name, no: str(b.no, 40), keys, start: b.start, open }); if (b.off) x.off = true; else delete x.off; clean(x);
      m.banks = l;
      d = (b.id ? 'تعديل' : 'إضافة') + ' حساب بنك: ' + name + ' · رصيد أول المدة ' + open + ' بتاريخ ' + b.start;
    } else if (t === 'bt.add' || t === 'bt.edit') {
      need(u, 'treasury');
      const old = t === 'bt.edit' ? (need(u, 'edit'), (m.bt || []).find(x => x.id === +b.id) || bad('الحركة غير موجودة', 404)) : null;
      if (old) b.bank = old.bank;
      const bk = banks(m).find(x => x.id === b.bank && (!x.off || old)) || bad('الحساب غير موجود', 404);
      const amt = Math.round(+b.amt * 100) / 100, desc = str(b.desc, 200);
      if (!BTK.includes(b.k) || !(amt > 0)) bad('بيانات الحركة غير مكتملة');
      if (!isDate(b.date) || b.date > T || b.date < bk.start) bad('تاريخ الحركة غير صحيح (قبل بداية الحساب أو في المستقبل)');
      if (!desc) bad('الوصف مطلوب');
      const cc = b.k === 'exp' ? (ccList(m).find(x => x.id === b.cc && !x.off) || bad('اختار مركز التكلفة')) : null;
      const to = b.k === 'xfer' ? (banks(m).find(x => x.id === b.to && !x.off && x.id !== bk.id) || bad('اختار الحساب المحوّل إليه')) : null;
      if (to && b.date < to.start) bad('التاريخ قبل بداية الحساب المحوّل إليه');
      if (b.k === 'wd' && b.date < trConf(m).start) bad('التاريخ قبل بداية حساب الخزنة');
      const f = { bank: bk.id, date: b.date, k: b.k, amt, desc, cc: cc ? cc.id : '', to: to ? to.id : '', who: str(b.who, 80), ref: str(b.ref, 40) };
      if (old) {
        ['cc', 'to', 'who', 'ref'].forEach(k => delete old[k]); Object.assign(old, f, { eby: u.name, eat: at }); clean(old);
        if (doc) old.docs = (old.docs || []).concat(doc);
      } else {
        m.seq.bt = (m.seq.bt || 0) + 1;
        const e = clean(Object.assign({ id: m.seq.bt }, f, { by: u.name, at }));
        if (doc) e.docs = [doc];
        m.bt = (m.bt || []).concat(e);
      }
      d = (old ? 'تعديل حركة · ' : '') + bk.name + ': ' + ({ in: 'إيداع ', exp: 'مصروف ', out: 'صرف ', wd: 'سحب للخزنة ', xfer: 'تحويل إلى ' + (to ? to.name : '') + ' ' })[b.k] + amt + ' · ' + desc + (cc ? ' · ' + cc.name : '');
    } else if (t === 'bt.del') {
      need(u, 'treasury'); need(u, 'edit');
      const e = (m.bt || []).find(x => x.id === +b.id) || bad('الحركة غير موجودة', 404);
      m.bt = m.bt.filter(x => x !== e);
      d = 'حذف حركة بنك ' + e.amt + ' · ' + e.desc;
    } else if (t === 'tr.conf') {
      if (u.role !== 'admin') bad('للأدمن فقط', 403);
      const open = Math.round(+b.open * 100) / 100;
      if (!isDate(b.start) || b.start > T || !isFinite(open)) bad('بيانات غير صحيحة');
      m.trc = { start: b.start, open };
      d = 'ضبط الخزنة: رصيد أول المدة ' + open + ' بتاريخ ' + b.start;
    } else if (t === 'addprojects') {
      if (u.role !== 'admin') bad('للأدمن فقط', 403);
      const add = require('../data/projects.json'), ids = add.projects.map(p => p.id);
      if (projects(m).some(p => ids.includes(p.id)) && !b.force) bad('المشاريع دي مضافة بالفعل');
      m.contracts.forEach(c => { if (!c.proj) c.proj = 's15'; });
      const old = {}, drop = new Set();
      m.contracts.forEach(c => { if (ids.includes(c.proj)) { drop.add(c.id); old[c.id] = c.ptok; } });
      m.contracts = m.contracts.filter(c => !drop.has(c.id)).concat(add.contracts.map(c => Object.assign({}, c, { ptok: old[c.id] || rid(12) })));
      m.payments = m.payments.filter(p => !drop.has(p.c)).concat(add.payments.map(p => Object.assign({ id: ++m.seq.pay }, p)));
      m.followups = m.followups.filter(f => !drop.has(f.c)); m.requests = m.requests.filter(q => !drop.has(q.c));
      m.projects = projects(m).filter(p => !ids.includes(p.id)).concat(add.projects);
      d = 'إضافة ' + add.projects.length + ' مشاريع: ' + add.contracts.length + ' عقد و' + add.payments.length + ' دفعة';
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
    Object.assign(x, { username: name, name: str(b.name, 60) || name, role: b.role === 'admin' ? 'admin' : 'user', perms, active: b.active !== false,
      projs: Array.isArray(b.projs) ? b.projs.map(v => str(v, 20)).filter(Boolean).slice(0, 30) : (x.projs || []) });
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

/* ---------- backups ---------- */
// One copy per day (taken by the daily scheduled call, at most once a day), plus copies the admin takes by hand.
// Daily copies are kept for 30 days; manual and pre-restore copies are kept until deleted.
const BK = 'db/backups/';
async function backup(kind) {
  const day = today(), name = kind ? kind + '-' + new Date().toISOString().replace(/[:.]/g, '-') : day;
  if (!kind && (await store.list(BK + day + '.json')).length) return { skip: true, name };
  const m = (await store.read(MAIN)).v, us = (await store.read(USERS)).v;
  if (!m) return { skip: true };
  await store.putText(BK + name + '.json', JSON.stringify({ at: new Date().toISOString(), rev: m.rev, main: m, users: us }));
  if (!kind) {
    const daily = (await store.list(BK)).filter(b => /\/\d{4}-\d{2}-\d{2}\.json$/.test(b.path)).sort((a, b) => a.path < b.path ? 1 : -1);
    await store.del(daily.slice(30).map(b => b.path));
  }
  return { name };
}
async function backups() {
  return (await store.list(BK)).map(b => ({ name: b.path.slice(BK.length).replace(/\.json$/, ''), size: b.size, at: b.at })).sort((a, b) => String(a.at) < String(b.at) ? 1 : -1);
}
async function restore(u, name) {
  if (u.role !== 'admin') bad('للأدمن فقط', 403);
  if (!/^[\w.-]+$/.test(name || '')) bad('اسم النسخة غير صحيح');
  const txt = await store.getText(BK + name + '.json'); if (!txt) bad('النسخة غير موجودة', 404);
  const snap = JSON.parse(txt);
  await backup('pre-restore');   // so a restore can itself be undone
  return (await mutate(MAIN, m => {
    const v = snap.main; v.rev = ((m && m.rev) || 0) + 1;
    v.log = (v.log || []).concat({ at: new Date().toISOString(), by: u.name, d: 'استرجاع نسخة احتياطية: ' + name });
    return { v };
  })).v;
}

/* ---------- client portal ---------- */
function portal(m, tok) {
  const c = tok && tok.length >= 16 && m && m.contracts.find(x => x.ptok === tok);
  if (!c) bad('الرابط غير صحيح', 404);
  const T = today(), ps = m.payments.filter(p => p.c === c.id).sort((a, b) => a.due < b.due ? -1 : 1);
  const paid = ps.filter(p => p.st === 'done').reduce((a, p) => a + p.amt, 0);
  return { client: c.client, unit: c.unit, floor: c.floor || '', active: c.st === 'active', value: c.value || 0, maint: (c.maint || 0) + (c.elev || 0), paid, today: T,
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
    if (r === 'backup' && req.method === 'GET') return send(200, await backup());   // daily scheduled call
    if (r === 'client') return send(200, req.method === 'POST' ? await portalAdd(b) : portal((await store.read(MAIN)).v, q.get('tok')));
    const { u, us } = await auth(req);
    if (r === 'password') return send(200, await changePw(u, b));
    if (u.mustChange) bad('يجب تغيير كلمة السر أولاً', 428);
    if (r === 'backups') { if (u.role !== 'admin') bad('للأدمن فقط', 403); return send(200, { items: await backups() }); }
    if (r === 'backup') { if (u.role !== 'admin') bad('للأدمن فقط', 403); return send(200, Object.assign(await backup('manual'), { items: await backups() })); }
    if (r === 'backupfile') {
      if (u.role !== 'admin') bad('للأدمن فقط', 403);
      const name = q.get('name') || ''; if (!/^[\w.-]+$/.test(name)) bad('اسم غير صحيح');
      const txt = await store.getText(BK + name + '.json'); if (!txt) bad('النسخة غير موجودة', 404);
      res.statusCode = 200; res.setHeader('Content-Type', 'application/json; charset=utf-8'); return res.end(txt);
    }
    if (r === 'restore') return send(200, view(forClient(await restore(u, b.name), q), u, us));
    if (r === 'data') {
      let m = (await store.read(MAIN)).v;
      if (u.role === 'admin' && q.get('v') && pendingUpdates(m).length) m = await applyUpdates();
      // unchanged since the phone's copy (same revision, same day): skip resending the whole dataset
      if (m && q.get('rev') && +q.get('rev') === (m.rev || 0) + DATA_FMT && q.get('day') === today()) return send(200, { same: true, me: pub(u), nusers: us.users.length });
      return send(200, view(forClient(m, q), u, us));
    }
    if (r === 'feed') {   // collections recorded by other users since a given time (polled by the phones for notifications)
      const m = forClient((await store.read(MAIN)).v, q) || empty(), since = q.get('since') || '', cm = {};
      m.contracts.forEach(c => cm[c.id] = c);
      const items = !can(u, 'viewAll') ? [] : m.payments.filter(p => p.st === 'done' && p.cat && p.cat > since && p.cby !== u.name && cm[p.c] && inScope(u, cm[p.c]))
        .map(p => ({ id: p.id, amt: p.amt, by: p.cby || '', at: p.cat, client: (cm[p.c] || {}).client || '', unit: (cm[p.c] || {}).unit || '' }))
        .sort((x, y) => x.at < y.at ? -1 : 1).slice(-20);
      return send(200, { now: new Date().toISOString(), items });
    }
    if (r === 'op') return send(200, view(forClient(await op(u, b), q), u, us));
    if (r === 'user') { await userOp(u, b); return send(200, view(forClient((await store.read(MAIN)).v, q), u, await loadUsers())); }
    if (r === 'doc') {
      const k = q.get('k') || '', m = (await store.read(MAIN)).v || empty();
      const has = x => (x.docs || []).some(d => d.k === k);
      if (!view(m, u, us).payments.some(has) && !(can(u, 'treasury') && (m.tr || []).concat(m.bt || []).some(has))) bad('غير موجود', 404);
      const f = await store.getFile(k); if (!f) bad('غير موجود', 404);
      res.statusCode = 200; res.setHeader('Content-Type', f.type); res.setHeader('X-Content-Type-Options', 'nosniff'); return res.end(f.buf);
    }
    bad('not found', 404);
  } catch (e) {
    if (e instanceof Err) return send(e.code, { error: e.message });
    console.error(e); send(500, { error: 'حدث خطأ في السيرفر' });
  }
};
