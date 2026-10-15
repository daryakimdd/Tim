/* ================================================================
   СЕРВЕР САЙТА «Навигатор диагноза» — всё в одном файле
   ----------------------------------------------------------------
   Что умеет:
   1. Раздаёт сам сайт (index.html) — сайт и сервер живут вместе
   2. Отправляет коды подтверждения на почту (Nodemailer)
   3. Аккаунты: регистрация (с кодом), вход, роли user/admin
   4. Публикации (статьи/истории): отправка на проверку, модерация
   5. Комментарии и «Сохранённое»
   Данные хранятся в файле data.json (создаётся сам при первом
   запуске). Пароли хранятся в зашифрованном виде (bcrypt).
   Деплой: Render.com — инструкция в конце файла.
   ================================================================ */
const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname)); /* раздаёт index.html и др. файлы */

/* ================== НАСТРОЙКИ (переменные окружения на Render) ==================
   SERVER_KEY      — секретный ключ сайта (придумайте длинный случайный)
   GMAIL_USER      — ваша почта, например daryakimdd@gmail.com
   GMAIL_APP_PASS  — «пароль приложения» Google (16 символов, НЕ обычный
                     пароль!). myaccount.google.com → Безопасность →
                     Двухэтапная аутентификация → Пароли приложений
   FROM_NAME       — имя отправителя в письме
   ADMIN_CONTACT   — почта, которая становится администратором
   PORT            — порт (на Render задаётся автоматически)              */
const SERVER_KEY = process.env.SERVER_KEY || 'смените-этот-ключ';
const GMAIL_USER = process.env.GMAIL_USER || '';
const GMAIL_APP_PASS = process.env.GMAIL_APP_PASS || '';
const FROM_NAME = process.env.FROM_NAME || 'Навигатор диагноза';
const ADMIN_CONTACT = process.env.ADMIN_CONTACT || 'daryakimdd@gmail.com';
const PORT = process.env.PORT || 3000;
const RATE_LIMIT_MS = Number(process.env.RATE_LIMIT_MS || 60000); /* пауза между письмами с одного IP */
const DB_FILE = path.join(__dirname, 'data.json');

/* ================== БАЗА ДАННЫХ (JSON-файл) ================== */
function loadDB(){
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch(e){ return { users: [], posts: [], comments: {}, saved: {}, codes: {}, sessions: {} }; }
}
let db = loadDB();
function saveDB(){ fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 1)); }

/* ================== ПОЧТА ================== */
const mailReady = !!(GMAIL_USER && GMAIL_APP_PASS);
const transporter = mailReady ? nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: Number(process.env.SMTP_PORT || 465),
  secure: true,
  auth: { user: GMAIL_USER, pass: GMAIL_APP_PASS }
}) : null;

function sendCodeEmail(email, code){
  if(!transporter) return Promise.resolve(false);
  return transporter.sendMail({
    from: `"${FROM_NAME}" <${GMAIL_USER}>`,
    to: email,
    subject: `Код подтверждения — ${FROM_NAME}`,
    text: `Здравствуйте!\n\nВаш код подтверждения: ${code}\n\nЕсли это были не вы — просто проигнорируйте письмо.`,
    html: `<div style="font-family:Arial,sans-serif;font-size:15px;line-height:1.6">
      <p>Здравствуйте!</p>
      <p>Ваш код подтверждения:<br><b style="font-size:24px;letter-spacing:4px">${code}</b></p>
      <p style="color:#777;font-size:13px">Если это были не вы — просто проигнорируйте письмо.</p>
    </div>`
  }).then(() => true).catch(e => { console.error('Почта:', e.message); return false; });
}

/* ================== УТИЛИТЫ ================== */
const now = () => Date.now();
const newToken = () => crypto.randomBytes(24).toString('hex');
const clean = s => String(s || '').trim();
const isEmail = s => /^\S+@\S+\.\S+$/.test(s);

function auth(req){
  const token = clean(req.headers.authorization || '').replace(/^Bearer\s+/i, '') || clean(req.body.token || req.query.token);
  const session = db.sessions[token];
  if(!session) return null;
  const user = db.users.find(u => u.contact === session.contact);
  return user ? { user, token } : null;
}
function isAdminUser(user){ return user && (user.role === 'admin' || user.contact === ADMIN_CONTACT); }
function publicUser(u){ return { name: u.name, contact: u.contact, contactMode: u.contactMode, role: u.role }; }

/* Простая защита от спама: не чаще 1 запроса в 60 секунд с одного IP */
const lastHit = new Map();
function rateLimit(req, res){
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '?').toString().split(',')[0].trim();
  const t = now();
  if(lastHit.has(ip) && t - lastHit.get(ip) < RATE_LIMIT_MS){ res.status(429).json({ ok: false, error: 'Слишком часто, подождите минуту' }); return false; }
  lastHit.set(ip, t);
  return true;
}

/* ================== API: КОДЫ ПОДТВЕРЖДЕНИЯ ================== */
/* Запрос кода (регистрация/вход/восстановление). Письмо уходит на почту. */
app.post('/api/code', async (req, res) => {
  if(!rateLimit(req, res)) return;
  const contact = clean(req.body.contact);
  if(!isEmail(contact)) return res.status(400).json({ ok: false, error: 'Некорректный email' });
  const code = String(Math.floor(100000 + Math.random() * 900000));
  db.codes[contact] = { code, exp: now() + 10 * 60 * 1000 }; /* код живёт 10 минут */
  saveDB();
  const sent = await sendCodeEmail(contact, code);
  const out = { ok: true, sent };
  if(!sent) out.devCode = code; /* если почта не настроена — код в ответе (для теста) */
  res.json(out);
});

function checkCode(contact, code){
  const c = db.codes[contact];
  if(!c || c.exp < now() || c.code !== clean(code)) return false;
  delete db.codes[contact];
  return true;
}

/* ================== API: АККАУНТЫ ================== */
/* Регистрация: имя, контакт, пароль, код из письма */
app.post('/api/register', (req, res) => {
  const name = clean(req.body.name), contact = clean(req.body.contact),
        contactMode = clean(req.body.contactMode) || 'email',
        pass = String(req.body.pass || ''), code = clean(req.body.code);
  if(name.length < 2) return res.status(400).json({ ok: false, error: 'Введите имя' });
  if(contactMode === 'email' && !isEmail(contact)) return res.status(400).json({ ok: false, error: 'Некорректный email' });
  if(pass.length < 4) return res.status(400).json({ ok: false, error: 'Пароль не короче 4 символов' });
  if(db.users.some(u => u.contact === contact)) return res.status(400).json({ ok: false, error: 'Такой аккаунт уже зарегистрирован' });
  if(contactMode === 'email' && !checkCode(contact, code)) return res.status(400).json({ ok: false, error: 'Неверный или просроченный код' });
  const user = { name, contact, contactMode, pass: bcrypt.hashSync(pass, 10), role: contact === ADMIN_CONTACT ? 'admin' : 'user', created: now() };
  db.users.push(user);
  const token = newToken();
  db.sessions[token] = { contact, created: now() };
  saveDB();
  res.json({ ok: true, token, user: publicUser(user) });
});

/* Вход: контакт + пароль */
app.post('/api/login', (req, res) => {
  const contact = clean(req.body.contact), pass = String(req.body.pass || '');
  const user = db.users.find(u => u.contact === contact);
  if(!user || !bcrypt.compareSync(pass, user.pass)) return res.status(400).json({ ok: false, error: 'Неверная почта/телефон или пароль' });
  const token = newToken();
  db.sessions[token] = { contact, created: now() };
  saveDB();
  res.json({ ok: true, token, user: publicUser(user) });
});

/* Кто я (по токену) */
app.get('/api/me', (req, res) => {
  const a = auth(req);
  if(!a) return res.status(401).json({ ok: false });
  res.json({ ok: true, user: publicUser(a.user) });
});

/* Восстановление пароля: контакт + код + новый пароль */
app.post('/api/reset-pass', (req, res) => {
  const contact = clean(req.body.contact), code = clean(req.body.code), pass = String(req.body.pass || '');
  const user = db.users.find(u => u.contact === contact);
  if(!user) return res.status(400).json({ ok: false, error: 'Аккаунт не найден' });
  if(!checkCode(contact, code)) return res.status(400).json({ ok: false, error: 'Неверный или просроченный код' });
  if(pass.length < 4) return res.status(400).json({ ok: false, error: 'Пароль не короче 4 символов' });
  user.pass = bcrypt.hashSync(pass, 10);
  saveDB();
  res.json({ ok: true });
});

/* Выход */
app.post('/api/logout', (req, res) => {
  const a = auth(req);
  if(a){ delete db.sessions[a.token]; saveDB(); }
  res.json({ ok: true });
});

/* ================== API: ПУБЛИКАЦИИ ================== */
/* Список: ?dir=ras|dcp — опубликованные (+ «на проверке» для автора/админа, если передан токен) */
app.get('/api/posts', (req, res) => {
  const dir = clean(req.query.dir);
  const a = auth(req);
  const meName = a ? a.user.name : null;
  const adm = a && isAdminUser(a.user);
  let posts = db.posts.filter(p => !dir || p.dir === dir);
  posts = posts.filter(p => p.status === 'published' || (meName && (p.author === meName || adm)));
  res.json({ ok: true, posts: posts.slice().reverse() });
});

/* Добавить публикацию — уходит на проверку */
app.post('/api/posts', (req, res) => {
  const a = auth(req);
  if(!a) return res.status(401).json({ ok: false, error: 'Войдите в аккаунт' });
  const title = clean(req.body.title), text = clean(req.body.text),
        topic = clean(req.body.topic), dir = clean(req.body.dir);
  if(title.length < 3 || text.length < 10) return res.status(400).json({ ok: false, error: 'Заполните заголовок и текст' });
  const post = { id: now(), dir, title, topic, text, author: a.user.name, status: 'pending', created: now() };
  db.posts.push(post);
  saveDB();
  res.json({ ok: true, post });
});

/* Модерация: редактировать / опубликовать (status: 'published') */
app.patch('/api/posts/:id', (req, res) => {
  const a = auth(req);
  if(!a) return res.status(401).json({ ok: false });
  const p = db.posts.find(x => String(x.id) === String(req.params.id));
  if(!p) return res.status(404).json({ ok: false });
  const adm = isAdminUser(a.user);
  if(p.author !== a.user.name && !adm) return res.status(403).json({ ok: false, error: 'Нет прав' });
  if(req.body.title !== undefined) p.title = clean(req.body.title);
  if(req.body.text !== undefined) p.text = clean(req.body.text);
  if(req.body.status !== undefined && adm) p.status = req.body.status === 'published' ? 'published' : 'pending';
  saveDB();
  res.json({ ok: true, post: p });
});

/* Удалить (автор — свою на проверке, админ — любую) */
app.delete('/api/posts/:id', (req, res) => {
  const a = auth(req);
  if(!a) return res.status(401).json({ ok: false });
  const p = db.posts.find(x => String(x.id) === String(req.params.id));
  if(!p) return res.status(404).json({ ok: false });
  if(p.author !== a.user.name && !isAdminUser(a.user)) return res.status(403).json({ ok: false });
  db.posts = db.posts.filter(x => x.id !== p.id);
  saveDB();
  res.json({ ok: true });
});

/* ================== API: КОММЕНТАРИИ ================== */
app.get('/api/comments', (req, res) => {
  const post = clean(req.query.post);
  res.json({ ok: true, comments: db.comments[post] || [] });
});
app.post('/api/comments', (req, res) => {
  const a = auth(req);
  if(!a) return res.status(401).json({ ok: false, error: 'Войдите, чтобы комментировать' });
  const post = clean(req.body.post), text = clean(req.body.text);
  if(!post || !text) return res.status(400).json({ ok: false });
  const c = { user: a.user.name, text, time: now() };
  (db.comments[post] = db.comments[post] || []).push(c);
  saveDB();
  res.json({ ok: true, comment: c });
});

/* ================== API: СОХРАНЁННОЕ ================== */
app.get('/api/saved', (req, res) => {
  const a = auth(req);
  if(!a) return res.status(401).json({ ok: false });
  res.json({ ok: true, saved: db.saved[a.user.contact] || [] });
});
app.post('/api/saved', (req, res) => {
  const a = auth(req);
  if(!a) return res.status(401).json({ ok: false });
  const id = clean(req.body.id);
  const list = db.saved[a.user.contact] = db.saved[a.user.contact] || [];
  if(!list.includes(id)) list.push(id);
  saveDB();
  res.json({ ok: true, saved: list });
});
app.delete('/api/saved', (req, res) => {
  const a = auth(req);
  if(!a) return res.status(401).json({ ok: false });
  const id = clean(req.body.id);
  db.saved[a.user.contact] = (db.saved[a.user.contact] || []).filter(x => String(x) !== String(id));
  saveDB();
  res.json({ ok: true, saved: db.saved[a.user.contact] });
});

/* ================== ПРОЧЕЕ ================== */
/* Старый endpoint (для текущей версии сайта) — код по ключу */
app.post('/send-code', async (req, res) => {
  if(!rateLimit(req, res)) return;
  const { email, code, key } = req.body || {};
  if(key !== SERVER_KEY) return res.status(403).json({ ok: false });
  if(!isEmail(email) || !/^\d{6}$/.test(code || '')) return res.status(400).json({ ok: false });
  const sent = await sendCodeEmail(email, code);
  res.json({ ok: true, sent });
});

app.get('/health', (req, res) => res.json({ ok: true, mail: mailReady, users: db.users.length, posts: db.posts.length }));

app.listen(PORT, () => console.log(`Сервер запущен: http://localhost:${PORT} (почта: ${mailReady ? 'настроена' : 'НЕ настроена'})`));

/* ================== ДЕПЛОЙ НА RENDER.COM ==================
   1. github.com → новый репозиторий → загрузите: server.js, package.json, index.html
   2. render.com → New → Web Service → ваш репозиторий
   3. Build Command:  npm install
      Start Command:  node server.js
   4. Environment Variables:
        SERVER_KEY      = придумайте длинную случайную строку
        GMAIL_USER      = daryakimdd@gmail.com
        GMAIL_APP_PASS  = пароль приложения Google (16 символов)
        FROM_NAME       = Навигатор диагноза
        ADMIN_CONTACT   = daryakimdd@gmail.com
   5. Deploy. Сайт откроется по адресу вида https://ваш-проект.onrender.com
      Проверка: https://ваш-проект.onrender.com/health
   ================================================================ */
