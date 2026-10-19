require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

const APPS_SCRIPT_URL = process.env.APPS_SCRIPT_URL;
const APPS_SCRIPT_SECRET = process.env.APPS_SCRIPT_SECRET;

console.log('Config check -> URL set:', !!APPS_SCRIPT_URL, '| SECRET set:', !!APPS_SCRIPT_SECRET);

async function sendToSheet(payload) {
  const res = await fetch(APPS_SCRIPT_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...payload, secret: APPS_SCRIPT_SECRET }),
    redirect: 'follow'
  });
  const text = await res.text();
  console.log('Apps Script response:', res.status, text.slice(0, 300));
  return JSON.parse(text);
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return salt + ':' + hash;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(check, 'hex'));
}

app.get('/', (req, res) => {
  res.json({ ok: true, message: 'AllInOneCrop backend chal raha hai' });
});

app.post('/api/signup', async (req, res) => {
  const { email, name, phone, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ ok: false, error: 'Email aur password zaroori hain' });
  }
  if (password.length < 6) {
    return res.status(400).json({ ok: false, error: 'Password kam se kam 6 characters ka ho' });
  }

  try {
    const result = await sendToSheet({
      type: 'user',
      email,
      name: name || '',
      phone: phone || '',
      passwordHash: hashPassword(password)
    });
    res.json(result);
  } catch (err) {
    console.log('Signup error:', err.message);
    res.status(500).json({ ok: false, error: 'Sheet se connect nahi ho paya' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password, browser, device, tool, pdfCount } = req.body;

  if (!email || !password) {
    return res.status(400).json({ ok: false, error: 'Email aur password zaroori hain' });
  }

  try {
    const user = await sendToSheet({ type: 'getuser', email });
    if (!user.found) {
      return res.status(401).json({ ok: false, error: 'Account nahi mila' });
    }

    let valid = false;
    try {
      valid = verifyPassword(password, user.passwordHash);
    } catch (e) {
      valid = false;
    }
    if (!valid) {
      return res.status(401).json({ ok: false, error: 'Galat password' });
    }

    await sendToSheet({
      type: 'login',
      email,
      browser: browser || '',
      device: device || '',
      ip: req.ip,
      tool: tool || '',
      pdfCount: pdfCount || 0
    });
    res.json({ ok: true, name: user.name });
  } catch (err) {
    console.log('Login error:', err.message);
    res.status(500).json({ ok: false, error: 'Sheet se connect nahi ho paya' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server chal raha hai: http://localhost:${PORT}`);
});