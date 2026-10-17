require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

const APPS_SCRIPT_URL = process.env.APPS_SCRIPT_URL;
const APPS_SCRIPT_SECRET = process.env.APPS_SCRIPT_SECRET;

// Google Sheet mein data bhejne ka helper
async function sendToSheet(payload) {
  const res = await fetch(APPS_SCRIPT_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...payload, secret: APPS_SCRIPT_SECRET })
  });
  return res.json();
}

// Password ko hash karna (plain text kabhi save nahi hoga)
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return salt + ':' + hash;
}

// Check ki server chal raha hai
app.get('/', (req, res) => {
  res.json({ ok: true, message: 'AllInOneCrop backend chal raha hai' });
});

// Signup: user ko Users sheet mein save karna
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
    res.status(500).json({ ok: false, error: 'Sheet se connect nahi ho paya' });
  }
});

// Login: login ka record Logins sheet mein save karna
app.post('/api/login', async (req, res) => {
  const { email, browser, device, tool, pdfCount } = req.body;

  if (!email) {
    return res.status(400).json({ ok: false, error: 'Email zaroori hai' });
  }

  try {
    const result = await sendToSheet({
      type: 'login',
      email,
      browser: browser || '',
      device: device || '',
      ip: req.ip,
      tool: tool || '',
      pdfCount: pdfCount || 0
    });
    res.json(result);
  } catch (err) {
    res.status(500).json({ ok: false, error: 'Sheet se connect nahi ho paya' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server chal raha hai: http://localhost:${PORT}`);
});
console.log('Server file updated');
