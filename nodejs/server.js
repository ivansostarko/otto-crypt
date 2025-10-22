'use strict';

const express = require('express');
const multer  = require('multer');
const fs = require('fs');
const path = require('path');

// Import from local package path or installed module
let OttoCrypt, KeyExchange;
try {
  ({ OttoCrypt, KeyExchange } = require('otto-crypt-js'));
} catch (e) {
  // fallback to local sibling path if running monorepo-style
  ({ OttoCrypt, KeyExchange } = require('../otto-crypt-js/src'));
}

const app = express();
const upload = multer({ dest: path.join(__dirname, 'uploads') });

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({extended:true}));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.render('index', {
    textResult: null,
    textError: null
  });
});

app.post('/text/encrypt', async (req, res) => {
  const { plaintext, mode, password, recipient_public, raw_key } = req.body;
  const otto = new OttoCrypt();
  try {
    const options = parseOptions({ mode, password, recipient_public, raw_key }, 'encrypt');
    const { cipher, header } = await otto.encryptString(Buffer.from(plaintext || '', 'utf8'), options);
    res.render('index', {
      textResult: {
        action: 'encrypt',
        cipher_b64: cipher.toString('base64'),
        header_b64: header.toString('base64')
      },
      textError: null
    });
  } catch (e) {
    res.render('index', { textResult: null, textError: 'Encrypt error: ' + e.message });
  }
});

app.post('/text/decrypt', async (req, res) => {
  const { cipher_b64, header_b64, mode, password, sender_secret, raw_key } = req.body;
  const otto = new OttoCrypt();
  try {
    const options = parseOptions({ mode, password, sender_secret, raw_key }, 'decrypt');
    const plain = await otto.decryptString(Buffer.from(cipher_b64, 'base64'), Buffer.from(header_b64, 'base64'), options);
    res.render('index', {
      textResult: {
        action: 'decrypt',
        plaintext: plain.toString('utf8')
      },
      textError: null
    });
  } catch (e) {
    res.render('index', { textResult: null, textError: 'Decrypt error: ' + e.message });
  }
});

app.post('/file/encrypt', upload.single('file'), async (req, res) => {
  const file = req.file;
  if (!file) return res.status(400).send('No file uploaded');
  const { mode, password, recipient_public, raw_key } = req.body;
  const otto = new OttoCrypt();
  const outName = file.originalname + '.otto';
  const outPath = path.join(__dirname, 'tmp', outName);
  fs.mkdirSync(path.dirname(outPath), { recursive: true });

  try {
    const options = parseOptions({ mode, password, recipient_public, raw_key }, 'encrypt');
    await otto.encryptFile(file.path, outPath, options);
    res.download(outPath, outName, (err) => {
      cleanup([file.path, outPath]);
      if (err) console.error('Download error:', err);
    });
  } catch (e) {
    cleanup([file.path, outPath]);
    res.status(500).send('File encrypt error: ' + e.message);
  }
});

app.post('/file/decrypt', upload.single('encfile'), async (req, res) => {
  const file = req.file;
  if (!file) return res.status(400).send('No file uploaded');
  const { mode, password, sender_secret, raw_key } = req.body;
  const otto = new OttoCrypt();
  const base = file.originalname.replace(/\.otto$/i, '') || file.originalname;
  const outName = base + '.dec';
  const outPath = path.join(__dirname, 'tmp', outName);
  fs.mkdirSync(path.dirname(outPath), { recursive: true });

  try {
    const options = parseOptions({ mode, password, sender_secret, raw_key }, 'decrypt');
    await otto.decryptFile(file.path, outPath, options);
    res.download(outPath, outName, (err) => {
      cleanup([file.path, outPath]);
      if (err) console.error('Download error:', err);
    });
  } catch (e) {
    cleanup([file.path, outPath]);
    res.status(500).send('File decrypt error: ' + e.message);
  }
});

app.get('/keys', async (req, res) => {
  try {
    const kp = await KeyExchange.generateKeypair();
    res.json({
      secret_base64: kp.secret.toString('base64'),
      public_base64: kp.public.toString('base64'),
      note: "Store secret securely; share public key with senders."
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

function parseOptions(inputs, mode) {
  const which = inputs.mode || 'password';
  if (which === 'password') {
    if (!inputs.password) throw new Error('Password required');
    return { password: inputs.password };
  }
  if (which === 'x25519') {
    if (mode === 'encrypt') {
      if (!inputs.recipient_public) throw new Error('Recipient public key required');
      return { recipient_public: inputs.recipient_public };
    } else {
      if (!inputs.sender_secret) throw new Error('Sender secret key required');
      return { sender_secret: inputs.sender_secret };
    }
  }
  if (which === 'raw') {
    if (!inputs.raw_key) throw new Error('Raw key required');
    return { raw_key: inputs.raw_key };
  }
  throw new Error('Unknown mode');
}

function cleanup(paths) {
  for (const p of paths) {
    try { fs.unlinkSync(p); } catch {}
  }
}

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`OTTO Crypt demo listening on http://localhost:${PORT}`);
});
