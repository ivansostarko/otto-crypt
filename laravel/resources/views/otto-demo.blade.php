@php($errors = $errors ?? new \Illuminate\Support\MessageBag())
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OTTO Crypt Demo</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; margin: 2rem; }
    .card { border: 1px solid #e5e7eb; border-radius: 12px; padding: 1rem 1.25rem; margin-bottom: 1.5rem; }
    h1 { margin-bottom: .5rem; }
    h2 { margin: 1rem 0 .5rem; }
    label { display:block; margin-top: .5rem; }
    input[type=text], input[type=password], textarea { width: 100%; padding: .5rem; border:1px solid #cbd5e1; border-radius: 8px; }
    input[type=file] { margin-top:.5rem; }
    .row { display:flex; gap:1rem; flex-wrap:wrap; }
    .col { flex:1 1 380px; }
    .btn { background:#111827; color:white; border:none; padding:.6rem 1rem; border-radius:10px; cursor:pointer; }
    .btn.secondary { background:#4b5563; }
    .muted { color:#6b7280; font-size:.9rem; }
    .radio-row { display:flex; gap:1rem; align-items:center; margin:.25rem 0 .25rem; }
    .error { color:#b91c1c; margin-top:.5rem; }
    pre { background:#0b1020; color:#e5e7eb; padding: .75rem 1rem; border-radius:10px; overflow:auto; }
    .tabs { display:flex; gap:.5rem; margin-bottom:1rem; }
    .tab { padding:.5rem .75rem; border-radius:999px; border:1px solid #e5e7eb; cursor:pointer; }
    .tab.active { background:#111827; color:white; }
    .hint { font-size:.85rem; color:#374151; }
  </style>
  <script>
    function onModeChange(scope){
      const which = document.querySelector(`#${scope} input[name="mode"]:checked`).value;
      ['password','x25519','raw'].forEach(m=>{
        document.querySelectorAll(`#${scope} .mode-`+m).forEach(el=>{
          el.style.display = (m===which)? 'block':'none';
        });
      });
    }
    function init(){
      ['text','file','decfile','dectext'].forEach(onModeChange);
    }
    window.addEventListener('DOMContentLoaded', init);
  </script>
</head>
<body>
  <h1>OTTO Crypt Demo</h1>
  <p class="muted">Encrypt/decrypt text and large files (photos, documents, audio, video) using OTTO-256-GCM-HKDF-SIV.</p>

  @if($errors->any())
    <div class="card" style="border-color:#fecaca; background:#fff1f2">
      <strong>Errors:</strong>
      <ul>
        @foreach($errors->all() as $err)
          <li>{{ $err }}</li>
        @endforeach
      </ul>
    </div>
  @endif

  <div class="row">
    <div class="col">
      <div class="card">
        <h2>Text — Encrypt</h2>
        <form id="text" method="POST" action="{{ route('otto.text.encrypt') }}">
          @csrf
          <label>Plaintext</label>
          <textarea name="plaintext" rows="5" placeholder="Type something..." required>{{ old('plaintext') }}</textarea>

          <div class="radio-row" style="margin-top:.75rem">
            <label><input type="radio" name="mode" value="password" checked onchange="onModeChange('text')"> Password</label>
            <label><input type="radio" name="mode" value="x25519" onchange="onModeChange('text')"> X25519 (recipient public)</label>
            <label><input type="radio" name="mode" value="raw" onchange="onModeChange('text')"> Raw 32-byte key</label>
          </div>

          <div class="mode-password">
            <label>Password</label>
            <input type="password" name="password" placeholder="Strong password">
          </div>
          <div class="mode-x25519" style="display:none">
            <label>Recipient public key (base64/hex)</label>
            <input type="text" name="recipient_public" placeholder="Recipient X25519 public key">
          </div>
          <div class="mode-raw" style="display:none">
            <label>Raw key (32 bytes; base64/hex/raw)</label>
            <input type="text" name="raw_key" placeholder="32-byte key">
          </div>

          <div style="margin-top:.75rem"><button class="btn" type="submit">Encrypt</button></div>
        </form>

        @if(session('text_cipher_b64'))
          <label style="margin-top:1rem">Ciphertext+Tag (base64)</label>
          <pre>{{ session('text_cipher_b64') }}</pre>
          <label>Header (base64)</label>
          <pre>{{ session('text_header_b64') }}</pre>
        @endif
      </div>
    </div>

    <div class="col">
      <div class="card">
        <h2>Text — Decrypt</h2>
        <form id="dectext" method="POST" action="{{ route('otto.text.decrypt') }}">
          @csrf
          <label>Ciphertext+Tag (base64)</label>
          <textarea name="cipher_b64" rows="3" placeholder="Paste base64 here..." required>{{ old('cipher_b64') }}</textarea>
          <label>Header (base64)</label>
          <textarea name="header_b64" rows="3" placeholder="Paste base64 here..." required>{{ old('header_b64') }}</textarea>

          <div class="radio-row" style="margin-top:.75rem">
            <label><input type="radio" name="mode" value="password" checked onchange="onModeChange('dectext')"> Password</label>
            <label><input type="radio" name="mode" value="x25519" onchange="onModeChange('dectext')"> X25519 (sender secret)</label>
            <label><input type="radio" name="mode" value="raw" onchange="onModeChange('dectext')"> Raw 32-byte key</label>
          </div>

          <div class="mode-password">
            <label>Password</label>
            <input type="password" name="password" placeholder="Password used for encryption">
          </div>
          <div class="mode-x25519" style="display:none">
            <label>Sender secret key (base64/hex)</label>
            <input type="text" name="sender_secret" placeholder="Your X25519 secret key">
          </div>
          <div class="mode-raw" style="display:none">
            <label>Raw key (32 bytes; base64/hex/raw)</label>
            <input type="text" name="raw_key" placeholder="32-byte key">
          </div>

          <div style="margin-top:.75rem"><button class="btn" type="submit">Decrypt</button></div>
        </form>

        @if(session('text_plain_dec'))
          <label style="margin-top:1rem">Plaintext (decrypted)</label>
          <pre>{{ session('text_plain_dec') }}</pre>
        @endif
      </div>
    </div>
  </div>

  <div class="card">
    <h2>Files — Photos / Documents / Audio / Video</h2>
    <div class="row">
      <div class="col">
        <form id="file" method="POST" action="{{ route('otto.file.encrypt') }}" enctype="multipart/form-data">
          @csrf
          <label>Select a file</label>
          <input type="file" name="file" accept="image/*,audio/*,video/*,application/pdf,application/octet-stream" required>

          <div class="radio-row" style="margin-top:.75rem">
            <label><input type="radio" name="mode" value="password" checked onchange="onModeChange('file')"> Password</label>
            <label><input type="radio" name="mode" value="x25519" onchange="onModeChange('file')"> X25519 (recipient public)</label>
            <label><input type="radio" name="mode" value="raw" onchange="onModeChange('file')"> Raw 32-byte key</label>
          </div>

          <div class="mode-password">
            <label>Password</label>
            <input type="password" name="password" placeholder="Strong password">
          </div>
          <div class="mode-x25519" style="display:none">
            <label>Recipient public key (base64/hex)</label>
            <input type="text" name="recipient_public" placeholder="Recipient X25519 public key">
          </div>
          <div class="mode-raw" style="display:none">
            <label>Raw key (32 bytes; base64/hex/raw)</label>
            <input type="text" name="raw_key" placeholder="32-byte key">
          </div>

          <div style="margin-top:.75rem"><button class="btn" type="submit">Encrypt & Download .otto</button></div>
          <p class="hint">The download will start automatically. Chunks are encrypted with deterministic HKDF-derived nonces.</p>
        </form>
      </div>

      <div class="col">
        <form id="decfile" method="POST" action="{{ route('otto.file.decrypt') }}" enctype="multipart/form-data">
          @csrf
          <label>Select an encrypted .otto file</label>
          <input type="file" name="encfile" accept=".otto,application/octet-stream" required>

          <div class="radio-row" style="margin-top:.75rem">
            <label><input type="radio" name="mode" value="password" checked onchange="onModeChange('decfile')"> Password</label>
            <label><input type="radio" name="mode" value="x25519" onchange="onModeChange('decfile')"> X25519 (sender secret)</label>
            <label><input type="radio" name="mode" value="raw" onchange="onModeChange('decfile')"> Raw 32-byte key</label>
          </div>

          <div class="mode-password">
            <label>Password</label>
            <input type="password" name="password" placeholder="Password used for encryption">
          </div>
          <div class="mode-x25519" style="display:none">
            <label>Sender secret key (base64/hex)</label>
            <input type="text" name="sender_secret" placeholder="Your X25519 secret key">
          </div>
          <div class="mode-raw" style="display:none">
            <label>Raw key (32 bytes; base64/hex/raw)</label>
            <input type="text" name="raw_key" placeholder="32-byte key">
          </div>

          <div style="margin-top:.75rem"><button class="btn secondary" type="submit">Decrypt & Download</button></div>
          <p class="hint">The decrypted file will download with a <code>.dec</code> suffix.</p>
        </form>
      </div>
    </div>

    @if(session('file_error'))
      <div class="error">{{ session('file_error') }}</div>
    @endif
  </div>

  <p class="muted">Demo powered by <strong>OTTO Crypt</strong>. See the package README for format and security notes.</p>
</body>
</html>
