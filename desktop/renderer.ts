// ═══════════════════════════════════════════════════════
// AthenaPass — popup.ts
// ═══════════════════════════════════════════════════════

// ── App name config ─────────────────────────────────────
// Cambia estas dos variables para renombrar la app en toda la UI
const APP_NAME_PRIMARY = 'Athena';
const APP_NAME_ACCENT  = 'Pass';

const APP_NAME_HTML = `${APP_NAME_PRIMARY}<span class="app-accent">${APP_NAME_ACCENT}</span>`;

(document.getElementById('logoText') as HTMLElement).innerHTML = APP_NAME_HTML;
(document.getElementById('appTitle') as HTMLElement).innerHTML = APP_NAME_HTML;

// ── Config ──────────────────────────────────────────────

// theme helper
function applyStoredTheme() {
  const theme = localStorage.getItem('theme');
  if (theme === 'light') document.documentElement.classList.add('light-mode');
}
function updateThemeButton() {
  const btn = document.getElementById('themeToggleBtn') as HTMLButtonElement;
  if (!btn) return;
  btn.textContent = document.documentElement.classList.contains('light-mode') ? 'Light' : 'Dark';
}

function toggleTheme() {
  const isLight = document.documentElement.classList.toggle('light-mode');
  localStorage.setItem('theme', isLight ? 'light' : 'dark');
  updateThemeButton();
}

// apply stored value on load
applyStoredTheme();
updateThemeButton();

// server running in Docker on port 4134
// NOTE: the backend is served over HTTPS. If you use a self‑signed or
// otherwise untrusted certificate the fetch() calls will still fail with
// a NetworkError unless the certificate is explicitly trusted by the
// browser (or you launch the browser with appropriate insecure flags).
const SERVER_BASE        = 'http://127.0.0.1:4134';
const API_ENDPOINT       = `${SERVER_BASE}/passwords`;
const EMAIL_STORAGE_KEY  = 'AthenaPass_email';

// authentication state (populated during login)
let authToken: string | null = null;
let savedUserEmail: string = '';  // decrypted email shown on lock screen

// key used to encrypt/decrypt password entries; derived from username+master password
let encryptionKey: CryptoKey | null = null;

// generate a random identifier for a password entry
function randomId(): string {
  const arr = new Uint8Array(12);
  crypto.getRandomValues(arr);
  return bytesToHex(arr);
}


// ── Types ───────────────────────────────────────────────
interface Password {
  id: string;
  name: string;
  password: string;
  tag?: string;
}

// ── SRP helpers (simplified; matches Python `srp` defaults) ──
// prime and generator taken from NG_2048, SHA-1 hashing
const SRP_N_HEX = `AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4
A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60
95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF
747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907
8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861
60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB
FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73`.replace(/\s+/g,'');
const SRP_g: bigint = 2n;

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2) hex = '0' + hex;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}
function bytesToHex(buf: ArrayBuffer | Uint8Array): string {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf as ArrayBuffer);
  return Array.from(b).map(x => x.toString(16).padStart(2,'0')).join('');
}
function concatBuffers(...bufs: ArrayBuffer[]): ArrayBuffer {
  const total = bufs.reduce((sum, b) => sum + b.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  bufs.forEach(b => {
    out.set(new Uint8Array(b), offset);
    offset += b.byteLength;
  });
  return out.buffer;
}

async function srpSha1(...data: ArrayBufferLike[]): Promise<string> {
  // normalize to ArrayBuffer
  const buffers = data.map(d => {
    if (d instanceof ArrayBuffer) return d;
    // Uint8Array, SharedArrayBuffer, etc.
    return (d as ArrayBufferLike) as ArrayBuffer;
  });
  const buf = concatBuffers(...buffers);
  const hash = await crypto.subtle.digest('SHA-1', buf);
  return bytesToHex(hash);
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result: bigint = 1n;
  base = base % mod;
  while (exp > 0n) {
    if ((exp & 1n) === 1n) result = (result * base) % mod;
    exp = exp >> 1n;
    base = (base * base) % mod;
  }
  return result;
}

function randomSalt(length = 4): string {
  const arr = new Uint8Array(length);
  crypto.getRandomValues(arr);
  return bytesToHex(arr);
}

// ── SRP session helpers ─────────────────────────────────
function generateEphemeral(): { secret: string; public: string } {
  // create a random 20‑byte secret ('a') and compute A = g^a mod N
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  const a = BigInt('0x' + bytesToHex(bytes));
  const N = BigInt('0x' + SRP_N_HEX);
  const A = modPow(SRP_g, a, N);
  return { secret: a.toString(16), public: A.toString(16) };
}

async function deriveSession(
  clientSecretHex: string,
  serverPubHex: string,
  saltHex: string,
  username: string,
  password: string
): Promise<{ key: string; proof: string }> {
  const N = BigInt('0x' + SRP_N_HEX);
  const g = SRP_g;

  const a = BigInt('0x' + clientSecretHex);
  const B = BigInt('0x' + serverPubHex);
  const xHex = await derivePrivateKey(username, password, saltHex);
  const x = BigInt('0x' + xHex);

  // verify B is not 0 mod N
  if (B % N === 0n) {
    throw new Error('Invalid server ephemeral');
  }

  // compute u = H(A, B)
  const A = modPow(g, a, N);
  const uHex = await srpSha1(
    hexToBytes(A.toString(16)).buffer,
    hexToBytes(B.toString(16)).buffer
  );
  const u = BigInt('0x' + uHex);

  // k = H(N, g)
  const kHex = await srpSha1(
    hexToBytes(SRP_N_HEX).buffer,
    hexToBytes(g.toString(16)).buffer
  );
  const k = BigInt('0x' + kHex);

  // S = (B - k * g^x) ^ (a + u * x) mod N
  // handle modular subtraction correctly
  const gx = modPow(g, x, N);
  let base = B - (k * gx) % N;
  while (base < 0n) base += N;
  base = base % N;
  const exp = a + u * x;
  const S = modPow(base, exp, N);

  const Khex = await srpSha1(hexToBytes(S.toString(16)).buffer);

  // compute M = H(H(N) xor H(g), H(username), salt, A, B, K)
  const hNhex = await srpSha1(hexToBytes(SRP_N_HEX).buffer);
  const hghex = await srpSha1(hexToBytes(g.toString(16)).buffer);
  const hNbytes = hexToBytes(hNhex);
  const hgbytes = hexToBytes(hghex);
  const hNxorg = new Uint8Array(hNbytes.length);
  for (let i = 0; i < hNxorg.length; i++) {
    hNxorg[i] = hNbytes[i] ^ hgbytes[i];
  }
  const hUhex = await srpSha1(new TextEncoder().encode(username).buffer);

  const Mhex = await srpSha1(
    hNxorg.buffer,
    hexToBytes(hUhex).buffer,
    hexToBytes(saltHex).buffer,
    hexToBytes(A.toString(16)).buffer,
    hexToBytes(B.toString(16)).buffer,
    hexToBytes(Khex).buffer
  );

  return { key: Khex, proof: Mhex };
}

async function verifySession(
  clientPubHex: string,
  clientSession: { key: string; proof: string },
  serverProofHex: string
): Promise<void> {
  const expected = await srpSha1(
    hexToBytes(clientPubHex).buffer,
    hexToBytes(clientSession.proof).buffer,
    hexToBytes(clientSession.key).buffer
  );
  if (expected !== serverProofHex) {
    throw new Error('Server provided session proof is invalid');
  }
}

// Private key derivation used both for verifier creation and login
async function derivePrivateKey(username: string, password: string, saltHex: string): Promise<string> {
  // salt comes as hex string from server or from registration
  const saltBuf = hexToBytes(saltHex);
  const userpass = new TextEncoder().encode(`${username}:${password}`);
  const inner = await srpSha1(userpass.buffer);
  // x = H(s || H(username:password))
  const innerBuf = hexToBytes(inner);
  const xHex = await srpSha1(saltBuf.buffer, innerBuf.buffer);
  return xHex;
}

async function deriveVerifier(username: string, password: string, saltHex: string): Promise<string> {
  const xHex = await derivePrivateKey(username, password, saltHex);
  const x = BigInt('0x' + xHex);
  const N = BigInt('0x' + SRP_N_HEX);
  const v = modPow(SRP_g, x, N);
  return v.toString(16);
}

// derive a CryptoKey for AES-GCM encryption from username/password/salt
async function deriveMasterKey(username: string, password: string, saltHex: string): Promise<CryptoKey> {
  const xHex = await derivePrivateKey(username, password, saltHex);
  // convert xHex (SHA-1 output) to raw bytes
  const raw = hexToBytes(xHex).buffer;
  const baseKey = await crypto.subtle.importKey(
    'raw', raw as ArrayBuffer,
    { name: 'PBKDF2' }, false,
    ['deriveKey']
  );
  // use a fixed additional salt so key derivation is deterministic
  const derived = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: new TextEncoder().encode('AthenaPassEntrySalt'), iterations: 100_000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt','decrypt']
  );
  return derived;
}


// encrypt/decrypt helper for entry blobs
async function encryptBlob(plaintext: string): Promise<string> {
  if (!encryptionKey) throw new Error('no encryption key');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder().encode(plaintext);
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, encryptionKey, enc);
  const toB64 = (buf: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  return `${toB64(iv.buffer)}:${toB64(cipher)}`;
}

async function decryptBlob(data: string): Promise<string> {
  if (!encryptionKey) throw new Error('no encryption key');
  const [ivB64, ctB64] = data.split(':');
  const fromB64 = (s: string) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const iv = fromB64(ivB64);
  const ct = fromB64(ctB64);
  const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, encryptionKey, ct);
  return new TextDecoder().decode(plainBuf);
}

async function registerUser(username: string, password: string) {
  const salt = randomSalt(4); // 4 bytes to mirror Python default
  const vkey = await deriveVerifier(username, password, salt);
  const res = await fetch(`${SERVER_BASE}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, salt, vkey })
  });
  return res.json();
}

// Perform SRP login flow and return bearer token and salt used for key derivation
async function authenticateUser(password: string): Promise<{token: string; salt: string}> {
  console.log('Starting authentication for user:', savedUserEmail);
  if (!savedUserEmail) throw new Error('no username available');
  const username = savedUserEmail;

  // step 1: generate client ephemeral and send A to server
  const { secret: aHex, public: Ahex } = generateEphemeral();
  const startRes = await fetch(`${SERVER_BASE}/auth/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, A: Ahex })
  });
  const startData = await startRes.json();
  const salt = startData.salt;
  const B = startData.B;
  console.log('Authentication start response:', startData);
  // derive session proof
  const clientSession = await deriveSession(aHex, B, salt, username, password);
  const proof = clientSession.proof;
  
  // send proof and receive HAMK + token
  const finishRes = await fetch(`${SERVER_BASE}/auth/finish`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, M: proof })
  });
  console.log('Derived client session proof:', proof);
  const finishData = await finishRes.json();
  console.log('Authentication response:', finishData);
  const HAMK = finishData.HAMK;
  const token = finishData.token;

  // verify server proof
  await verifySession(Ahex, clientSession, HAMK);
  if (!token) throw new Error('no token from server');
  // return both token and the salt received earlier (startData.salt)
  return { token, salt };
}


// ── State ───────────────────────────────────────────────
let passwords: Password[]  = [];
let previousScreen: string = 'screen-main';
let currentEditIndex: number | null = null;  // track which password we're editing

// ═══════════════════════════════════════════════════════
// EMAIL ENCRYPTION
// El email se cifra con AES-GCM usando una clave derivada
// del origen de la extensión mediante Web Crypto API.
// No es un secreto perfecto (la clave vive en memoria),
// pero evita que el email quede en plano en localStorage
// y es lo más seguro posible sin un backend de auth.
// ═══════════════════════════════════════════════════════

// Derivamos una clave AES-GCM a partir de un string fijo
// del dominio/origen. Puedes cambiar CRYPTO_SALT por cualquier
// string único de tu app.
const CRYPTO_SALT = 'AthenaPass-local-salt-v1';

async function getCryptoKey(): Promise<CryptoKey> {
  const encoder   = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', encoder.encode(CRYPTO_SALT),
    { name: 'PBKDF2' }, false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: encoder.encode('AthenaPass'), iterations: 100_000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptEmail(email: string): Promise<string> {
  const key     = await getCryptoKey();
  const iv      = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(email);
  const cipher  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
  // Guardamos iv + ciphertext como base64 separados por ":"
  const toB64   = (buf: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  return `${toB64(iv.buffer)}:${toB64(cipher)}`;
}

async function decryptEmail(stored: string): Promise<string> {
  try {
    const key          = await getCryptoKey();
    const [ivB64, ctB64] = stored.split(':');
    const fromB64      = (s: string) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
    const plain        = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(ivB64) },
      key,
      fromB64(ctB64)
    );
    return new TextDecoder().decode(plain);
  } catch {
    return '';
  }
}

async function getSavedEmail(): Promise<string> {
  const stored = localStorage.getItem(EMAIL_STORAGE_KEY);
  if (!stored) return '';
  return decryptEmail(stored);
}

async function saveEmail(email: string): Promise<void> {
  const encrypted = await encryptEmail(email);
  localStorage.setItem(EMAIL_STORAGE_KEY, encrypted);
}

function clearEmail(): void {
  localStorage.removeItem(EMAIL_STORAGE_KEY);
}

// ═══════════════════════════════════════════════════════
// LOCK SCREEN INIT
// ═══════════════════════════════════════════════════════
async function initLockScreen(): Promise<void> {
  const saved = await getSavedEmail();
  savedUserEmail = saved;
  if (saved) {
    (document.getElementById('lockUserEmail') as HTMLElement).textContent = saved;
    (document.getElementById('lockFormMain')  as HTMLElement).style.display = 'flex';
    (document.getElementById('lockFormSetup') as HTMLElement).style.display = 'none';
  } else {
    (document.getElementById('lockFormMain')  as HTMLElement).style.display = 'none';
    (document.getElementById('lockFormSetup') as HTMLElement).style.display = 'flex';
  }
}
initLockScreen();

// ── Botón "change" email ─────────────────────────────
document.getElementById('lockChangeUser')!.addEventListener('click', () => {
  authToken = null;
  encryptionKey = null;
  savedUserEmail = '';
  clearEmail();
  (document.getElementById('setupEmail')    as HTMLInputElement).value = '';
  (document.getElementById('setupPassword') as HTMLInputElement).value = '';
  (document.getElementById('lockFormMain')  as HTMLElement).style.display = 'none';
  (document.getElementById('lockFormSetup') as HTMLElement).style.display = 'flex';
  (document.getElementById('setupEmail') as HTMLInputElement).focus();
});

// ── Setup: primera vez ────────────────────────────────
document.getElementById('setupBtn')!.addEventListener('click', async () => {
  const email = (document.getElementById('setupEmail') as HTMLInputElement).value.trim();
  const password = (document.getElementById('setupPassword') as HTMLInputElement).value;
  
  if (!email) { 
    (document.getElementById('setupEmail') as HTMLInputElement).focus(); 
    return; 
  }
  if (!password) {
    (document.getElementById('setupPassword') as HTMLInputElement).focus();
    alert('Please enter a password');
    return;
  }
  
  // Save email
  await saveEmail(email);
  savedUserEmail = email;
  
  // Now authenticate with SRP to get token
  const hint = document.querySelector('.lock-hint') as HTMLElement;
  if (hint) hint.textContent = 'Authenticating…';
  
  try {
    const result = await authenticateUser(password);
    authToken = result.token;
    encryptionKey = await deriveMasterKey(savedUserEmail, password, result.salt);
    console.log('Setup: Token obtained:', authToken, 'key derived');
    if (hint) hint.textContent = '';
    unlockApp();
  } catch (err) {
    console.error('Setup authentication failed:', err);
    if (hint) hint.textContent = 'Authentication failed';
    alert('Login failed. Please check your credentials.');
  }
});
(document.getElementById('setupPassword') as HTMLInputElement)
  .addEventListener('keydown', (e: KeyboardEvent) => {
    if (e.key === 'Enter') (document.getElementById('setupBtn') as HTMLButtonElement).click();
  });

// ── Create account / signup screen ─────────────────────
const btnCreate = document.getElementById('btnCreateUser') as HTMLButtonElement;
const lockFormMain = document.getElementById('lockFormMain') as HTMLElement;
const lockFormSetupEl = document.getElementById('lockFormSetup') as HTMLElement;
const lockFormSignup = document.getElementById('lockFormSignup') as HTMLElement;

btnCreate.addEventListener('click', () => {
  // show signup form
  lockFormMain.style.display = 'none';
  lockFormSetupEl.style.display = 'none';
  lockFormSignup.style.display = 'flex';
});

// signup submit logic
const signupErrorEl = document.getElementById('signupError') as HTMLElement;
document.getElementById('signupSubmit')!.addEventListener('click', async () => {
  signupErrorEl.textContent = '';
  const user = (document.getElementById('signupUser') as HTMLInputElement).value.trim();
  const pw   = (document.getElementById('signupPassword') as HTMLInputElement).value;
  const pwc  = (document.getElementById('signupPasswordConfirm') as HTMLInputElement).value;
  if (!user) { (document.getElementById('signupUser') as HTMLInputElement).focus(); return; }
  if (pw !== pwc) {
    signupErrorEl.textContent = 'Passwords do not match';
    return;
  }

  // perform SRP-style registration
  signupErrorEl.textContent = 'Registering...';
  try {
    const result = await registerUser(user, pw);
    if (result && result.status === 'ok') {
      alert('Account created successfully');
      lockFormSignup.style.display = 'none';
      lockFormSetupEl.style.display = 'flex';
    } else if (result && result.error) {
      signupErrorEl.textContent = result.error;
    } else {
      signupErrorEl.textContent = 'Unexpected response from server';
      console.error('register response', result);
    }
  } catch (err) {
    console.error('registration failed', err);
    signupErrorEl.textContent = 'Network error';
  }
});
// clear error as user types
['signupPassword','signupPasswordConfirm'].forEach(id => {
  (document.getElementById(id) as HTMLInputElement).addEventListener('input', () => {
    signupErrorEl.textContent = '';
  });
});

// back button on signup form
(document.getElementById('signupBackBtn') as HTMLButtonElement).addEventListener('click', () => {
  lockFormSignup.style.display = 'none';
  initLockScreen();
});

// eye toggles for signup fields
(document.getElementById('signupEye') as HTMLButtonElement).addEventListener('click', () => {
  const inp = document.getElementById('signupPassword') as HTMLInputElement;
  inp.type = inp.type === 'password' ? 'text' : 'password';
});
(document.getElementById('signupEyeConfirm') as HTMLButtonElement).addEventListener('click', () => {
  const inp = document.getElementById('signupPasswordConfirm') as HTMLInputElement;
  inp.type = inp.type === 'password' ? 'text' : 'password';
});

// theme toggle listener (settings tab may not exist until loaded but we attach here)
const themeBtn = document.getElementById('themeToggleBtn');
if (themeBtn) themeBtn.addEventListener('click', toggleTheme);

// logout button
const logoutBtn = document.getElementById('logoutBtn');
if (logoutBtn) {
  logoutBtn.addEventListener('click', () => {
    window.close();
  });
}

// add/edit security check button
const addEditCheckBtn = document.getElementById('addEditCheckBtn');
if (addEditCheckBtn) {
  addEditCheckBtn.addEventListener('click', () => {
    if (addEditPassword.value) {
      openSecurityScreen('Password', addEditPassword.value);
    }
  });
}


// ── Unlock normal ─────────────────────────────────────
document.getElementById('lockBtn')!.addEventListener('click', async () => {
  console.log('Login button clicked');
  const hint = document.querySelector('.lock-hint') as HTMLElement;
  hint.textContent = '';
  const pw = (document.getElementById('lockPassword') as HTMLInputElement).value;
  if (!pw) {
    (document.getElementById('lockPassword') as HTMLInputElement).focus();
    return;
  }
  hint.textContent = 'Authenticating…';
  try {
    const result = await authenticateUser(pw);
    authToken = result.token;
    encryptionKey = await deriveMasterKey(savedUserEmail, pw, result.salt);
    console.log('Token asignado:', authToken);
    hint.textContent = '';
    unlockApp();
  } catch (err) {
    console.error('login failed', err);
    hint.textContent = 'Login failed';
  }
});
(document.getElementById('lockPassword') as HTMLInputElement)
  .addEventListener('keydown', (e: KeyboardEvent) => {
    if (e.key === 'Enter') (document.getElementById('lockBtn') as HTMLButtonElement).click();
  });



// ── Toggle eye ────────────────────────────────────────
function toggleEye(inputId: string, btnId: string): void {
  const btn   = document.getElementById(btnId)   as HTMLButtonElement;
  const input = document.getElementById(inputId) as HTMLInputElement;
  btn.addEventListener('click', () => {
    input.type = input.type === 'password' ? 'text' : 'password';
  });
}
toggleEye('lockPassword', 'lockEye');
toggleEye('setupPassword', 'setupEye');

// ─────────────────────────────────────────────────────
async function unlockApp(): Promise<void> {
  if (!authToken) {
    alert('No auth token, cannot unlock app');
    return;
  }
  showScreen('screen-main');
  await loadPasswords();
}

// ═══════════════════════════════════════════════════════
// SCREEN NAVIGATION
// ═══════════════════════════════════════════════════════
function showScreen(id: string): void {
  document.querySelectorAll<HTMLDivElement>('.screen').forEach(s => s.classList.remove('active'));
  document.getElementById(id)?.classList.add('active');
}

async function openSecurityScreen(pwName: string, pwValue?: string): Promise<void> {
  // remember current active screen so back behaves correctly
  const active = document.querySelector('.screen.active');
  previousScreen = active ? active.id : 'screen-main';
  (document.getElementById('securityPwName') as HTMLElement).textContent = pwName || '—';
  showScreen('screen-security');
  await analyzePassword(pwValue);
}

function openAddEditScreen(mode: 'add' | 'edit', idx?: number): void {
  previousScreen = 'screen-main';
  const titleEl = document.getElementById('addEditTitle') as HTMLElement;
  const nameInput = document.getElementById('addEditName') as HTMLInputElement;
  const tagInput = document.getElementById('addEditTag') as HTMLInputElement;
  const pwInput = document.getElementById('addEditPassword') as HTMLInputElement;

  if (mode === 'add') {
    titleEl.textContent = 'Add password';
    nameInput.value = '';
    tagInput.value = '';
    pwInput.value = '';
    currentEditIndex = null;
  } else if (mode === 'edit' && idx !== undefined) {
    titleEl.textContent = 'Edit password';
    nameInput.value = passwords[idx].name;
    tagInput.value = passwords[idx].tag || '';
    pwInput.value = passwords[idx].password;
    currentEditIndex = idx;
  }
  
  // Reset password field to hidden
  pwInput.type = 'password';
  // clear live check icon
  const icon = document.getElementById('addEditCheckIcon');
  if (icon) icon.textContent = '—';
  // if editing existing and password present, run quick live check
  if (pwInput.value) {
    liveCheckAddEditPassword();
  }

  showScreen('screen-addedit');
}

document.getElementById('backBtn')!.addEventListener('click', () => showScreen(previousScreen));
document.getElementById('addEditBackBtn')!.addEventListener('click', () => showScreen(previousScreen));

document.getElementById('addEditCancelBtn')!.addEventListener('click', () => showScreen(previousScreen));

document.getElementById('addEditSaveBtn')!.addEventListener('click', async () => {
  const name = (document.getElementById('addEditName') as HTMLInputElement).value.trim();
  const tag = (document.getElementById('addEditTag') as HTMLInputElement).value.trim();
  const pw = (document.getElementById('addEditPassword') as HTMLInputElement).value;

  if (!name || !pw) {
    alert('Please fill in name and password');
    return;
  }

  const btn = document.getElementById('addEditSaveBtn') as HTMLButtonElement;
  const originalText = btn.textContent;
  btn.textContent = 'Saving…';
  btn.disabled = true;

  try {
    // build plaintext entry
    const entry = { name, password: pw, tag: tag || undefined };
    const encBlob = await encryptBlob(JSON.stringify(entry));

    if (currentEditIndex !== null) {
      // Edit existing: use stored id
      const originalId = passwords[currentEditIndex].id;
      const success = await updatePassword(originalId, encBlob);
      if (!success) {
        alert('Failed to update password on server');
        return;
      }
      passwords[currentEditIndex] = { id: originalId, name, password: pw, tag: tag || undefined };
    } else {
      // Add new
      const newId = randomId();
      const success = await addPassword(newId, encBlob);
      if (!success) {
        alert('Failed to add password to server');
        return;
      }
      passwords.push({ id: newId, name, password: pw, tag: tag || undefined });
    }

    showScreen(previousScreen);
    renderPasswordList(passwords);
    updateTagFilter();
  } finally {
    btn.textContent = originalText;
    btn.disabled = false;
  }
});

// ═══════════════════════════════════════════════════════
// PASSWORD API OPERATIONS
// ═══════════════════════════════════════════════════════

async function loadPasswords(): Promise<void> {
  const dot     = document.getElementById('statusDot')  as HTMLElement;
  const statusT = document.getElementById('statusText') as HTMLElement;

  dot.classList.add('loading');
  statusT.textContent = 'syncing…';

  try {
    console.log('loadPasswords called, authToken =', authToken);
    if (!authToken) {
      throw new Error('no auth token');
    }
    const headers: Record<string,string> = {
      'Authorization': `Bearer ${authToken}`
    };
    const res  = await fetch(API_ENDPOINT, { headers });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    // El servidor retorna un diccionario { id: encrypted_blob, ... }
    const data = await res.json() as Record<string, string>;
    console.log('Raw data from server:', data);
    // Convertir a array de Password descifrando cada blob
    passwords = [];
    for (const [id, blob] of Object.entries(data)) {
      try {
        const plain = await decryptBlob(blob);
        const obj = JSON.parse(plain);
        passwords.push({ id, name: obj.name, password: obj.password, tag: obj.tag });
      } catch (e) {
        console.error('failed to decrypt entry', id, e);
      }
    }
    
    dot.classList.remove('loading');
    dot.style.background = '';
    statusT.textContent  = `${passwords.length} entries`;
  } catch (err) {
    console.error('loadPasswords error:', err);
    dot.classList.remove('loading');
    dot.style.background = 'var(--danger)';
    statusT.textContent  = 'offline';
    passwords = [];
  }
  renderPasswordList(passwords);
  updateTagFilter();
}

async function addPassword(id: string, encryptedValue: string): Promise<boolean> {
  try {
    if (!authToken) {
      throw new Error('no auth token');
    }
    const res = await fetch(API_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${authToken}`
      },
      body: JSON.stringify({ id, value: encryptedValue })
    });
    if (!res.ok) {
      const err = await res.json();
      console.error('addPassword error:', err);
      return false;
    }
    return true;
  } catch (err) {
    console.error('addPassword error:', err);
    return false;
  }
}

async function updatePassword(id: string, encryptedValue: string): Promise<boolean> {
  try {
    if (!authToken) {
      throw new Error('no auth token');
    }
    const res = await fetch(`${API_ENDPOINT}/${id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${authToken}`
      },
      body: JSON.stringify({ value: encryptedValue })
    });
    if (!res.ok) {
      const err = await res.json();
      console.error('updatePassword error:', err);
      return false;
    }
    return true;
  } catch (err) {
    console.error('updatePassword error:', err);
    return false;
  }
}

async function deletePassword(id: string): Promise<boolean> {
  try {
    if (!authToken) {
      throw new Error('no auth token');
    }
    const res = await fetch(`${API_ENDPOINT}/${id}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    if (!res.ok) {
      const err = await res.json();
      console.error('deletePassword error:', err);
      return false;
    }
    return true;
  } catch (err) {
    console.error('deletePassword error:', err);
    return false;
  }
}

// ═══════════════════════════════════════════════════════
// RENDER PASSWORD LIST
// ═══════════════════════════════════════════════════════
function renderPasswordList(list: Password[]): void {
  const container = document.getElementById('pwList') as HTMLDivElement;

  if (list.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">🔍</div>
        <div>No passwords found</div>
      </div>`;
    return;
  }

  container.innerHTML = list.map((pw, idx) => `
    <div class="pw-item" data-idx="${idx}">
      <div class="pw-icon">${pw.name.charAt(0)}</div>
      <div class="pw-info">
        <div class="pw-name">${escHtml(pw.name)}</div>
        <div class="pw-value" data-pw="${escHtml(pw.password)}" data-visible="false">
          ••••••••••••
        </div>
      </div>
      <div class="pw-actions">
        <button class="pw-btn eye-btn"   data-idx="${idx}" title="Show/hide">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
          </svg>
        </button>
        <button class="pw-btn copy-btn"  data-idx="${idx}" title="Copy">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="9" y="9" width="13" height="13" rx="2"/>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
          </svg>
        </button>
        <button class="pw-btn edit-btn"  data-idx="${idx}" title="Edit">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
          </svg>
        </button>
        <button class="pw-btn check-btn" data-idx="${idx}" title="Security check">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="20 6 9 17 4 12"/>
          </svg>
        </button>
        <button class="pw-btn delete-btn" data-idx="${idx}" title="Delete">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/>
          </svg>
        </button>
      </div>
    </div>
  `).join('');

  container.querySelectorAll<HTMLButtonElement>('.eye-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const idx     = parseInt(btn.dataset.idx!);
      const item    = container.querySelectorAll('.pw-item')[idx];
      const valueEl = item.querySelector('.pw-value') as HTMLElement;
      const visible = valueEl.dataset.visible === 'true';
      valueEl.dataset.visible = visible ? 'false' : 'true';
      valueEl.textContent     = visible ? '••••••••••••' : valueEl.dataset.pw!;
    });
  });

  container.querySelectorAll<HTMLButtonElement>('.copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const idx = parseInt(btn.dataset.idx!);
      navigator.clipboard.writeText(passwords[idx].password).then(() => {
        btn.classList.add('copy-success');
        setTimeout(() => btn.classList.remove('copy-success'), 1500);
      });
    });
  });

  container.querySelectorAll<HTMLButtonElement>('.edit-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const idx = parseInt(btn.dataset.idx!);
      openAddEditScreen('edit', idx);
    });
  });

  container.querySelectorAll<HTMLButtonElement>('.check-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const idx = parseInt(btn.dataset.idx!);
      openSecurityScreen(passwords[idx].name, passwords[idx].password);
    });
  });

  container.querySelectorAll<HTMLButtonElement>('.delete-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const idx = parseInt(btn.dataset.idx!);
      const entry = passwords[idx];
      if (!confirm(`Delete "${entry.name}"?`)) {
        return;
      }
      btn.disabled = true;
      const success = await deletePassword(entry.id);
      if (!success) {
        alert('Failed to delete password from server');
        btn.disabled = false;
        return;
      }
      passwords.splice(idx, 1);
      renderPasswordList(passwords);
      updateTagFilter();
    });
  });
}
(document.getElementById('vaultSearch') as HTMLInputElement)
  .addEventListener('input', (e: Event) => {
    const q        = (e.target as HTMLInputElement).value.toLowerCase();
    const tag      = (document.getElementById('vaultTagFilter') as HTMLSelectElement).value;
    const filtered = passwords.filter(p => {
      const matchName = p.name.toLowerCase().includes(q);
      const matchTag = !tag || (p.tag === tag);
      return matchName && matchTag;
    });
    renderPasswordList(filtered);
  });

// ── Vault Tag filter ───────────────────────────────────
(document.getElementById('vaultTagFilter') as HTMLSelectElement)
  .addEventListener('change', (e: Event) => {
    const q   = (document.getElementById('vaultSearch') as HTMLInputElement).value.toLowerCase();
    const tag = (e.target as HTMLSelectElement).value;
    const filtered = passwords.filter(p => {
      const matchName = p.name.toLowerCase().includes(q);
      const matchTag = !tag || (p.tag === tag);
      return matchName && matchTag;
    });
    renderPasswordList(filtered);
  });

document.getElementById('vaultAddBtn')!.addEventListener('click', () => openAddEditScreen('add'));
// Update tag filter options
function updateTagFilter(): void {
  const tagSet = new Set(passwords.map(p => p.tag).filter(Boolean) as string[]);
  const select = document.getElementById('vaultTagFilter') as HTMLSelectElement;
  const currentValue = select.value;
  
  select.innerHTML = '<option value="">All tags</option>';
  Array.from(tagSet).forEach(tag => {
    const opt = document.createElement('option');
    opt.value = tag;
    opt.textContent = tag;
    select.appendChild(opt);
  });
  
  select.value = currentValue;
}

// ═══════════════════════════════════════════════════════
// TABS
// ═══════════════════════════════════════════════════════
document.querySelectorAll<HTMLButtonElement>('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b  => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(`tab-${btn.dataset.tab}`)?.classList.add('active');
  });
});

// ═══════════════════════════════════════════════════════
// GENERATE TAB
// ═══════════════════════════════════════════════════════
const genLen    = document.getElementById('genLen')    as HTMLInputElement;
const genLenVal = document.getElementById('genLenVal') as HTMLElement;
const genOutput = document.getElementById('genOutput') as HTMLInputElement;
const genCheckIcon = document.getElementById('genCheckIcon') as HTMLElement;
const genCheckBtn = document.getElementById('genCheckBtn') as HTMLButtonElement;

genLen.addEventListener('input', () => { genLenVal.textContent = genLen.value; });

// Live analysis on password output changes
let liveAnalysisTimeout: number | undefined;
async function liveCheckPassword() {
  const pw = genOutput.value;
  if (!pw) {
    genCheckIcon.textContent = '—';
    genCheckBtn.dataset.checkStatus = 'unchecked';
    return;
  }
  
  // Run live analysis without full UI update (only icon)
  genCheckIcon.textContent = '...';
  const pwnedCount = await checkPwned(pw);
  
  if (pwnedCount > 0) {
    genCheckIcon.textContent = '✕';
    genCheckIcon.style.color = 'var(--danger)';
    genCheckIcon.style.fontSize = '18px';
    genCheckBtn.dataset.checkStatus = 'failed';
  } else {
    // Quick entropy check
    const hasUpper = /[A-Z]/.test(pw);
    const hasLower = /[a-z]/.test(pw);
    const hasDigit = /[0-9]/.test(pw);
    const hasSym  = /[^A-Za-z0-9]/.test(pw);
    let charset = 0;
    if (hasUpper) charset += 26;
    if (hasLower) charset += 26;
    if (hasDigit) charset += 10;
    if (hasSym)  charset += 32;
    const bits = charset > 0 ? Math.log2(Math.max(1, charset)) * pw.length : 0;
    
    // Score calculation (same as analyzePassword)
    let score = 0;
    const e = Math.max(0, Math.min(80, bits));
    score += Math.round((e / 80) * 40);
    const classesCount = [hasUpper, hasLower, hasDigit, hasSym].filter(Boolean).length;
    score += (classesCount - 1) * 5;
    
    if (score < 30) {
      genCheckIcon.textContent = '✕';
      genCheckIcon.style.color = 'var(--danger)';
      genCheckIcon.style.fontSize = '20px';
      genCheckBtn.dataset.checkStatus = 'failed';
    } else if (score >= 50) {
      genCheckIcon.textContent = '✓';
      genCheckIcon.style.color = 'var(--accent2)';
      genCheckIcon.style.fontSize = '20px';
      genCheckBtn.dataset.checkStatus = 'passed';
    } else {
      genCheckIcon.textContent = '◐';
      genCheckIcon.style.color = 'var(--warn)';
      genCheckIcon.style.fontSize = '20px';
      genCheckBtn.dataset.checkStatus = 'warning';
    }
  }
}

genOutput.addEventListener('input', () => {
  clearTimeout(liveAnalysisTimeout);
  liveAnalysisTimeout = window.setTimeout(liveCheckPassword, 300);
});

(['Upper','Lower','Nums','Syms'] as const).forEach(id => {
  const chk   = document.getElementById(`chk${id}`)   as HTMLInputElement;
  const label = document.getElementById(`label${id}`) as HTMLElement;
  chk.addEventListener('change', () => label.classList.toggle('checked', chk.checked));
});

document.getElementById('genBtn')!.addEventListener('click', () => {
  const len   = parseInt(genLen.value);
  const upper = (document.getElementById('chkUpper') as HTMLInputElement).checked;
  const lower = (document.getElementById('chkLower') as HTMLInputElement).checked;
  const nums  = (document.getElementById('chkNums')  as HTMLInputElement).checked;
  const syms  = (document.getElementById('chkSyms')  as HTMLInputElement).checked;

  let charset = '';
  if (upper) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (lower) charset += 'abcdefghijklmnopqrstuvwxyz';
  if (nums)  charset += '0123456789';
  if (syms)  charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
  if (!charset) return;

  const arr = new Uint32Array(len);
  crypto.getRandomValues(arr);
  genOutput.value = Array.from(arr).map(n => charset[n % charset.length]).join('');
  liveCheckPassword();
});


document.getElementById('genCopyBtn')!.addEventListener('click', () => {
  if (!genOutput.value) return;
  navigator.clipboard.writeText(genOutput.value).then(() => {
    const btn = document.getElementById('genCopyBtn') as HTMLButtonElement;
    btn.classList.add('copy-success');
    setTimeout(() => btn.classList.remove('copy-success'), 1500);
  });
});

document.getElementById('genCheckBtn')!.addEventListener('click', () => {
  if (genOutput.value) {
    openSecurityScreen('Generated', genOutput.value);
  }
});

document.getElementById('genCopyMainBtn')!.addEventListener('click', () => {
  if (!genOutput.value) return;
  navigator.clipboard.writeText(genOutput.value).then(() => {
    const btn = document.getElementById('genCopyMainBtn') as HTMLButtonElement;
    btn.textContent = '✅ Copied!';
    setTimeout(() => btn.textContent = '📋 Copy to clipboard', 1500);
  });
});

// ═══════════════════════════════════════════════════════
// UTIL
// ═══════════════════════════════════════════════════════
function escHtml(str: string): string {
  return str
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;');
}

// ═════════════════════════════════════════════════════════════════════
// Password analysis helpers: HIBP check (k-anonymity), entropy, structural mix
// ═════════════════════════════════════════════════════════════════════

function hexFromBuffer(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sha1Hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-1', data);
  return hexFromBuffer(digest).toUpperCase();
}

async function checkPwned(password: string): Promise<number> {
  try {
    const hash = await sha1Hex(password);
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);
    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    if (!res.ok) return 0;
    const text = await res.text();
    const lines = text.split('\n');
    for (const line of lines) {
      const [suf, count] = line.split(':');
      if (suf && suf.trim().toUpperCase() === suffix) return parseInt((count||'0').trim(), 10);
    }
    return 0;
  } catch {
    return 0;
  }
}

function charType(ch: string): 'upper'|'lower'|'digit'|'symbol' {
  if (/[A-Z]/.test(ch)) return 'upper';
  if (/[a-z]/.test(ch)) return 'lower';
  if (/[0-9]/.test(ch)) return 'digit';
  return 'symbol';
}

function classifyEntropy(bits: number): string {
  if (bits < 28) return 'Very weak';
  if (bits < 36) return 'Weak';
  if (bits < 60) return 'Good';
  return 'Strong';
}

async function analyzePassword(pw?: string): Promise<void> {
  const sub = document.querySelector('.security-sub') as HTMLElement;
  if (!pw) {
    sub.innerHTML = '<div>No password provided for analysis.</div>';
    return;
  }

  // HIBP check
  sub.innerHTML = `<div>Checking breach database…</div>`;
  const pwnedCount = await checkPwned(pw);

  // Character classes
  const hasUpper = /[A-Z]/.test(pw);
  const hasLower = /[a-z]/.test(pw);
  const hasDigit = /[0-9]/.test(pw);
  const hasSym  = /[^A-Za-z0-9]/.test(pw);

  // Charset size estimate
  let charset = 0;
  if (hasUpper) charset += 26;
  if (hasLower) charset += 26;
  if (hasDigit) charset += 10;
  if (hasSym)  charset += 32;
  const bits = charset > 0 ? Math.log2(Math.max(1, charset)) * pw.length : 0;
  const entropyClass = classifyEntropy(bits);

  // Structural mixing: detect runs of same character type
  let maxRun = 1;
  let curRun = 1;
  for (let i = 1; i < pw.length; i++) {
    if (charType(pw[i]) === charType(pw[i-1])) {
      curRun++;
      if (curRun > maxRun) maxRun = curRun;
    } else {
      curRun = 1;
    }
  }
  const classesCount = [hasUpper, hasLower, hasDigit, hasSym].filter(Boolean).length;

  // Define mixing quality: runs of 1 or 2 are perfect, 3 is acceptable, >3 is poor
  let mixingStatus: 'perfect' | 'acceptable' | 'poor' = 'perfect';
  if (maxRun <= 2 && classesCount >= 2) mixingStatus = 'perfect';
  else if (maxRun === 3 && classesCount >= 2) mixingStatus = 'acceptable';
  else mixingStatus = 'poor';

  // Build result HTML
  const pwnHtml = pwnedCount > 0
    ? `<div class="security-row"><strong>Pwned:</strong> <span style="color: var(--danger)">Yes</span> — seen ${pwnedCount.toLocaleString()} times</div>`
    : `<div class="security-row"><strong>Pwned:</strong> <span style="color: var(--accent2)">No known leaks</span></div>`;

  const entropyHtml = `<div class="security-row"><strong>Entropy:</strong> ${bits.toFixed(1)} bits — ${entropyClass}</div>`;

  const structureParts: string[] = [];
  structureParts.push(`<span>${hasUpper ? 'Upper' : '—'}</span>`);
  structureParts.push(`<span>${hasLower ? 'Lower' : '—'}</span>`);
  structureParts.push(`<span>${hasDigit ? 'Digits' : '—'}</span>`);
  structureParts.push(`<span>${hasSym ? 'Symbols' : '—'}</span>`);

  const mixingLabel = mixingStatus === 'perfect' ? `<span style="color: var(--accent2)">Good mix</span>`
    : mixingStatus === 'acceptable' ? `<span style="color: var(--warn)">Acceptable mix</span>`
    : `<span style="color: var(--danger)">Poor mix</span>`;
  const mixingHtml = `<div class="security-row"><strong>Structure:</strong> ${mixingLabel}` +
    `<div class="security-small">Character classes: ${structureParts.join(' · ')} — max same-type run: ${maxRun}</div></div>`;

  const advice: string[] = [];
  if (pwnedCount > 0) advice.push('Choose a different password (found in breaches).');
  if (bits < 36) advice.push('Increase length and include more character classes.');
  if (mixingStatus == "poor") advice.push('Avoid long runs of the same character type; mix letters, digits and symbols.');

  const adviceHtml = `<div class="security-row"><strong>Advice:</strong> ${advice.length ? advice.join(' ') : 'No immediate action required.'}</div>`;

  // Compute a simple overall score (0-100)
  let score = 0;
  if (pwnedCount > 0) {
    // HaveIBeenPwned should heavily penalize the score
    score = 5;
  } else {
    // entropy contributes up to 40 points (0..80 bits mapped)
    const e = Math.max(0, Math.min(80, bits));
    score += Math.round((e / 80) * 40);
    // mixing contributes: perfect -> 40, acceptable -> 25, poor -> 10
    score += mixingStatus === 'perfect' ? 40 : mixingStatus === 'acceptable' ? 25 : 10;
    // small bonus for having many classes
    score += (classesCount - 1) * 5;
    score = Math.min(100, Math.max(0, score));
  }

  // Update gradient on the logo accent only (avoid changing app title)
  const logoAccent = document.querySelector<HTMLElement>('#logoText .app-accent');
  const red = '#f24';
  const yellow = '#f7b500';
  const green = '#3fb950';
  const pct = score; // 0..100
  const grad = `linear-gradient(90deg, ${red} 0%, ${red} ${100 - pct}%, ${green} ${100 - pct}%, ${green} 100%)`;
  if (logoAccent) {
    logoAccent.style.background = grad;
    logoAccent.classList.add('gradient');
    (logoAccent.style as any).webkitBackgroundClip = 'text';
    logoAccent.style.color = 'transparent';
  }

  // Meter HTML
  const meterHtml = `<div class="security-row"><strong>Score:</strong> <span style="font-family: 'Space Mono', monospace;">${score}%</span>` +
    `<div class="security-meter"><div class="meter-fill" style="width:${score}%"></div></div></div>`;

  sub.innerHTML = pwnHtml + entropyHtml + mixingHtml + adviceHtml + meterHtml;

  // Update shield and label color
  const shield = document.querySelector('.security-shield') as HTMLElement | null;
  const label  = document.querySelector('.security-label') as HTMLElement | null;
  if (shield) {
    if (score < 30) shield.style.filter = 'drop-shadow(0 0 20px rgba(242,81,73,0.45))';
    else if (score < 60) shield.style.filter = 'drop-shadow(0 0 20px rgba(247,181,0,0.35))';
    else shield.style.filter = 'drop-shadow(0 0 20px rgba(63,185,80,0.45))';
  }
  if (label) {
    if (score < 30) label.style.color = 'var(--danger)';
    else if (score < 60) label.style.color = 'var(--warn)';
    else label.style.color = 'var(--accent2)';
  }
  label!.textContent = score <10 ? "Insecure" : score < 30 ? 'weak password' : score < 60 ? 'Moderate password' : 'Strong password';
}

// ═════════════════════════════════════════════════════════════════════
// ADD/EDIT SCREEN HANDLERS
// ═════════════════════════════════════════════════════════════════════

const addEditLen = document.getElementById('addEditLen') as HTMLInputElement;
const addEditLenVal = document.getElementById('addEditLenVal') as HTMLElement;
const addEditPassword = document.getElementById('addEditPassword') as HTMLInputElement;
const addEditEye = document.getElementById('addEditEye') as HTMLButtonElement;

// Password visibility toggle
addEditEye.addEventListener('click', () => {
  addEditPassword.type = addEditPassword.type === 'password' ? 'text' : 'password';
});

// Length slider
addEditLen.addEventListener('input', () => {
  addEditLenVal.textContent = addEditLen.value;
});

// Live check for add/edit password field
let addEditLiveTimeout: number | undefined;
async function liveCheckAddEditPassword() {
  const addEditCheckIcon = document.getElementById('addEditCheckIcon') as HTMLElement;
  const pw = addEditPassword.value;
  
  if (!pw) {
    addEditCheckIcon.textContent = '—';
    return;
  }
  
  addEditCheckIcon.textContent = '...';
  const pwnedCount = await checkPwned(pw);
  
  if (pwnedCount > 0) {
    addEditCheckIcon.textContent = '✕';
    addEditCheckIcon.style.color = 'var(--danger)';
  } else {
    const hasUpper = /[A-Z]/.test(pw);
    const hasLower = /[a-z]/.test(pw);
    const hasDigit = /[0-9]/.test(pw);
    const hasSym  = /[^A-Za-z0-9]/.test(pw);
    let charset = 0;
    if (hasUpper) charset += 26;
    if (hasLower) charset += 26;
    if (hasDigit) charset += 10;
    if (hasSym)  charset += 32;
    const bits = charset > 0 ? Math.log2(Math.max(1, charset)) * pw.length : 0;
    
    let score = 0;
    const e = Math.max(0, Math.min(80, bits));
    score += Math.round((e / 80) * 40);
    const classesCount = [hasUpper, hasLower, hasDigit, hasSym].filter(Boolean).length;
    score += (classesCount - 1) * 5;
    
    if (score < 30) {
      addEditCheckIcon.textContent = '✕';
      addEditCheckIcon.style.color = 'var(--danger)';
    } else if (score >= 50) {
      addEditCheckIcon.textContent = '✓';
      addEditCheckIcon.style.color = 'var(--accent2)';
    } else {
      addEditCheckIcon.textContent = '◐';
      addEditCheckIcon.style.color = 'var(--warn)';
    }
  }
}

addEditPassword.addEventListener('input', () => {
  clearTimeout(addEditLiveTimeout);
  addEditLiveTimeout = window.setTimeout(liveCheckAddEditPassword, 300);
});

// Character set checkboxes
(['Upper','Lower','Nums','Syms'] as const).forEach(id => {
  const chk = document.getElementById(`addEditChk${id}`) as HTMLInputElement;
  const label = document.getElementById(`addEditLabel${id}`) as HTMLElement;
  chk.addEventListener('change', () => label.classList.toggle('checked', chk.checked));
});

// Generate button in add/edit screen
document.getElementById('addEditGenBtn')!.addEventListener('click', () => {
  const len = parseInt(addEditLen.value);
  const upper = (document.getElementById('addEditChkUpper') as HTMLInputElement).checked;
  const lower = (document.getElementById('addEditChkLower') as HTMLInputElement).checked;
  const nums = (document.getElementById('addEditChkNums') as HTMLInputElement).checked;
  const syms = (document.getElementById('addEditChkSyms') as HTMLInputElement).checked;

  let charset = '';
  if (upper) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (lower) charset += 'abcdefghijklmnopqrstuvwxyz';
  if (nums) charset += '0123456789';
  if (syms) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
  if (!charset) return;

  const arr = new Uint32Array(len);
  crypto.getRandomValues(arr);
  addEditPassword.value = Array.from(arr).map(n => charset[n % charset.length]).join('');
  // trigger live check immediately after generation
  liveCheckAddEditPassword();
});
