"use strict";
// ═══════════════════════════════════════════════════════
// AthenaPass — popup.ts
// ═══════════════════════════════════════════════════════
// ── App name config ─────────────────────────────────────
// Cambia estas dos variables para renombrar la app en toda la UI
const APP_NAME_PRIMARY = 'Athena';
const APP_NAME_ACCENT = 'Pass';
const APP_NAME_HTML = `${APP_NAME_PRIMARY}<span class="app-accent">${APP_NAME_ACCENT}</span>`;
document.getElementById('logoText').innerHTML = APP_NAME_HTML;
document.getElementById('appTitle').innerHTML = APP_NAME_HTML;
// ── Config ──────────────────────────────────────────────
const API_ENDPOINT = 'http://localhost:3000/passwords';
const EMAIL_STORAGE_KEY = 'AthenaPass_email';
// ── State ───────────────────────────────────────────────
let passwords = [];
let previousScreen = 'screen-main';
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
async function getCryptoKey() {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(CRYPTO_SALT), { name: 'PBKDF2' }, false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: encoder.encode('AthenaPass'), iterations: 100000, hash: 'SHA-256' }, keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function encryptEmail(email) {
    const key = await getCryptoKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(email);
    const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
    // Guardamos iv + ciphertext como base64 separados por ":"
    const toB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
    return `${toB64(iv.buffer)}:${toB64(cipher)}`;
}
async function decryptEmail(stored) {
    try {
        const key = await getCryptoKey();
        const [ivB64, ctB64] = stored.split(':');
        const fromB64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
        const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(ivB64) }, key, fromB64(ctB64));
        return new TextDecoder().decode(plain);
    }
    catch (_a) {
        return '';
    }
}
async function getSavedEmail() {
    const stored = localStorage.getItem(EMAIL_STORAGE_KEY);
    if (!stored)
        return '';
    return decryptEmail(stored);
}
async function saveEmail(email) {
    const encrypted = await encryptEmail(email);
    localStorage.setItem(EMAIL_STORAGE_KEY, encrypted);
}
function clearEmail() {
    localStorage.removeItem(EMAIL_STORAGE_KEY);
}
// ═══════════════════════════════════════════════════════
// LOCK SCREEN INIT
// ═══════════════════════════════════════════════════════
async function initLockScreen() {
    const saved = await getSavedEmail();
    if (saved) {
        document.getElementById('lockUserEmail').textContent = saved;
        document.getElementById('lockFormMain').style.display = 'flex';
        document.getElementById('lockFormSetup').style.display = 'none';
    }
    else {
        document.getElementById('lockFormMain').style.display = 'none';
        document.getElementById('lockFormSetup').style.display = 'flex';
    }
}
initLockScreen();
// ── Botón "change" email ─────────────────────────────
document.getElementById('lockChangeUser').addEventListener('click', () => {
    clearEmail();
    document.getElementById('setupEmail').value = '';
    document.getElementById('setupPassword').value = '';
    document.getElementById('lockFormMain').style.display = 'none';
    document.getElementById('lockFormSetup').style.display = 'flex';
    document.getElementById('setupEmail').focus();
});
// ── Setup: primera vez ────────────────────────────────
document.getElementById('setupBtn').addEventListener('click', async () => {
    const email = document.getElementById('setupEmail').value.trim();
    if (!email) {
        document.getElementById('setupEmail').focus();
        return;
    }
    await saveEmail(email);
    // TODO: verificar contraseña con (document.getElementById('setupPassword') as HTMLInputElement).value
    unlockApp();
});
document.getElementById('setupPassword')
    .addEventListener('keydown', (e) => {
    if (e.key === 'Enter')
        document.getElementById('setupBtn').click();
});
// ── Unlock normal ─────────────────────────────────────
document.getElementById('lockBtn').addEventListener('click', () => {
    // TODO: verificar contraseña con (document.getElementById('lockPassword') as HTMLInputElement).value
    unlockApp();
});
document.getElementById('lockPassword')
    .addEventListener('keydown', (e) => {
    if (e.key === 'Enter')
        document.getElementById('lockBtn').click();
});
// ── Botón crear usuario (top-right, sin funcionalidad aún) ──
document.getElementById('btnCreateUser').addEventListener('click', () => {
    // TODO: implementar creación de usuario
    console.log('Create user clicked');
});
// ── Toggle eye ────────────────────────────────────────
function toggleEye(inputId, btnId) {
    const btn = document.getElementById(btnId);
    const input = document.getElementById(inputId);
    btn.addEventListener('click', () => {
        input.type = input.type === 'password' ? 'text' : 'password';
    });
}
toggleEye('lockPassword', 'lockEye');
toggleEye('setupPassword', 'setupEye');
// ─────────────────────────────────────────────────────
async function unlockApp() {
    showScreen('screen-main');
    await loadPasswords();
}
// ═══════════════════════════════════════════════════════
// SCREEN NAVIGATION
// ═══════════════════════════════════════════════════════
function showScreen(id) {
    var _a;
    document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
    (_a = document.getElementById(id)) === null || _a === void 0 ? void 0 : _a.classList.add('active');
}
function openSecurityScreen(pwName) {
    previousScreen = 'screen-main';
    document.getElementById('securityPwName').textContent = pwName || '—';
    showScreen('screen-security');
}
document.getElementById('backBtn').addEventListener('click', () => showScreen(previousScreen));
// ═══════════════════════════════════════════════════════
// LOAD PASSWORDS FROM API
// ═══════════════════════════════════════════════════════
async function loadPasswords() {
    const dot = document.getElementById('statusDot');
    const statusT = document.getElementById('statusText');
    dot.classList.add('loading');
    statusT.textContent = 'syncing…';
    try {
        const res = await fetch(API_ENDPOINT);
        const data = await res.json();
        passwords = data;
        dot.classList.remove('loading');
        dot.style.background = '';
        statusT.textContent = `${passwords.length} entries`;
    }
    catch (_a) {
        dot.classList.remove('loading');
        dot.style.background = 'var(--danger)';
        statusT.textContent = 'offline';
        passwords = [
            { name: 'GitHub', password: 'gh_abc123XYZ!' },
            { name: 'Netflix', password: 'nflx_pass#99' },
            { name: 'Gmail', password: 'gm4il$ecure01' },
        ];
    }
    renderPasswordList(passwords);
}
// ═══════════════════════════════════════════════════════
// RENDER PASSWORD LIST
// ═══════════════════════════════════════════════════════
function renderPasswordList(list) {
    const container = document.getElementById('pwList');
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
        <button class="pw-btn check-btn" data-idx="${idx}" title="Security check">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="20 6 9 17 4 12"/>
          </svg>
        </button>
      </div>
    </div>
  `).join('');
    container.querySelectorAll('.eye-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const idx = parseInt(btn.dataset.idx);
            const item = container.querySelectorAll('.pw-item')[idx];
            const valueEl = item.querySelector('.pw-value');
            const visible = valueEl.dataset.visible === 'true';
            valueEl.dataset.visible = visible ? 'false' : 'true';
            valueEl.textContent = visible ? '••••••••••••' : valueEl.dataset.pw;
        });
    });
    container.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const idx = parseInt(btn.dataset.idx);
            navigator.clipboard.writeText(passwords[idx].password).then(() => {
                btn.classList.add('copy-success');
                setTimeout(() => btn.classList.remove('copy-success'), 1500);
            });
        });
    });
    container.querySelectorAll('.check-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const idx = parseInt(btn.dataset.idx);
            openSecurityScreen(passwords[idx].name);
        });
    });
}
// ── Vault search ──────────────────────────────────────
document.getElementById('vaultSearch')
    .addEventListener('input', (e) => {
    const q = e.target.value.toLowerCase();
    const filtered = passwords.filter(p => p.name.toLowerCase().includes(q));
    renderPasswordList(filtered);
});
// ═══════════════════════════════════════════════════════
// TABS
// ═══════════════════════════════════════════════════════
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        var _a;
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        (_a = document.getElementById(`tab-${btn.dataset.tab}`)) === null || _a === void 0 ? void 0 : _a.classList.add('active');
    });
});
// ═══════════════════════════════════════════════════════
// GENERATE TAB
// ═══════════════════════════════════════════════════════
const genLen = document.getElementById('genLen');
const genLenVal = document.getElementById('genLenVal');
const genOutput = document.getElementById('genOutput');
genLen.addEventListener('input', () => { genLenVal.textContent = genLen.value; });
['Upper', 'Lower', 'Nums', 'Syms'].forEach(id => {
    const chk = document.getElementById(`chk${id}`);
    const label = document.getElementById(`label${id}`);
    chk.addEventListener('change', () => label.classList.toggle('checked', chk.checked));
});
document.getElementById('genBtn').addEventListener('click', () => {
    const len = parseInt(genLen.value);
    const upper = document.getElementById('chkUpper').checked;
    const lower = document.getElementById('chkLower').checked;
    const nums = document.getElementById('chkNums').checked;
    const syms = document.getElementById('chkSyms').checked;
    let charset = '';
    if (upper)
        charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (lower)
        charset += 'abcdefghijklmnopqrstuvwxyz';
    if (nums)
        charset += '0123456789';
    if (syms)
        charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
    if (!charset)
        return;
    const arr = new Uint32Array(len);
    crypto.getRandomValues(arr);
    genOutput.value = Array.from(arr).map(n => charset[n % charset.length]).join('');
});
document.getElementById('genCopyBtn').addEventListener('click', () => {
    if (!genOutput.value)
        return;
    navigator.clipboard.writeText(genOutput.value).then(() => {
        const btn = document.getElementById('genCopyBtn');
        btn.classList.add('copy-success');
        setTimeout(() => btn.classList.remove('copy-success'), 1500);
    });
});
document.getElementById('genCheckBtn').addEventListener('click', () => {
    const name = document.getElementById('genName').value.trim();
    openSecurityScreen(name || 'Generated');
});
document.getElementById('genSaveBtn').addEventListener('click', () => {
    // TODO: enviar al servidor
    const btn = document.getElementById('genSaveBtn');
    btn.textContent = '✅ Saved!';
    setTimeout(() => btn.textContent = '💾 Save password', 1500);
});
// ═══════════════════════════════════════════════════════
// UTIL
// ═══════════════════════════════════════════════════════
function escHtml(str) {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}
