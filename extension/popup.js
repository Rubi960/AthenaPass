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
let currentEditIndex = null; // track which password we're editing
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
async function openSecurityScreen(pwName, pwValue) {
    previousScreen = 'screen-main';
    document.getElementById('securityPwName').textContent = pwName || '—';
    showScreen('screen-security');
    await analyzePassword(pwValue);
}
function openAddEditScreen(mode, idx) {
    previousScreen = 'screen-main';
    const titleEl = document.getElementById('addEditTitle');
    const nameInput = document.getElementById('addEditName');
    const tagInput = document.getElementById('addEditTag');
    const pwInput = document.getElementById('addEditPassword');
    if (mode === 'add') {
        titleEl.textContent = 'Add password';
        nameInput.value = '';
        tagInput.value = '';
        pwInput.value = '';
        currentEditIndex = null;
    }
    else if (mode === 'edit' && idx !== undefined) {
        titleEl.textContent = 'Edit password';
        nameInput.value = passwords[idx].name;
        tagInput.value = passwords[idx].tag || '';
        pwInput.value = passwords[idx].password;
        currentEditIndex = idx;
    }
    // Reset password field to hidden
    pwInput.type = 'password';
    showScreen('screen-addedit');
}
document.getElementById('backBtn').addEventListener('click', () => showScreen(previousScreen));
document.getElementById('addEditBackBtn').addEventListener('click', () => showScreen(previousScreen));
document.getElementById('addEditCancelBtn').addEventListener('click', () => showScreen(previousScreen));
document.getElementById('addEditSaveBtn').addEventListener('click', () => {
    const name = document.getElementById('addEditName').value.trim();
    const tag = document.getElementById('addEditTag').value.trim();
    const pw = document.getElementById('addEditPassword').value;
    if (!name || !pw) {
        alert('Please fill in name and password');
        return;
    }
    if (currentEditIndex !== null) {
        // Edit existing
        passwords[currentEditIndex] = { name, password: pw, tag: tag || undefined };
    }
    else {
        // Add new
        passwords.push({ name, password: pw, tag: tag || undefined });
    }
    // TODO: send to server
    showScreen(previousScreen);
    renderPasswordList(passwords);
    updateTagFilter();
});
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
    updateTagFilter();
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
    container.querySelectorAll('.edit-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const idx = parseInt(btn.dataset.idx);
            openAddEditScreen('edit', idx);
        });
    });
    container.querySelectorAll('.check-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const idx = parseInt(btn.dataset.idx);
            openSecurityScreen(passwords[idx].name, passwords[idx].password);
        });
    });
}
// ── Vault search ──────────────────────────────────────
document.getElementById('vaultSearch')
    .addEventListener('input', (e) => {
    const q = e.target.value.toLowerCase();
    const tag = document.getElementById('vaultTagFilter').value;
    const filtered = passwords.filter(p => {
        const matchName = p.name.toLowerCase().includes(q);
        const matchTag = !tag || (p.tag === tag);
        return matchName && matchTag;
    });
    renderPasswordList(filtered);
});
// ── Vault Tag filter ───────────────────────────────────
document.getElementById('vaultTagFilter')
    .addEventListener('change', (e) => {
    const q = document.getElementById('vaultSearch').value.toLowerCase();
    const tag = e.target.value;
    const filtered = passwords.filter(p => {
        const matchName = p.name.toLowerCase().includes(q);
        const matchTag = !tag || (p.tag === tag);
        return matchName && matchTag;
    });
    renderPasswordList(filtered);
});
document.getElementById('vaultAddBtn').addEventListener('click', () => openAddEditScreen('add'));
// Update tag filter options
function updateTagFilter() {
    const tagSet = new Set(passwords.map(p => p.tag).filter(Boolean));
    const select = document.getElementById('vaultTagFilter');
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
const genCheckIcon = document.getElementById('genCheckIcon');
const genCheckBtn = document.getElementById('genCheckBtn');
genLen.addEventListener('input', () => { genLenVal.textContent = genLen.value; });
// Live analysis on password output changes
let liveAnalysisTimeout;
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
    }
    else {
        // Quick entropy check
        const hasUpper = /[A-Z]/.test(pw);
        const hasLower = /[a-z]/.test(pw);
        const hasDigit = /[0-9]/.test(pw);
        const hasSym = /[^A-Za-z0-9]/.test(pw);
        let charset = 0;
        if (hasUpper)
            charset += 26;
        if (hasLower)
            charset += 26;
        if (hasDigit)
            charset += 10;
        if (hasSym)
            charset += 32;
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
        }
        else if (score >= 50) {
            genCheckIcon.textContent = '✓';
            genCheckIcon.style.color = 'var(--accent2)';
            genCheckIcon.style.fontSize = '20px';
            genCheckBtn.dataset.checkStatus = 'passed';
        }
        else {
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
    liveCheckPassword();
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
    if (genOutput.value) {
        openSecurityScreen('Generated', genOutput.value);
    }
});
document.getElementById('genCopyMainBtn').addEventListener('click', () => {
    if (!genOutput.value)
        return;
    navigator.clipboard.writeText(genOutput.value).then(() => {
        const btn = document.getElementById('genCopyMainBtn');
        btn.textContent = '✅ Copied!';
        setTimeout(() => btn.textContent = '📋 Copy to clipboard', 1500);
    });
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
// ═════════════════════════════════════════════════════════════════════
// Password analysis helpers: HIBP check (k-anonymity), entropy, structural mix
// ═════════════════════════════════════════════════════════════════════
function hexFromBuffer(buf) {
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}
async function sha1Hex(text) {
    const data = new TextEncoder().encode(text);
    const digest = await crypto.subtle.digest('SHA-1', data);
    return hexFromBuffer(digest).toUpperCase();
}
async function checkPwned(password) {
    try {
        const hash = await sha1Hex(password);
        const prefix = hash.slice(0, 5);
        const suffix = hash.slice(5);
        const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
        if (!res.ok)
            return 0;
        const text = await res.text();
        const lines = text.split('\n');
        for (const line of lines) {
            const [suf, count] = line.split(':');
            if (suf && suf.trim().toUpperCase() === suffix)
                return parseInt((count || '0').trim(), 10);
        }
        return 0;
    }
    catch (_a) {
        return 0;
    }
}
function charType(ch) {
    if (/[A-Z]/.test(ch))
        return 'upper';
    if (/[a-z]/.test(ch))
        return 'lower';
    if (/[0-9]/.test(ch))
        return 'digit';
    return 'symbol';
}
function classifyEntropy(bits) {
    if (bits < 28)
        return 'Very weak';
    if (bits < 36)
        return 'Weak';
    if (bits < 60)
        return 'Good';
    return 'Strong';
}
async function analyzePassword(pw) {
    const sub = document.querySelector('.security-sub');
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
    const hasSym = /[^A-Za-z0-9]/.test(pw);
    // Charset size estimate
    let charset = 0;
    if (hasUpper)
        charset += 26;
    if (hasLower)
        charset += 26;
    if (hasDigit)
        charset += 10;
    if (hasSym)
        charset += 32;
    const bits = charset > 0 ? Math.log2(Math.max(1, charset)) * pw.length : 0;
    const entropyClass = classifyEntropy(bits);
    // Structural mixing: detect runs of same character type
    let maxRun = 1;
    let curRun = 1;
    for (let i = 1; i < pw.length; i++) {
        if (charType(pw[i]) === charType(pw[i - 1])) {
            curRun++;
            if (curRun > maxRun)
                maxRun = curRun;
        }
        else {
            curRun = 1;
        }
    }
    const classesCount = [hasUpper, hasLower, hasDigit, hasSym].filter(Boolean).length;
    // Define mixing quality: runs of 1 or 2 are perfect, 3 is acceptable, >3 is poor
    let mixingStatus = 'perfect';
    if (maxRun <= 2 && classesCount >= 2)
        mixingStatus = 'perfect';
    else if (maxRun === 3 && classesCount >= 2)
        mixingStatus = 'acceptable';
    else
        mixingStatus = 'poor';
    // Build result HTML
    const pwnHtml = pwnedCount > 0
        ? `<div class="security-row"><strong>Pwned:</strong> <span style="color: var(--danger)">Yes</span> — seen ${pwnedCount.toLocaleString()} times</div>`
        : `<div class="security-row"><strong>Pwned:</strong> <span style="color: var(--accent2)">No known leaks</span></div>`;
    const entropyHtml = `<div class="security-row"><strong>Entropy:</strong> ${bits.toFixed(1)} bits — ${entropyClass}</div>`;
    const structureParts = [];
    structureParts.push(`<span>${hasUpper ? 'Upper' : '—'}</span>`);
    structureParts.push(`<span>${hasLower ? 'Lower' : '—'}</span>`);
    structureParts.push(`<span>${hasDigit ? 'Digits' : '—'}</span>`);
    structureParts.push(`<span>${hasSym ? 'Symbols' : '—'}</span>`);
    const mixingLabel = mixingStatus === 'perfect' ? `<span style="color: var(--accent2)">Good mix</span>`
        : mixingStatus === 'acceptable' ? `<span style="color: var(--warn)">Acceptable mix</span>`
            : `<span style="color: var(--danger)">Poor mix</span>`;
    const mixingHtml = `<div class="security-row"><strong>Structure:</strong> ${mixingLabel}` +
        `<div class="security-small">Character classes: ${structureParts.join(' · ')} — max same-type run: ${maxRun}</div></div>`;
    const advice = [];
    if (pwnedCount > 0)
        advice.push('Choose a different password (found in breaches).');
    if (bits < 36)
        advice.push('Increase length and include more character classes.');
    if (mixingStatus == "poor")
        advice.push('Avoid long runs of the same character type; mix letters, digits and symbols.');
    const adviceHtml = `<div class="security-row"><strong>Advice:</strong> ${advice.length ? advice.join(' ') : 'No immediate action required.'}</div>`;
    // Compute a simple overall score (0-100)
    let score = 0;
    if (pwnedCount > 0) {
        // HaveIBeenPwned should heavily penalize the score
        score = 5;
    }
    else {
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
    const logoAccent = document.querySelector('#logoText .app-accent');
    const red = '#f24';
    const yellow = '#f7b500';
    const green = '#3fb950';
    const pct = score; // 0..100
    const grad = `linear-gradient(90deg, ${red} 0%, ${red} ${100 - pct}%, ${green} ${100 - pct}%, ${green} 100%)`;
    if (logoAccent) {
        logoAccent.style.background = grad;
        logoAccent.classList.add('gradient');
        logoAccent.style.webkitBackgroundClip = 'text';
        logoAccent.style.color = 'transparent';
    }
    // Meter HTML
    const meterHtml = `<div class="security-row"><strong>Score:</strong> <span style="font-family: 'Space Mono', monospace;">${score}%</span>` +
        `<div class="security-meter"><div class="meter-fill" style="width:${score}%"></div></div></div>`;
    sub.innerHTML = pwnHtml + entropyHtml + mixingHtml + adviceHtml + meterHtml;
    // Update shield and label color
    const shield = document.querySelector('.security-shield');
    const label = document.querySelector('.security-label');
    if (shield) {
        if (score < 30)
            shield.style.filter = 'drop-shadow(0 0 20px rgba(242,81,73,0.45))';
        else if (score < 60)
            shield.style.filter = 'drop-shadow(0 0 20px rgba(247,181,0,0.35))';
        else
            shield.style.filter = 'drop-shadow(0 0 20px rgba(63,185,80,0.45))';
    }
    if (label) {
        if (score < 30)
            label.style.color = 'var(--danger)';
        else if (score < 60)
            label.style.color = 'var(--warn)';
        else
            label.style.color = 'var(--accent2)';
    }
    label.textContent = score < 10 ? "Insecure" : score < 30 ? 'weak password' : score < 60 ? 'Moderate password' : 'Strong password';
}
// ═════════════════════════════════════════════════════════════════════
// ADD/EDIT SCREEN HANDLERS
// ═════════════════════════════════════════════════════════════════════
const addEditLen = document.getElementById('addEditLen');
const addEditLenVal = document.getElementById('addEditLenVal');
const addEditPassword = document.getElementById('addEditPassword');
const addEditEye = document.getElementById('addEditEye');
// Password visibility toggle
addEditEye.addEventListener('click', () => {
    addEditPassword.type = addEditPassword.type === 'password' ? 'text' : 'password';
});
// Length slider
addEditLen.addEventListener('input', () => {
    addEditLenVal.textContent = addEditLen.value;
});
// Live check for add/edit password field
let addEditLiveTimeout;
async function liveCheckAddEditPassword() {
    const addEditCheckIcon = document.getElementById('addEditCheckIcon');
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
    }
    else {
        const hasUpper = /[A-Z]/.test(pw);
        const hasLower = /[a-z]/.test(pw);
        const hasDigit = /[0-9]/.test(pw);
        const hasSym = /[^A-Za-z0-9]/.test(pw);
        let charset = 0;
        if (hasUpper)
            charset += 26;
        if (hasLower)
            charset += 26;
        if (hasDigit)
            charset += 10;
        if (hasSym)
            charset += 32;
        const bits = charset > 0 ? Math.log2(Math.max(1, charset)) * pw.length : 0;
        let score = 0;
        const e = Math.max(0, Math.min(80, bits));
        score += Math.round((e / 80) * 40);
        const classesCount = [hasUpper, hasLower, hasDigit, hasSym].filter(Boolean).length;
        score += (classesCount - 1) * 5;
        if (score < 30) {
            addEditCheckIcon.textContent = '✕';
            addEditCheckIcon.style.color = 'var(--danger)';
        }
        else if (score >= 50) {
            addEditCheckIcon.textContent = '✓';
            addEditCheckIcon.style.color = 'var(--accent2)';
        }
        else {
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
['Upper', 'Lower', 'Nums', 'Syms'].forEach(id => {
    const chk = document.getElementById(`addEditChk${id}`);
    const label = document.getElementById(`addEditLabel${id}`);
    chk.addEventListener('change', () => label.classList.toggle('checked', chk.checked));
});
// Generate button in add/edit screen
document.getElementById('addEditGenBtn').addEventListener('click', () => {
    const len = parseInt(addEditLen.value);
    const upper = document.getElementById('addEditChkUpper').checked;
    const lower = document.getElementById('addEditChkLower').checked;
    const nums = document.getElementById('addEditChkNums').checked;
    const syms = document.getElementById('addEditChkSyms').checked;
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
    addEditPassword.value = Array.from(arr).map(n => charset[n % charset.length]).join('');
});
