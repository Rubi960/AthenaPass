// ═══════════════════════════════════════════════════════
// AthenaPass — popup.js
// ═══════════════════════════════════════════════════════

// ── App name config ────────────────────────────────────
// Cambia estas dos variables para renombrar la app en toda la UI
const APP_NAME_PRIMARY = 'Athena';
const APP_NAME_ACCENT  = 'Pass';

const APP_NAME_HTML = `${APP_NAME_PRIMARY}<span class="app-accent">${APP_NAME_ACCENT}</span>`;

// Renderizar nombre en todos los puntos donde aparece
document.getElementById('logoText').innerHTML  = APP_NAME_HTML;
document.getElementById('appTitle').innerHTML  = APP_NAME_HTML;

// ── Config ─────────────────────────────────────────────
const API_ENDPOINT   = 'http://localhost:5000/passwords';
const EMAIL_STORAGE_KEY = 'athenapass_email'; // clave en localStorage

// ── State ──────────────────────────────────────────────
let passwords        = [];
let previousScreen   = 'screen-main';

// ═══════════════════════════════════════════════════════
// EMAIL / SESSION — se guarda en localStorage para no
// tener que reescribirlo cada vez que se abre la extensión
// ═══════════════════════════════════════════════════════
function getSavedEmail() {
  return localStorage.getItem(EMAIL_STORAGE_KEY) || '';
}
function saveEmail(email) {
  localStorage.setItem(EMAIL_STORAGE_KEY, email);
}
function clearEmail() {
  localStorage.removeItem(EMAIL_STORAGE_KEY);
}

// ── Inicializar lock screen según si hay email guardado ─
function initLockScreen() {
  const saved = getSavedEmail();
  if (saved) {
    // Ya tenemos email — mostrar solo campo de contraseña
    document.getElementById('lockUserEmail').textContent = saved;
    document.getElementById('lockFormMain').style.display  = 'flex';
    document.getElementById('lockFormSetup').style.display = 'none';
  } else {
    // Primera vez — pedir email + contraseña
    document.getElementById('lockFormMain').style.display  = 'none';
    document.getElementById('lockFormSetup').style.display = 'flex';
  }
}
initLockScreen();

// ── Botón "change" junto al email mostrado ─────────────
document.getElementById('lockChangeUser').addEventListener('click', () => {
  clearEmail();
  document.getElementById('setupEmail').value    = '';
  document.getElementById('setupPassword').value = '';
  document.getElementById('lockFormMain').style.display  = 'none';
  document.getElementById('lockFormSetup').style.display = 'flex';
  document.getElementById('setupEmail').focus();
});

// ── Setup (primera vez): guardar email y continuar ──────
document.getElementById('setupBtn').addEventListener('click', () => {
  const email = document.getElementById('setupEmail').value.trim();
  if (!email) { document.getElementById('setupEmail').focus(); return; }
  saveEmail(email);
  // TODO: verificar contraseña aquí con document.getElementById('setupPassword').value
  unlockApp();
});
document.getElementById('setupPassword').addEventListener('keydown', e => {
  if (e.key === 'Enter') document.getElementById('setupBtn').click();
});

// ── Unlock normal (email ya guardado) ──────────────────
document.getElementById('lockBtn').addEventListener('click', () => {
  // TODO: verificar contraseña aquí con document.getElementById('lockPassword').value
  unlockApp();
});
document.getElementById('lockPassword').addEventListener('keydown', e => {
  if (e.key === 'Enter') document.getElementById('lockBtn').click();
});

// ── Toggle show/hide password ──────────────────────────
function toggleEye(inputId, btnId) {
  const btn   = document.getElementById(btnId);
  const input = document.getElementById(inputId);
  btn.addEventListener('click', () => {
    input.type = input.type === 'password' ? 'text' : 'password';
  });
}
toggleEye('lockPassword', 'lockEye');
toggleEye('setupPassword', 'setupEye');

// ── Unlock → cargar app ────────────────────────────────
async function unlockApp() {
  showScreen('screen-main');
  await loadPasswords();
}

// ═══════════════════════════════════════════════════════
// SCREEN NAVIGATION
// ═══════════════════════════════════════════════════════
function showScreen(id) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  const el = document.getElementById(id);
  if (el) el.classList.add('active');
}

function openSecurityScreen(pwName) {
  previousScreen = 'screen-main';
  document.getElementById('securityPwName').textContent = pwName || '—';
  showScreen('screen-security');
}

document.getElementById('backBtn').addEventListener('click', () => {
  showScreen(previousScreen);
});

// ═══════════════════════════════════════════════════════
// LOAD PASSWORDS FROM API
// ═══════════════════════════════════════════════════════
async function loadPasswords() {
  const dot     = document.getElementById('statusDot');
  const statusT = document.getElementById('statusText');

  dot.classList.add('loading');
  statusT.textContent = 'syncing…';

  try {
    const res  = await fetch(API_ENDPOINT);
    console.log("AAAAAAAAAAAA");
    const data = await res.json();
    console.log("BBBBBBBBBBBB");
    passwords = data;
    dot.classList.remove('loading');
    dot.style.background = '';
    statusT.textContent = `${passwords.length} entries`;
  } catch {
    dot.classList.remove('loading');
    dot.style.background = 'var(--danger)';
    statusT.textContent = 'offline';
    // Datos de ejemplo si el servidor no está disponible
    passwords = [
      { name: 'GitHub',   password: 'gh_abc123XYZ!' },
      { name: 'Netflix',  password: 'nflx_pass#99'  },
      { name: 'Gmail',    password: 'gm4il$ecure01' },
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
        <button class="pw-btn eye-btn" data-idx="${idx}" title="Show/hide">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
          </svg>
        </button>
        <button class="pw-btn copy-btn" data-idx="${idx}" title="Copy">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
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
      const idx     = parseInt(btn.dataset.idx);
      const item    = container.querySelectorAll('.pw-item')[idx];
      const valueEl = item.querySelector('.pw-value');
      const visible = valueEl.dataset.visible === 'true';
      valueEl.dataset.visible = visible ? 'false' : 'true';
      valueEl.textContent     = visible ? '••••••••••••' : valueEl.dataset.pw;
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
document.getElementById('vaultSearch').addEventListener('input', e => {
  const q        = e.target.value.toLowerCase();
  const filtered = passwords.filter(p => p.name.toLowerCase().includes(q));
  renderPasswordList(filtered);
});

// ═══════════════════════════════════════════════════════
// TABS
// ═══════════════════════════════════════════════════════
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    const panel = document.getElementById(`tab-${btn.dataset.tab}`);
    if (panel) panel.classList.add('active');
  });
});

// ═══════════════════════════════════════════════════════
// GENERATE TAB
// ═══════════════════════════════════════════════════════
const genLen    = document.getElementById('genLen');
const genLenVal = document.getElementById('genLenVal');
const genOutput = document.getElementById('genOutput');

genLen.addEventListener('input', () => { genLenVal.textContent = genLen.value; });

['Upper','Lower','Nums','Syms'].forEach(id => {
  const chk   = document.getElementById(`chk${id}`);
  const label = document.getElementById(`label${id}`);
  chk.addEventListener('change', () => label.classList.toggle('checked', chk.checked));
});

document.getElementById('genBtn').addEventListener('click', () => {
  const len   = parseInt(genLen.value);
  const upper = document.getElementById('chkUpper').checked;
  const lower = document.getElementById('chkLower').checked;
  const nums  = document.getElementById('chkNums').checked;
  const syms  = document.getElementById('chkSyms').checked;

  let charset = '';
  if (upper) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (lower) charset += 'abcdefghijklmnopqrstuvwxyz';
  if (nums)  charset += '0123456789';
  if (syms)  charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
  if (!charset) return;

  const arr = new Uint32Array(len);
  crypto.getRandomValues(arr);
  genOutput.value = Array.from(arr).map(n => charset[n % charset.length]).join('');
});

// Copy button en generate
document.getElementById('genCopyBtn').addEventListener('click', () => {
  if (!genOutput.value) return;
  navigator.clipboard.writeText(genOutput.value).then(() => {
    const btn = document.getElementById('genCopyBtn');
    btn.classList.add('copy-success');
    setTimeout(() => btn.classList.remove('copy-success'), 1500);
  });
});

// Security check desde generate
document.getElementById('genCheckBtn').addEventListener('click', () => {
  const name = document.getElementById('genName').value.trim();
  openSecurityScreen(name || 'Generated');
});

// Save
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
