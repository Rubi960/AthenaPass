// SPDX-FileCopyrightText: 2026 Rubi960 & Ryosh1
//
// SPDX-License-Identifier: MIT

const fs = require('fs');
const path = require('path');

const EXT = path.join(__dirname, '../extension');
const DESK = path.join(__dirname, '../desktop');

// 1. Copiar style.css tal cual
fs.copyFileSync(
  path.join(EXT, 'style.css'),
  path.join(DESK, 'style.css')
);
console.log('✓ style.css');

// 2. Copiar popup.ts → renderer.ts
fs.copyFileSync(
  path.join(EXT, 'popup.ts'),
  path.join(DESK, 'renderer.ts')
);
console.log('✓ popup.ts → renderer.ts');

// 3. Transformar popup.html → index.html
const html = fs.readFileSync(path.join(EXT, 'popup.html'), 'utf8');
const htmlDesktop = html.replace(/popup\.js/g, 'renderer.js');
fs.writeFileSync(path.join(DESK, 'index.html'), htmlDesktop);
console.log('✓ popup.html → index.html (popup.js reemplazado por renderer.js)');

console.log('\nSync completado');