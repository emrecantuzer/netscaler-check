'use strict';
// Explicit allowlist: never publish local appliance exports or reports.
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const dest = path.join(root, '_site');
if (fs.existsSync(dest)) throw new Error('_site already exists; use a fresh workspace for a release build.');
fs.mkdirSync(dest);
for (const name of ['index.html', 'styles.css', 'app.js', 'checker.js', 'i18n.js', 'icon.svg']) {
  fs.copyFileSync(path.join(root, 'site', name), path.join(dest, name));
}
fs.writeFileSync(path.join(dest, '.nojekyll'), '');
console.log('GitHub Pages artifact: _site/ (6 public assets + .nojekyll)');
