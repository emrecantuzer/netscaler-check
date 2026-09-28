#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const { assess, LABELS } = require('../site/checker.js');
const HELP = `NetScaler CTX697096 kontrolü (Node.js 22+)

node scripts/check.cjs --version 14.1-60.21 --edition standard --config private/ns.conf --complete
node scripts/check.cjs --version-file private/version.txt --config private/ns.conf --tcp-params private/tcp.txt --complete --json

  --version VALUE       Build veya tırnak içinde show ns version çıktısı
  --version-file FILE   UTF-8 show ns version çıktısı
  --edition VALUE       standard (varsayılan), fips, ndcpp; cihaz ailesini doğrulayın
  --config FILE         UTF-8 ns.conf veya show ns runningConfig çıktısı
  --tcp-params FILE     UTF-8 show ns tcpparam çıktısı
  --complete            Dosyanın tam ve güncel yapılandırma olduğunu beyan eder
  --json                Makine tarafından okunabilir, ham config içermeyen rapor
  --help                Bu yardım

Çıkış: 0 = eşikler/ön koşullar karşılandı, 1 = aksiyon gerekli,
       2 = belirsiz/inceleme gerekli, 3 = girdi veya çalışma hatası.
Bağlantı kurmaz, cihazı değiştirmez; istismar/ihlal testi yapmaz.
`;
function main(args) {
  if (args.includes('--help')) { process.stdout.write(HELP); return 0; }
  const opts = {};
  const values = new Set(['--version', '--version-file', '--edition', '--config', '--tcp-params']);
  for (let i = 0; i < args.length; i++) {
    const flag = args[i];
    if (Object.hasOwn(opts, flag)) throw new Error(`Tekrarlanan seçenek: ${flag}`);
    if (['--complete', '--json'].includes(flag)) opts[flag] = true;
    else if (values.has(flag)) {
      if (!args[i + 1] || args[i + 1].startsWith('--')) throw new Error(`${flag} için değer gerekli.`);
      opts[flag] = args[++i];
    } else throw new Error(`Bilinmeyen seçenek: ${flag}`);
  }
  if (!opts['--version'] && !opts['--version-file']) throw new Error('--version veya --version-file gerekli.');
  if (opts['--version'] && opts['--version-file']) throw new Error('Yalnızca bir sürüm kaynağı seçin.');
  const read = path => {
    if (!path) return '';
    if (fs.statSync(path).size > 10 * 1024 * 1024) throw new Error('Dosya sınırı 10 MiB.');
    const text = fs.readFileSync(path, 'utf8');
    if (text.includes('\0') || text.includes('\uFFFD')) throw new Error('Dosya UTF-8 metin olmalıdır.');
    return text;
  };
  const report = assess({ version: opts['--version'] || read(opts['--version-file']), edition: opts['--edition'] || 'standard', config: read(opts['--config']), tcpParams: read(opts['--tcp-params']), complete: Boolean(opts['--complete']) });
  if (opts['--json']) process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  else {
    console.log(`\nNetScaler / ${report.ruleset}\n${LABELS[report.verdict]} | ${report.version.normalized || 'Bilinmeyen sürüm'} / ${report.version.edition}`);
    console.log(`Hedef: ${report.version.target || 'Üretici doğrulaması gerekli'} | Enhanced ISN: ${report.isn}\n`);
    for (const r of report.results) {
      console.log(`${r.id}  ${r.label}\n  ${r.title}\n  ${r.action}`);
      if (r.note) console.log(`  ${r.note}`);
      if (r.evidence.length) console.log(`  Kanıt satırları: ${[...new Set(r.evidence.map(e => e.line))].join(', ')}`);
    }
    for (const warning of report.warnings) console.log(`\nNot: ${warning}`);
    console.log(`\n${report.scope}\nKaynak: ${report.source}`);
  }
  return report.verdict === 'affected' ? 1 : report.verdict === 'review' ? 2 : 0;
}
try { process.exitCode = main(process.argv.slice(2)); }
catch (error) { console.error(`Hata: ${error.message}`); process.exitCode = 3; }
