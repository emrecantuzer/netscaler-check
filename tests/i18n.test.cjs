const { test } = require('node:test');
const assert = require('node:assert/strict');
const { assess } = require('../site/checker.js');
const { localizeReport, translate } = require('../site/i18n.js');

test('report translation preserves findings and covers warnings, evidence and actions', () => {
  for (const version of ['14.1-60.21', '14.1-73.37', 'unknown', '15.1-99.99']) {
    for (const config of ['', 'add vpn vserver gw SSL 192.0.2.1 443\nset ns tcpparam -enhancedISNgeneration DISABLED', 'add lb vserver "broken', 'add lb vserver x', 'add lsn group g\nset ns tcpparam -enhancedISNgeneration ENABLED\nunset ns tcpparam -enhancedISNgeneration']) {
      const report = assess({ version, config, complete: true, tcpParams: 'Enhanced ISN Generation: DISABLED' });
      const before = JSON.stringify(report);
      const english = localizeReport(report, 'en');
      assert.equal(/[çğıöşüÇĞİÖŞÜ]/.test(JSON.stringify(english)), false);
      assert.deepEqual(english.counts, report.counts);
      assert.deepEqual(english.results.map(r => [r.id, r.status, r.precondition]), report.results.map(r => [r.id, r.status, r.precondition]));
      assert.equal(JSON.stringify(report), before, 'canonical report must not be mutated');
      assert.equal(localizeReport(report, 'tr').results[0].title, 'Kimlik doğrulamasız komut çalıştırma');
    }
  }
  assert.equal(translate('Satır 12: eksik komut.', 'en'), 'Line 12: incomplete command.');
  assert.equal(translate('Satır 12: nesne adı eksik.', 'en'), 'Line 12: missing object name.');
  assert.equal(translate('Satır 12: protokol türü okunamadı.', 'en'), 'Line 12: could not parse the protocol type.');
  assert.equal(translate('Satır 12: tamamlanmamış devam satırı.', 'en'), 'Line 12: incomplete continuation line.');
});
