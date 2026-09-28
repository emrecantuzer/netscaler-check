'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const vm = require('node:vm');
const { assess, parseVersion } = require('../site/checker.js');
const base = { version: '14.1-60.21', complete: true };
const check = (config, extra = {}) => assess({ ...base, config, ...extra });
const cve = (report, suffix) => report.results.find(r => r.id === `CVE-2026-${suffix}`);

test('all branch/edition boundaries use numeric build comparison', () => {
  for (const [edition, before, exact, after] of [
    ['standard', '14.1-73.36', '14.1-73.37', '14.1-100.1'],
    ['standard', '13.1-64.22', '13.1-64.23', '13.1-65.1'],
    ['fips', '14.1-73.36', '14.1-73.37', '14.1-74.1'],
    ['fips', '13.1-37.278', '13.1-37.279', '13.1-37.280'],
    ['ndcpp', '13.1-37.278', '13.1-37.279', '13.1-38.1']
  ]) {
    assert.equal(parseVersion(before, edition).status, 'affected');
    assert.equal(parseVersion(exact, edition).status, 'patched');
    assert.equal(parseVersion(after, edition).status, 'patched');
  }
  assert.equal(parseVersion('13.1-37.279', 'standard').status, 'affected');
  assert.equal(parseVersion('13.1.37.279', 'fips').status, 'patched');
  assert.equal(parseVersion('NetScaler NS14.1: Build 73.37.nc, Date: Sep 27 2026').status, 'patched');
  assert.equal(parseVersion('14.1-73.37.5').status, 'patched');
});
test('unknown branches, malformed versions and unknown editions never pass', () => {
  for (const value of ['12.1-99.99', '15.1-99.99', '', 'nonsense', '14.1-73.37junk', 'some 14.1-73.37 text']) assert.equal(parseVersion(value).status, 'unknown');
  assert.equal(parseVersion('14.1-99.99', 'ndcpp').status, 'unknown');
  assert.throws(() => parseVersion('14.1-73.37', 'oops'));
  assert.equal(check('', { version: '15.1-99.99' }).verdict, 'review');
});
test('default RCE precondition applies without configuration', () => {
  assert.equal(cve(check(''), 88771).status, 'affected');
  assert.equal(cve(check('', { version: '?' }), 88771).status, 'review');
});
test('Gateway DTLS defaults, quoted names and later set overrides', () => {
  const config = 'add vpn vserver "My gateway" SSL 192.0.2.1 443';
  assert.equal(cve(check(config), 88772).status, 'affected');
  assert.equal(cve(check(config + '\nset vpn vserver "My gateway" -dtls OFF'), 88772).status, 'not_detected');
  assert.equal(cve(check(config + '\nset vpn vserver "My gateway" -dtls OFF\nset vpn vserver "My gateway" -dtls ON'), 88772).status, 'affected');
  assert.equal(cve(check(config, { complete: false }), 88772).status, 'review');
  assert.equal(cve(check(config + '\nset vpn vserver "My gateway" -dtls INVALID'), 88772).status, 'review');
  assert.equal(cve(check('add lb vserver dtls DTLS 192.0.2.2 443'), 88772).status, 'affected');
});
test('object names are case sensitive while commands/options are case insensitive', () => {
  const report = check('ADD VPN VSERVER Gateway SSL 192.0.2.1 443\nadd vpn vserver gateway SSL 192.0.2.2 443\nSET VPN VSERVER Gateway -DTLS OFF');
  assert.equal(cve(report, 88772).status, 'affected');
});
test('HTTP, gateway, AAA and Oracle preconditions are detected', () => {
  const report = check('add authentication vserver aaa SSL 192.0.2.1 443\nadd lb vserver db ORACLE 192.0.2.2 1521');
  for (const id of [88773, 88775, 88776]) assert.equal(cve(report, id).status, 'affected');
  assert.equal(cve(check('add lb vserver not_ORACLE HTTP 192.0.2.2 80'), 88776).status, 'not_detected');
});
test('URL policy discrepancy is reported instead of treating SSL as proof', () => {
  const report = check('add lb vserver web SSL 192.0.2.1 443');
  assert.equal(cve(report, 88774).status, 'review');
  const policy = check('add responder policy demo "HTTP.REQ.URL.CONTAINS(\\"/admin\\")" NOOP');
  assert.equal(cve(policy, 88774).status, 'affected');
  assert.equal(cve(policy, 88774).evidence[0].line, 1);
});
test('L7 cases cover FTP service/monitor, NAT64, DNS64 and LSN groups', () => {
  for (const config of [
    'add lb vserver ftp FTP 192.0.2.1 21', 'add cs vserver ftp FTP 192.0.2.1 21',
    'add service ftp 192.0.2.1 FTP 21', 'add serviceGroup ftp FTP',
    'add lb monitor ftp FTP', 'add lb monitor ftp FTP-EXTENDED',
    'add nat64 prefix p 2001:db8::/96', 'add lsn group g -clientname c',
    'add lsn group g -ftp DISABLED\nset lsn group g -rtspalg ENABLED',
    'add lb vserver dns DNS 192.0.2.1 53\nset lb vserver dns -dns64 ENABLED'
  ]) assert.equal(cve(check(config), 88777).status, 'affected', config);
  assert.equal(cve(check('add lsn group a\nadd lsn group b\nset lsn group a -ftp DISABLED'), 88777).status, 'affected');
  assert.equal(cve(check('add lsn group a\nset lsn group a -ftp DISABLED'), 88777).status, 'review');
  assert.equal(cve(check('add dns policy64 p -rule TRUE -action a'), 88777).status, 'review');
});
test('TCP ISN requires explicit evidence and remains actionable on patched build', () => {
  const config = 'add lb vserver web HTTP 192.0.2.1 80';
  assert.equal(cve(check(config), 88778).status, 'review');
  for (const version of ['14.1-60.21', '14.1-73.37']) {
    const report = check(config, { version, tcpParams: 'Enhanced ISN Generation: DISABLED' });
    assert.equal(cve(report, 88778).status, 'affected');
    assert.equal(report.verdict, 'affected');
  }
  assert.equal(cve(check(config, { tcpParams: 'Enhanced ISN Generation: ENABLED' }), 88778).status, 'mitigated');
  assert.equal(cve(check(config + '\nset ns tcpparam -enhancedISNgeneration ENABLED'), 88778).status, 'mitigated');
  assert.equal(cve(check('add lb vserver dns DNS 192.0.2.1 53'), 88778).status, 'not_detected');
});
test('contradictory ISN inputs require review', () => {
  const config = 'add lb vserver web TCP 192.0.2.1 80\nset ns tcpparam -enhancedISNgeneration ENABLED';
  const report = check(config, { tcpParams: 'Enhanced ISN Generation: DISABLED' });
  assert.equal(report.isn, 'unknown');
  assert.equal(cve(report, 88778).status, 'review');
  assert.equal(check(config, { tcpParams: 'Enhanced ISN Generation: ENABLED\nEnhanced ISN Generation: DISABLED' }).isn, 'unknown');
});
test('empty, partial and malformed configuration never yields false absent preconditions', () => {
  for (const config of ['', '# comment only', 'add lb vserver broken', 'add lb vserver "broken HTTP 192.0.2.1 80', 'add lb vserver x HTTP \\']) {
    const report = check(config);
    assert.equal(report.complete, false, config);
    assert.equal(cve(report, 88776).status, 'review', config);
  }
  assert.equal(cve(check('set ns hostname demo', { complete: false }), 88775).status, 'review');
});
test('continuation lines, CRLF, comments and prompt prefixes preserve evidence positions', () => {
  const report = check('# comment\r\n> add vpn vserver "GW with spaces" SSL \\\r\n192.0.2.1 443 -dtls OFF\r\n# add lb vserver db ORACLE 192.0.2.2 1521');
  assert.equal(cve(report, 88772).status, 'not_detected');
  assert.equal(cve(report, 88775).evidence[0].line, 2);
  assert.equal(cve(report, 88776).status, 'not_detected');
});
test('change-history inputs do not prove absent preconditions', () => {
  const report = check('add lb vserver db ORACLE 192.0.2.2 1521\nrm lb vserver db');
  assert.equal(report.complete, false);
  assert.equal(cve(report, 88773).status, 'review');
  const tcpHistory = check('add lb vserver web HTTP 192.0.2.1 80\nset ns tcpparam -enhancedISNgeneration ENABLED\nunset ns tcpparam -enhancedISNgeneration');
  assert.equal(cve(tcpHistory, 88778).status, 'review');
});
test('reports never echo raw config, names, IPs, policy strings or credentials', () => {
  const secret = 'VERY_SECRET_VALUE';
  const report = check(`add vpn vserver ${secret} SSL 192.0.2.199 443\nset system user admin -password ${secret}\nadd responder policy p "HTTP.REQ.URL.CONTAINS(\\"${secret}\\")" NOOP`);
  const serialized = JSON.stringify(report);
  for (const value of [secret, '192.0.2.199', 'set system user', 'HTTP.REQ.URL.CONTAINS']) assert.equal(serialized.includes(value), false);
});
test('browser and CLI share identical assessment logic', () => {
  const sandbox = {};
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../site/checker.js'), 'utf8'), sandbox);
  const input = { ...base, config: fs.readFileSync(path.join(__dirname, '../examples/demo.conf'), 'utf8') };
  const local = assess(input); const browser = JSON.parse(JSON.stringify(sandbox.NetScalerCheck.assess(input)));
  delete local.generatedAt; delete browser.generatedAt;
  assert.deepEqual(browser, local);
});
test('CLI JSON and exit codes distinguish actionable, review, completed and error', () => {
  const cli = (...args) => spawnSync(process.execPath, ['scripts/check.cjs', ...args], { cwd: path.join(__dirname, '..'), encoding: 'utf8' });
  const affected = cli('--version', '14.1-60.21', '--config', 'examples/demo.conf', '--complete', '--json');
  assert.equal(affected.status, 1); assert.equal(JSON.parse(affected.stdout).results.length, 8);
  assert.equal(cli('--version', '14.1-73.37', '--json').status, 2);
  assert.equal(cli('--version', '14.1-73.37', '--tcp-params', 'examples/tcp-enabled.txt', '--json').status, 0);
  assert.equal(cli('--version', 'bad', '--json').status, 2);
  assert.equal(cli('--version').status, 3);
  assert.equal(cli('--version', '14.1-73.37', '--edition', 'oops').status, 3);
  assert.equal(cli('--version', '14.1-73.37', '--config', 'missing.conf').status, 3);
  assert.equal(cli('--wat').status, 3);
  assert.equal(cli('--help').status, 0);
  assert.equal(cli('--version', '14.1-60.21', '--version-file', 'README.md').status, 3);
});
