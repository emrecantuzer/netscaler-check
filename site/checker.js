/* Shared, dependency-free assessment engine for Node.js and the browser. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.NetScalerCheck = factory();
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';
  const SOURCE = 'https://support.citrix.com/external/article/CTX697096';
  const TCP_SOURCE = 'https://docs.netscaler.com/en-us/citrix-adc/current-release/system/tcp-configurations.html#enhanced-isn-generation';
  const LABELS = {
    affected: 'Aksiyon gerekli', review: 'İnceleme gerekli', patched: 'Sürüm eşiği karşılandı',
    not_detected: 'Ön koşul saptanmadı', mitigated: 'ISN önlemi etkin'
  };
  const TITLES = [
    'Kimlik doğrulamasız komut çalıştırma', 'DTLS bellek taşması', 'HTTP request smuggling',
    'URL politikası atlatma', 'Gateway / AAA bellek taşması', 'Oracle LB bellek taşması',
    'HTTP dışı L7 bellek taşması', 'TCP sıra numarası tahmini'
  ];
  const SCORES = [9.5, 9.5, 9.3, 7.0, 8.8, 8.8, 8.8, 8.8];
  const TCP_TYPES = new Set('HTTP SSL SSL_BRIDGE TCP SSL_TCP FTP NNTP RTSP RDP DNS_TCP DOT SIP_TCP SIP_SSL DIAMETER SSL_DIAMETER MYSQL MSSQL ORACLE SMPP MQTT MQTT_TLS MONGO MONGO_TLS PROXY SSL_PROXY USER_TCP USER_SSL_TCP'.split(' '));
  const upper = x => String(x || '').toUpperCase();
  const enabled = x => /^(ENABLED|ON)$/i.test(x || '');
  const disabled = x => /^(DISABLED|OFF)$/i.test(x || '');

  function parseVersion(text, edition = 'standard') {
    if (!['standard', 'fips', 'ndcpp'].includes(edition)) throw new Error('Geçersiz sürüm ailesi.');
    const input = String(text || '').trim();
    const match = input.match(/^(\d+\.\d+)[-.](\d+)\.(\d+)(?:\.(\d+))?$/)
      || input.match(/\b(?:NS|NetScaler\s+NS)\s*(\d+\.\d+)\s*:\s*Build\s+(\d+)\.(\d+)(?:\.(\d+))?\b/i);
    if (!match) return { status: 'unknown', edition, reason: 'Sürüm okunamadı; 14.1-73.37 veya show ns version çıktısını girin.' };
    const branch = match[1];
    const build = [Number(match[2]), Number(match[3]), Number(match[4] || 0)];
    if (build.some(n => !Number.isSafeInteger(n))) return { status: 'unknown', edition, reason: 'Geçersiz build numarası.' };
    // Never compare builds across branches or compliance editions.
    const thresholds = { 'standard:14.1': [73, 37], 'standard:13.1': [64, 23], 'fips:14.1': [73, 37], 'fips:13.1': [37, 279], 'ndcpp:13.1': [37, 279] };
    const threshold = thresholds[`${edition}:${branch}`];
    const normalized = `${branch}-${build[0]}.${build[1]}${match[4] ? '.' + build[2] : ''}`;
    if (!threshold) return { status: 'unknown', edition, normalized, branch, reason: 'Bu dal / sürüm ailesi bültendeki eşik tablosunda yok; üretici doğrulaması gerekli.' };
    const affected = build[0] < threshold[0] || (build[0] === threshold[0] && build[1] < threshold[1]);
    return { status: affected ? 'affected' : 'patched', edition, normalized, branch, target: `${branch}-${threshold.join('.')}`, reason: affected ? 'Bültendeki düzeltme eşiğinin altında.' : 'Bu dal için bültendeki düzeltme eşiği karşılandı.' };
  }

  function tokenize(line) {
    const tokens = []; let token = ''; let quote = ''; let started = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (c === '\\' && i + 1 < line.length) { token += line[++i]; started = true; continue; }
      if (quote) { if (c === quote) quote = ''; else token += c; started = true; continue; }
      if (c === '"' || c === "'") { quote = c; started = true; continue; }
      if (c === '#' && !started) break;
      if (/\s/.test(c)) { if (started) { tokens.push(token); token = ''; started = false; } }
      else { token += c; started = true; }
    }
    if (started) tokens.push(token);
    return { tokens, malformed: Boolean(quote) };
  }

  function parseConfig(text) {
    const records = []; const warnings = []; const lines = String(text || '').replace(/^\uFEFF/, '').split(/\r?\n/);
    let pending = ''; let start = 0;
    lines.forEach((raw, index) => {
      if (!pending) start = index + 1;
      pending += raw;
      if (/\\\s*$/.test(pending)) { pending = pending.replace(/\\\s*$/, ' '); return; }
      const { tokens, malformed } = tokenize(pending.trim().replace(/^>\s*/, ''));
      pending = '';
      if (malformed) warnings.push(`Satır ${start}: kapanmamış tırnak; negatif sonuçlar belirsiz sayıldı.`);
      if (tokens.length && /^(add|set|bind|enable|disable|unset|rm|unbind)$/i.test(tokens[0])) {
        records.push({ tokens, line: start });
        if (/^(unset|rm|unbind)$/i.test(tokens[0])) warnings.push(`Satır ${start}: değişiklik geçmişi algılandı; güncel runningConfig kullanın.`);
        if (tokens.length < 3) warnings.push(`Satır ${start}: eksik komut.`);
      }
    });
    if (pending) warnings.push(`Satır ${start}: tamamlanmamış devam satırı.`);
    return { records, warnings };
  }

  function assess(input = {}) {
    const version = parseVersion(input.version, input.edition || 'standard');
    const parsed = parseConfig(input.config);
    const warnings = [...parsed.warnings];
    const records = parsed.records;
    const full = input.complete === true && records.length > 0 && !warnings.length;
    if (!full) warnings.push('Tam ve okunabilir yapılandırma doğrulanmadı; eşleşme yokluğu güvenli sonuç sayılmaz.');
    const objects = new Map();
    for (const r of records) {
      const t = r.tokens; const verb = upper(t[0]); const kind = upper(t[1]); const subtype = upper(t[2]);
      if (!['ADD', 'SET'].includes(verb)) continue;
      const relevant = subtype === 'VSERVER' || (kind === 'LSN' && subtype === 'GROUP') || (kind === 'LB' && subtype === 'MONITOR') || kind === 'SERVICE' || kind === 'SERVICEGROUP';
      if (!relevant) continue;
      const nameIndex = kind === 'SERVICE' || kind === 'SERVICEGROUP' ? 2 : 3;
      const name = t[nameIndex];
      if (!name) { warnings.push(`Satır ${r.line}: nesne adı eksik.`); continue; }
      const key = `${kind}:${subtype === 'VSERVER' ? subtype : kind === 'SERVICE' || kind === 'SERVICEGROUP' ? '' : subtype}:${name}`;
      let obj = objects.get(key);
      if (!obj) { obj = { kind, subtype, added: false, type: '', options: {}, lines: [] }; objects.set(key, obj); }
      obj.lines.push(r.line);
      if (verb === 'ADD') {
        obj.added = true;
        const typeIndex = kind === 'SERVICE' ? 4 : kind === 'SERVICEGROUP' ? 3 : 4;
        if (!(kind === 'LSN' && subtype === 'GROUP')) {
          obj.type = upper(t[typeIndex]);
          if (!obj.type || !/^[A-Z][A-Z0-9_-]*$/.test(obj.type)) warnings.push(`Satır ${r.line}: protokol türü okunamadı.`);
        }
      }
      for (let i = nameIndex + 1; i < t.length - 1; i++) {
        if (t[i].startsWith('-')) obj.options[upper(t[i])] = upper(t[i + 1]);
      }
    }
    const all = [...objects.values()];
    const vservers = all.filter(o => o.subtype === 'VSERVER');
    const complete = full && warnings.length === parsed.warnings.length;
    const evidence = (objs, rule) => objs.flatMap(o => o.lines.map(line => ({ line, rule })));
    const condition = (matches, rule, uncertain = false) => ({
      state: matches.length ? 'met' : complete && !uncertain ? 'not_detected' : 'unknown',
      evidence: evidence(matches, rule)
    });
    const conditions = [{ state: 'met', evidence: [], note: 'Bültende ek yapılandırma koşulu belirtilmiyor.' }];
    const dtls = vservers.filter(o => o.type === 'DTLS' || (o.kind === 'VPN' && (enabled(o.options['-DTLS']) || (complete && o.added && !o.options['-DTLS']))));
    const dtlsUnknown = vservers.some(o => o.kind === 'VPN' && !disabled(o.options['-DTLS']) && !enabled(o.options['-DTLS']) && (!complete || Boolean(o.options['-DTLS'])));
    conditions.push(condition(dtls, 'DTLS vServer veya DTLS açık Gateway', dtlsUnknown));
    const http = vservers.filter(o => ['LB', 'CS', 'VPN', 'AUTHENTICATION'].includes(o.kind) && ['HTTP', 'SSL'].includes(o.type));
    conditions.push(condition(http, 'HTTP / SSL vServer'));
    const urlPolicies = records.filter(r => ['ADD', 'SET'].includes(upper(r.tokens[0])) && r.tokens.some(t => /\bHTTP\.(REQ|RES)\.URL\b|\bREQ\.HTTP\.URL\b/i.test(t)));
    conditions.push({ state: urlPolicies.length ? 'met' : 'unknown', evidence: urlPolicies.map(r => ({ line: r.line, rule: 'HTTP URL ifadesi' })), note: 'Bültendeki URL politikası ön koşulu ile HTTP/SSL örnekleri uyuşmuyor. Eşleşme yoksa politika incelemesi gerekir; ifade eşleşmesi de aktif bağlamayı kanıtlamaz.' });
    conditions.push(condition(vservers.filter(o => ['VPN', 'AUTHENTICATION'].includes(o.kind)), 'Gateway / AAA vServer'));
    conditions.push(condition(vservers.filter(o => o.kind === 'LB' && o.type === 'ORACLE'), 'Oracle LB vServer'));
    const l7 = all.filter(o =>
      (['FTP', 'FTP-EXTENDED'].includes(o.type) && (['SERVICE', 'SERVICEGROUP'].includes(o.kind) || ['LB', 'CS'].includes(o.kind))) ||
      (o.kind === 'LSN' && o.subtype === 'GROUP' && (enabled(o.options['-RTSPALG']) || enabled(o.options['-FTP']) || (complete && o.added && !o.options['-FTP']))) ||
      (o.kind === 'LB' && o.type === 'DNS' && enabled(o.options['-DNS64']))
    );
    const nat64 = records.filter(r => upper(r.tokens[0]) === 'ADD' && upper(r.tokens[1]) === 'NAT64');
    const policy64 = records.filter(r => upper(r.tokens[1]) === 'DNS' && upper(r.tokens[2]) === 'POLICY64');
    const l7Condition = condition(l7, 'HTTP dışı L7 / ALG / DNS64', policy64.length > 0);
    if (nat64.length) { l7Condition.state = 'met'; l7Condition.evidence.push(...nat64.map(r => ({ line: r.line, rule: 'NAT64 yapılandırması' }))); }
    // These patterns are illustrative, not an exhaustive protocol/feature inventory.
    if (l7Condition.state === 'not_detected') l7Condition.state = 'unknown';
    l7Condition.note = 'L7 örnekleri kapsamlı bir protokol listesi değildir. DNS policy64 için DNS vServer bağlamasını, diğer L7 özelliklerini ayrıca inceleyin.';
    conditions.push(l7Condition);

    let configIsn = 'unknown';
    for (const r of records) {
      if (r.tokens.slice(0, 3).map(upper).join(' ') !== 'SET NS TCPPARAM') continue;
      const at = r.tokens.findIndex(t => upper(t) === '-ENHANCEDISNGENERATION');
      if (at >= 0) configIsn = enabled(r.tokens[at + 1]) ? 'enabled' : disabled(r.tokens[at + 1]) ? 'disabled' : 'unknown';
    }
    if (parsed.warnings.length) configIsn = 'unknown';
    const isnText = String(input.tcpParams || '');
    const isnMatches = [...isnText.matchAll(/Enhanced\s+ISN\s+Generation\s*:\s*(ENABLED|DISABLED)\b/gi)].map(m => m[1].toLowerCase());
    const unique = [...new Set(isnMatches)];
    let isn = unique.length === 1 ? unique[0] : configIsn;
    if (unique.length > 1 || (unique.length === 1 && configIsn !== 'unknown' && configIsn !== unique[0])) {
      isn = 'unknown'; warnings.push('TCP çıktısı ile yapılandırma tutarsız veya birden fazla ISN değeri var; güncel durumu doğrulayın.');
    }
    const tcp = vservers.filter(o => TCP_TYPES.has(o.type));
    const tcpCondition = condition(tcp, 'TCP kullanan vServer');
    if (isn === 'enabled') tcpCondition.state = 'not_detected';
    else if (tcp.length) tcpCondition.state = isn === 'disabled' ? 'met' : 'unknown';
    tcpCondition.note = `Enhanced ISN: ${isn}. CVE-2026-88778 için sürüm güncellemesine ek olarak TCP ayarını doğrulayın.`;
    conditions.push(tcpCondition);

    const results = conditions.map((c, i) => {
      let status;
      if (i === 7) status = isn === 'enabled' ? 'mitigated' : c.state === 'met' ? 'affected' : c.state === 'not_detected' ? 'not_detected' : 'review';
      else status = version.status === 'patched' ? 'patched' : c.state === 'not_detected' ? 'not_detected' : version.status === 'affected' && c.state === 'met' ? 'affected' : 'review';
      const action = i === 7
        ? isn === 'enabled' ? 'ISN önlemi etkin. Sürüm eşiğini de sağlayın.' : 'show ns tcpparam ile doğrulayın. Gerekirse üretici talimatıyla Enhanced ISN Generation etkinleştirin; ayrıca sürümü güncelleyin.'
        : version.status === 'patched' ? 'Bu bülten için sürüm eşiği karşılandı; geçmiş istismar durumunu bu kontrol belirlemez.'
          : version.target ? `${version.target} veya aynı daldaki daha yeni uygun build sürümüne güncelleyin.` : 'Sürüm ve ürün ailesini doğrulayın; desteklenen güncel sürüm için üreticiye başvurun.';
      return { id: `CVE-2026-${88771 + i}`, title: TITLES[i], cvss: SCORES[i], status, label: LABELS[status], precondition: c.state, evidence: c.evidence, note: c.note || '', action };
    });
    const counts = Object.fromEntries(Object.keys(LABELS).map(s => [s, results.filter(r => r.status === s).length]));
    const verdict = counts.affected || version.status === 'affected' ? 'affected' : counts.review || version.status === 'unknown' ? 'review' : 'patched';
    return { schemaVersion: 1, ruleset: 'CTX697096 / 2026-09-28', source: SOURCE, tcpSource: TCP_SOURCE, generatedAt: new Date().toISOString(), version, complete, isn, verdict, counts, warnings: [...new Set(warnings)], results, scope: 'Sürüm ve yapılandırma ön koşulu değerlendirmesi; istismar veya ihlal kanıtı değildir. Ham yapılandırma ve nesne adları rapora eklenmez.' };
  }
  return { assess, parseVersion, parseConfig, LABELS, SOURCE, TCP_SOURCE };
});
