'use strict';
(() => {
  const $ = id => document.getElementById(id);
  let current = null;
  let fileRead = 0;
  let language = new URLSearchParams(location.search).get('lang') === 'en' ? 'en' : 'tr';
  let fileInfo = 'UTF-8 metin · En fazla 10 MiB · Sunucuya gönderilmez';
  let loadedFile = null;
  let errorText = '';
  const t = text => NetScalerI18n.translate(text, language);
  // Capture text nodes once so switching languages preserves markup and form values.
  const staticText = [];
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  while (walker.nextNode()) {
    const node = walker.currentNode;
    if (node.textContent.trim() && !node.parentElement.closest('script, textarea, #file-info, #form-error, .language-switch')) staticText.push([node, node.textContent]);
  }
  const staticAttributes = [];
  for (const node of document.querySelectorAll('[placeholder], [aria-label], meta[name="description"]')) {
    if (node.closest('.language-switch button')) continue;
    for (const attribute of ['placeholder', 'aria-label', 'content']) if (node.hasAttribute(attribute)) staticAttributes.push([node, attribute, node.getAttribute(attribute)]);
  }
  const pageTitle = document.title;
  const limit = 10 * 1024 * 1024;
  const demo = '# SENTETİK ÖRNEK\nadd vpn vserver "demo gateway" SSL 192.0.2.10 443\nset vpn vserver "demo gateway" -dtls ON\nadd lb vserver demo_oracle ORACLE 192.0.2.20 1521\nadd responder policy demo_url "HTTP.REQ.URL.CONTAINS(\\"/demo\\")" NOOP\nadd lsn group demo_lsn -clientname demo_client\nset ns tcpparam -enhancedISNgeneration DISABLED';
  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
  }
  function error(message) { errorText = message; $('form-error').textContent = t(message); $('form-error').hidden = !message; }
  function renderFileInfo() {
    $('file-info').textContent = loadedFile ? `${loadedFile.name} · ${(loadedFile.size / 1024).toFixed(1)} KiB · ${t('Yalnızca yerel bellekte')}` : t(fileInfo);
  }
  function setLanguage(value) {
    language = value === 'en' ? 'en' : 'tr';
    document.documentElement.lang = language;
    document.title = t(pageTitle);
    for (const [node, original] of staticText) node.textContent = original.replace(/\S[\s\S]*\S|\S/, value => t(value));
    for (const [node, attribute, original] of staticAttributes) node.setAttribute(attribute, t(original));
    for (const button of document.querySelectorAll('[data-language]')) button.setAttribute('aria-pressed', String(button.dataset.language === language));
    const url = new URL(location.href); url.searchParams.set('lang', language);
    history.replaceState(null, '', url);
    renderFileInfo(); error(errorText);
    if (current) renderReport();
  }
  function invalidate() {
    current = null; $('download').disabled = true; $('report').hidden = true; $('empty-state').hidden = false; error('');
  }
  function renderResults() {
    if (!current) return;
    const filter = $('filter').value;
    const open = new Set([...document.querySelectorAll('.result-row[open]')].map(row => row.dataset.cve));
    const results = NetScalerI18n.localizeReport(current, language).results.filter(r => filter === 'all' || (filter === 'resolved' ? !['affected', 'review'].includes(r.status) : r.status === filter));
    $('result-list').replaceChildren();
    if (!results.length) $('result-list').append(el('p', t('Bu filtrede sonuç bulunmuyor.'), 'no-results'));
    for (const result of results) {
      const row = el('details', undefined, 'result-row');
      row.dataset.cve = result.id; row.open = open.has(result.id);
      const summary = el('summary');
      const title = el('span');
      title.append(el('span', result.id, 'cve-id'), el('span', result.title, 'result-title'));
      summary.append(title, el('span', result.label, `badge ${result.status}`));
      const body = el('div', undefined, 'result-detail');
      const precondition = { met: 'Saptandı', unknown: 'Belirsiz / doğrulama gerekli', not_detected: 'Saptanmadı' };
      body.append(el('p', `CVSS v4: ${result.cvss.toFixed(1)} · ${t('Ön koşul')}: ${t(precondition[result.precondition])}`));
      body.append(el('p', result.action));
      if (result.note) body.append(el('p', result.note));
      if (result.evidence.length) {
        const list = el('ul');
        for (const item of result.evidence) list.append(el('li', `${t('Satır')} ${item.line} · ${item.rule}`));
        body.append(list);
      }
      row.append(summary, body); $('result-list').append(row);
    }
  }
  function renderReport() {
      const report = NetScalerI18n.localizeReport(current, language);
      $('summary').dataset.verdict = report.verdict;
      const headlines = { affected: 'Öncelikli aksiyon gerekiyor.', review: 'Bazı kontroller için doğrulama gerekiyor.', patched: 'Sürüm eşiği ve ISN kontrolü tamamlandı.' };
      $('summary').replaceChildren(el('h3', t(headlines[report.verdict])), el('p', `${report.version.normalized || t('Sürüm belirlenemedi')} · ${report.version.edition.toUpperCase()} · ${t('Hedef')}: ${report.version.target || t('Üretici doğrulaması')}`), el('p', `${t(report.complete ? 'Tam yapılandırma beyanı' : 'Kısmi / belirsiz yapılandırma')} · Enhanced ISN: ${report.isn}`));
      $('metrics').replaceChildren();
      for (const [count, label] of [[report.counts.affected, 'Aksiyon gerekli'], [report.counts.review, 'İnceleme gerekli'], [8 - report.counts.affected - report.counts.review, 'Eşik / ön koşul tamam']]) {
        const metric = el('div', undefined, 'metric'); metric.append(el('strong', String(count).padStart(2, '0')), el('span', t(label))); $('metrics').append(metric);
      }
      $('warnings').replaceChildren(...report.warnings.map(w => el('p', w)));
      renderResults();
      $('empty-state').hidden = true; $('report').hidden = false; $('download').disabled = false;
  }
  function run() {
    try {
      if (!$('version').value.trim()) throw new Error('NetScaler sürümünü girin.');
      if (new Blob([$('config').value]).size > limit || new Blob([$('tcp').value]).size > limit) throw new Error('Metin alanları en fazla 10 MiB olabilir.');
      if (/\0|\uFFFD/.test($('config').value + $('tcp').value)) throw new Error('UTF-8 metin kullanın.');
      current = NetScalerCheck.assess({ version: $('version').value, edition: $('edition').value, config: $('config').value, complete: $('complete').checked, tcpParams: $('tcp').value });
      $('filter').value = 'all'; renderReport(); error('');
    } catch (e) { invalidate(); error(e.message); }
  }
  $('check-form').addEventListener('submit', e => { e.preventDefault(); run(); });
  for (const id of ['version', 'edition', 'config', 'complete', 'tcp']) $(id).addEventListener('input', () => { fileRead++; invalidate(); });
  $('filter').addEventListener('change', renderResults);
  $('demo').addEventListener('click', () => {
    fileRead++; $('version').value = '14.1-60.21'; $('edition').value = 'standard'; $('config').value = demo;
    $('tcp').value = 'Enhanced ISN Generation: DISABLED'; $('complete').checked = true;
    $('config-file').value = ''; loadedFile = null; fileInfo = 'Deneniyor: sentetik örnek yapılandırma'; renderFileInfo(); run();
  });
  $('clear').addEventListener('click', () => {
    fileRead++; $('check-form').reset(); loadedFile = null; fileInfo = 'UTF-8 metin · En fazla 10 MiB · Sunucuya gönderilmez'; renderFileInfo(); invalidate(); $('version').focus();
  });
  $('config-file').addEventListener('change', async e => {
    const file = e.target.files[0]; if (!file) return;
    const generation = ++fileRead;
    invalidate(); loadedFile = null; $('config').value = ''; $('complete').checked = false;
    try {
      if (file.size > limit) throw new Error('Dosya sınırı 10 MiB.');
      const content = await file.text();
      if (generation !== fileRead) return;
      if (/\0|\uFFFD/.test(content)) throw new Error('Dosya UTF-8 metin olmalıdır.');
      $('config').value = content;
      loadedFile = { name: file.name, size: file.size }; renderFileInfo();
    } catch (e) { if (generation === fileRead) { fileInfo = 'Dosya yüklenemedi.'; renderFileInfo(); error(e.message); } }
  });
  $('download').addEventListener('click', () => {
    if (!current) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(NetScalerI18n.localizeReport(current, language), null, 2)], { type: 'application/json' }));
    const link = el('a'); link.href = url; link.download = `netscaler-check-${new Date().toISOString().slice(0, 10)}.json`; document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  for (const button of document.querySelectorAll('[data-language]')) button.addEventListener('click', () => setLanguage(button.dataset.language));
  setLanguage(language);
})();
