(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.NetScalerI18n = factory();
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';
  const en = {
    'NetScaler Check — Güvenlik Bülteni Kontrolü': 'NetScaler Check — Security Bulletin Assessment',
    'Citrix NetScaler CTX697096 için tarayıcınızda çalışan sürüm ve yapılandırma kontrolü.': 'Browser-based version and configuration assessment for Citrix NetScaler CTX697096.',
    'Kontrole geç': 'Skip to assessment', 'Ana menü': 'Main navigation', 'Dil seçimi': 'Language selection',
    'Nasıl çalışır?': 'How it works', 'Resmî bülten ↗': 'Official bulletin ↗',
    '27 EYLÜL 2026 BÜLTENİ': '27 SEPTEMBER 2026 BULLETIN',
    'Yapılandırmanızı kontrol edin.': 'Check your configuration.', 'Sonraki adımı netleştirin.': 'Know your next step.',
    'NetScaler ADC ve Gateway için 8 CVE’yi sürüm ve yapılandırma ön koşullarıyla değerlendirin. Verileriniz yalnızca tarayıcınızda işlenir.': 'Assess 8 CVEs for NetScaler ADC and Gateway using version and configuration prerequisites. Your data is processed only in your browser.',
    'CVE KONTROLÜ': 'CVE CHECKS', '◉ Yerel analiz': '◉ Local analysis', '↗ JSON raporu': '↗ JSON report', '⌘ Komut satırı desteği': '⌘ Command-line support',
    'Kural doğrulaması: 28.09.2026': 'Rules verified: 2026-09-28',
    'İlk iki CVE için aktif istismar bildirildi.': 'Active exploitation reported for the first two CVEs.',
    'Citrix, etkilenen cihazların güncellenmesini öneriyor. Bu kontrol ön koşulları değerlendirir; cihazın ihlal edilip edilmediğini belirlemez.': 'Citrix recommends updating affected appliances. This assessment checks prerequisites; it does not determine whether an appliance has been compromised.',
    'Bülteni incele ↗': 'Read the bulletin ↗', 'Kontrol alanı': 'Assessment workspace', 'Cihaz bilgileri': 'Appliance details', 'YEREL': 'LOCAL',
    'NetScaler sürümü': 'NetScaler version', 'Gerekli': 'Required', 'Örn. 14.1-60.21': 'e.g. 14.1-60.21', 'Build numarası veya': 'Build number or', 'çıktısı.': 'output.',
    'Sürüm ailesi': 'Edition', 'Cihazın ürün ailesini doğrulayın; güncelleme eşikleri farklıdır.': 'Verify the appliance edition; update thresholds differ.',
    'Yapılandırma': 'Configuration', 'Dosya seç ↗': 'Choose file ↗',
    'ns.conf veya show ns runningConfig çıktısını buraya yapıştırın…': 'Paste ns.conf or show ns runningConfig output here…',
    'UTF-8 metin · En fazla 10 MiB · Sunucuya gönderilmez': 'UTF-8 text · Up to 10 MiB · Never uploaded',
    'Bu, cihazın': 'This is the appliance’s', 'tam ve güncel': 'complete and current', 'yapılandırmasıdır.': 'configuration.',
    'TCP / Enhanced ISN çıktısı': 'TCP / Enhanced ISN output', 'İsteğe bağlı': 'Optional',
    'CVE-2026-88778 kontrolünü tamamlamak için': 'To complete the CVE-2026-88778 check, provide', 'çıktısı': 'output',
    'Kontrolü çalıştır': 'Run assessment', 'Örnek veriyle dene': 'Try sample data', 'Temizle': 'Clear',
    'Veriler depolanmaz. Raporlar ham yapılandırmayı, IP adreslerini ve nesne adlarını içermez.': 'Data is not stored. Reports exclude raw configuration, IP addresses and object names.',
    'Kontrol sonuçları': 'Assessment results', 'JSON indir ↓': 'Download JSON ↓', 'ANALİZE HAZIR': 'READY TO ASSESS',
    'Önce cihaz bilgilerinizi ekleyin.': 'Start with your appliance details.',
    'Sürüm eşikleri, yapılandırma bulguları ve önerilen aksiyonlar burada görünecek.': 'Version thresholds, configuration findings and recommended actions will appear here.',
    '01   Sürüm karşılaştırması': '01   Version comparison', '02   CVE ön koşulları': '02   CVE prerequisites', '03   Aksiyon raporu': '03   Action report',
    'Bir cihaz / bir yapılandırma üzerinden değerlendirilir.': 'Assesses one appliance and one configuration at a time.',
    '8 CVE / BÜLTEN KAPSAMI': '8 CVEs / BULLETIN SCOPE', 'Sonuçları filtrele': 'Filter results', 'Tüm sonuçlar': 'All results',
    'Aksiyon gerekli': 'Action required', 'İnceleme gerekli': 'Review required', 'Eşik / ön koşul tamam': 'Threshold / prerequisite resolved',
    'Sonuçlar, girilen veriler ve bülten kapsamıyla sınırlıdır. Sürüm eşiğinin karşılanması, geçmiş bir ihlali dışlamaz.': 'Results are limited to the supplied data and this bulletin. Meeting the version threshold does not rule out a previous compromise.',
    'YÖNTEM': 'METHOD', 'Üç adımda kontrol': 'Assess in three steps', 'Salt okunur çıktıları alın.': 'Collect read-only outputs.',
    'NetScaler CLI üzerinde': 'In the NetScaler CLI, run', 've': 'and', 'komutlarını çalıştırın.': 'commands.',
    'Sürümü ve yapılandırmayı ekleyin.': 'Add the version and configuration.',
    'FIPS / NDcPP ailesini seçin. Eksik veriyle yapılan kontrollerde belirsiz sonuçları ayrıca doğrulayın.': 'Select the correct FIPS / NDcPP edition. Verify uncertain results separately when the supplied data is incomplete.',
    'Bulgulara göre aksiyon alın.': 'Act on the findings.',
    'Uygun sürüme geçin ve Enhanced ISN ayarını doğrulayın. HA çiftindeki her düğümü ayrı kontrol edin.': 'Update to the appropriate build and verify Enhanced ISN. Assess each node in an HA pair separately.',
    'BÜLTENDEKİ DÜZELTME EŞİKLERİ': 'BULLETIN FIX THRESHOLDS', 'Sürüm referansı': 'Version reference',
    'Ürün ailelerine göre minimum düzeltme sürümü': 'Minimum fixed builds by product edition', 'Ürün ailesi': 'Product edition',
    'Aynı dal ve ürün ailesindeki daha yeni build’ler dahildir. TCP ISN kontrolü ayrıca değerlendirilir.': 'Later builds in the same branch and edition are included. TCP ISN is assessed separately.',
    'Enhanced ISN dokümantasyonu ↗': 'Enhanced ISN documentation ↗', '· Bağımsız topluluk aracı': '· Independent community tool',
    'Citrix / NetScaler ile resmî bağlantısı yoktur.': 'Not officially affiliated with Citrix / NetScaler.',
    'Kontrolü çalıştırmak için JavaScript’i etkinleştirin veya Node.js komut satırı aracını kullanın.': 'Enable JavaScript to run the assessment, or use the Node.js command-line tool.',
    'Bu filtrede sonuç bulunmuyor.': 'No results match this filter.', 'Saptandı': 'Detected', 'Belirsiz / doğrulama gerekli': 'Unknown / verification needed', 'Saptanmadı': 'Not detected',
    'Ön koşul': 'Prerequisite', 'Satır': 'Line', 'NetScaler sürümünü girin.': 'Enter the NetScaler version.',
    'Metin alanları en fazla 10 MiB olabilir.': 'Text fields must not exceed 10 MiB.', 'UTF-8 metin kullanın.': 'Use UTF-8 text.',
    'Öncelikli aksiyon gerekiyor.': 'Priority action is required.', 'Bazı kontroller için doğrulama gerekiyor.': 'Some checks need verification.',
    'Sürüm eşiği ve ISN kontrolü tamamlandı.': 'Version threshold and ISN checks completed.', 'Sürüm belirlenemedi': 'Version unknown', 'Hedef': 'Target',
    'Üretici doğrulaması': 'Vendor verification', 'Tam yapılandırma beyanı': 'Declared complete configuration', 'Kısmi / belirsiz yapılandırma': 'Partial / uncertain configuration',
    'Deneniyor: sentetik örnek yapılandırma': 'Using synthetic sample configuration', 'Yalnızca yerel bellekte': 'In local memory only',
    'Dosya sınırı 10 MiB.': 'File limit: 10 MiB.', 'Dosya UTF-8 metin olmalıdır.': 'The file must contain UTF-8 text.', 'Dosya yüklenemedi.': 'Could not load the file.',
    'Sürüm eşiği karşılandı': 'Version threshold met', 'Ön koşul saptanmadı': 'Prerequisite not detected', 'ISN önlemi etkin': 'ISN mitigation enabled',
    'Kimlik doğrulamasız komut çalıştırma': 'Unauthenticated command execution', 'DTLS bellek taşması': 'DTLS memory overflow',
    'URL politikası atlatma': 'URL policy bypass', 'Gateway / AAA bellek taşması': 'Gateway / AAA memory overflow', 'Oracle LB bellek taşması': 'Oracle LB memory overflow',
    'HTTP dışı L7 bellek taşması': 'Non-HTTP L7 memory overflow', 'TCP sıra numarası tahmini': 'TCP sequence number prediction',
    'Geçersiz sürüm ailesi.': 'Invalid edition.', 'Sürüm okunamadı; 14.1-73.37 veya show ns version çıktısını girin.': 'Could not parse the version; enter 14.1-73.37 or show ns version output.',
    'Geçersiz build numarası.': 'Invalid build number.', 'Bu dal / sürüm ailesi bültendeki eşik tablosunda yok; üretici doğrulaması gerekli.': 'This branch / edition is not in the bulletin threshold table; vendor verification is required.',
    'Bültendeki düzeltme eşiğinin altında.': 'Below the fixed-build threshold in the bulletin.', 'Bu dal için bültendeki düzeltme eşiği karşılandı.': 'The bulletin fixed-build threshold is met for this branch.',
    'Tam ve okunabilir yapılandırma doğrulanmadı; eşleşme yokluğu güvenli sonuç sayılmaz.': 'A complete, readable configuration was not confirmed; absence of a match does not establish safety.',
    'Bültende ek yapılandırma koşulu belirtilmiyor.': 'The bulletin specifies no additional configuration prerequisite.',
    'DTLS vServer veya DTLS açık Gateway': 'DTLS vServer or Gateway with DTLS enabled', 'HTTP URL ifadesi': 'HTTP URL expression',
    'Bültendeki URL politikası ön koşulu ile HTTP/SSL örnekleri uyuşmuyor. Eşleşme yoksa politika incelemesi gerekir; ifade eşleşmesi de aktif bağlamayı kanıtlamaz.': 'The bulletin’s URL policy prerequisite does not match its HTTP/SSL examples. No match requires policy review; an expression match does not prove an active binding.',
    'HTTP dışı L7 / ALG / DNS64': 'Non-HTTP L7 / ALG / DNS64', 'NAT64 yapılandırması': 'NAT64 configuration',
    'L7 örnekleri kapsamlı bir protokol listesi değildir. DNS policy64 için DNS vServer bağlamasını, diğer L7 özelliklerini ayrıca inceleyin.': 'The L7 examples are not an exhaustive protocol list. Review DNS vServer bindings for DNS policy64 and other L7 features separately.',
    'TCP çıktısı ile yapılandırma tutarsız veya birden fazla ISN değeri var; güncel durumu doğrulayın.': 'TCP output conflicts with the configuration or contains multiple ISN values; verify the current state.',
    'TCP kullanan vServer': 'vServer using TCP', 'ISN önlemi etkin. Sürüm eşiğini de sağlayın.': 'ISN mitigation is enabled. Also meet the version threshold.',
    'show ns tcpparam ile doğrulayın. Gerekirse üretici talimatıyla Enhanced ISN Generation etkinleştirin; ayrıca sürümü güncelleyin.': 'Verify with show ns tcpparam. If needed, enable Enhanced ISN Generation following vendor guidance; also update the version.',
    'Bu bülten için sürüm eşiği karşılandı; geçmiş istismar durumunu bu kontrol belirlemez.': 'The version threshold for this bulletin is met; this check does not determine past exploitation.',
    'Sürüm ve ürün ailesini doğrulayın; desteklenen güncel sürüm için üreticiye başvurun.': 'Verify the version and edition; consult the vendor for a supported current build.',
    'Sürüm ve yapılandırma ön koşulu değerlendirmesi; istismar veya ihlal kanıtı değildir. Ham yapılandırma ve nesne adları rapora eklenmez.': 'Version and configuration prerequisite assessment; not evidence of exploitation or compromise. Raw configuration and object names are excluded from the report.'
  };
  const warningSuffixes = {
    'kapanmamış tırnak; negatif sonuçlar belirsiz sayıldı.': 'unclosed quote; negative results are treated as uncertain.',
    'değişiklik geçmişi algılandı; güncel runningConfig kullanın.': 'change history detected; use current runningConfig output.',
    'eksik komut.': 'incomplete command.', 'tamamlanmamış devam satırı.': 'incomplete continuation line.',
    'nesne adı eksik.': 'missing object name.', 'protokol türü okunamadı.': 'could not parse the protocol type.'
  };
  function translate(text, language) {
    if (language !== 'en' || typeof text !== 'string') return text;
    if (Object.hasOwn(en, text)) return en[text];
    const line = text.match(/^Satır (\d+): (.+)$/);
    if (line && Object.hasOwn(warningSuffixes, line[2])) return `Line ${line[1]}: ${warningSuffixes[line[2]]}`;
    const upgrade = text.match(/^([\d.-]+) veya aynı daldaki daha yeni uygun build sürümüne güncelleyin\.$/);
    if (upgrade) return `Update to ${upgrade[1]} or a later appropriate build in the same branch.`;
    const isn = text.match(/^Enhanced ISN: (enabled|disabled|unknown)\. CVE-2026-88778 için sürüm güncellemesine ek olarak TCP ayarını doğrulayın\.$/);
    if (isn) return `Enhanced ISN: ${isn[1]}. For CVE-2026-88778, verify the TCP setting in addition to updating the version.`;
    return text;
  }
  function localizeReport(report, language) {
    const walk = value => Array.isArray(value) ? value.map(walk) : value && typeof value === 'object'
      ? Object.fromEntries(Object.entries(value).map(([key, item]) => [key, walk(item)])) : translate(value, language);
    return { ...walk(report), language: language === 'en' ? 'en' : 'tr' };
  }
  return { translate, localizeReport };
});
