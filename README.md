# NetScaler Check

Citrix NetScaler ADC / Gateway için **CTX697096 · CVE-2026-88771–88778** sürüm ve yapılandırma kontrol aracı. Node.js komut satırı aracı ve Türkçe GitHub Pages arayüzü aynı kontrol motorunu kullanır. Haricî paket kurulumu gerekmez.

Bu araç müşteri tarafından yönetilen NetScaler cihazlarını değerlendirir. Exploit çalıştırmaz, cihaza bağlanmaz ve yapılandırmayı değiştirmez. Ön koşul eşleşmesi bir ihlal kanıtı değildir; sürüm eşiğinin karşılanması da geçmiş bir ihlali dışlamaz.

## Hızlı kullanım

Node.js 22 veya üzeri gerekir. Yetkili NetScaler CLI oturumunda aşağıdaki salt okunur komutların çıktılarını alın:

```text
show ns version
show ns runningConfig
show ns tcpparam
```

Çıktıları UTF-8 dosyaları olarak, örneğin Git tarafından dışlanan `private/` klasöründe tutun. HA çiftindeki her düğümü ayrı değerlendirin. `ns.conf` kayıtlı yapılandırmadır; canlı durumdan farklı olabilir. Güncel `show ns runningConfig` çıktısını tercih edin.

```powershell
node scripts/check.cjs --version 14.1-60.21 --edition standard --config private/ns.conf --tcp-params private/tcp.txt --complete
```

Dosyadan sürüm okuma ve JSON raporu:

```powershell
node scripts/check.cjs --version-file private/version.txt --edition fips --config private/ns.conf --tcp-params private/tcp.txt --complete --json
```

`--edition standard|fips|ndcpp` cihazdaki ürün ailesiyle aynı olmalıdır. Otomatik aile tespiti yapılmaz. `--complete` yalnızca tam ve güncel tek cihaz çıktısında kullanılmalıdır. Kısmi dosyada bu bayrağı kullanmayın. Config veya TCP çıktısı yoksa ilgili kontroller belirsiz kalır. Dosya başına sınır 10 MiB; UTF-16 dosyalarını önce UTF-8’e dönüştürün.

Sentetik örnek:

```powershell
node scripts/check.cjs --version 14.1-60.21 --config examples/demo.conf --complete
```

Çıkış kodları: **0** = sürüm eşiği / kontrol edilen ön koşullar tamam, **1** = aksiyon gerekli, **2** = inceleme gerekli, **3** = girdi/çalışma hatası. Bir aksiyon ile belirsizlik birlikte varsa 1 döner. 0, genel bir güvenlik veya ihlalden arınmışlık garantisi değildir.

## Web arayüzü

```powershell
node scripts/serve.cjs
```

Tarayıcıda `http://127.0.0.1:4173` adresini açın. Sürüm ve yapılandırma girin veya **Örnek veriyle dene** düğmesini kullanın. Sonuçlar filtrelenebilir, CVE satırları açılarak kanıt satırları incelenebilir ve JSON raporu indirilebilir. Veri değişirse önceki rapor geçersiz kılınır.

Üst menüdeki **TR / EN** düğmeleriyle Türkçe ve İngilizce arasında geçiş yapın. Form, açıklamalar, bulgular, uyarılar ve indirilen JSON raporunun açıklama alanları seçilen dili kullanır. Dil değişiminde girilen yapılandırma, sonuçlar ve filtre korunur. Paylaşılabilir İngilizce bağlantı: `http://127.0.0.1:4173/?lang=en`; Türkçe: `?lang=tr`. Tercih URL’de tutulur, cihaz verileri URL’ye eklenmez. CLI çıktısı Türkçe kalır; makine durum kodları her iki web dilinde de aynıdır.

Tüm analiz tarayıcıda yapılır. Analitik, CDN, uzak font, fetch veya localStorage kullanılmaz. CSP, uygulamanın ağ bağlantılarını kapatır. GitHub Pages sayfanın statik dosyalarını servis eder; kaynak bağlantıları kullanıcı tıklarsa açılır. JSON çıktıları ham config, nesne adları, IP ve parolaları içermez; sürüm, bulgu ve satır numaraları içerir. Bu raporları da kurum politikanıza göre koruyun.

## GitHub Pages yayını

Hedef depo adı: **emrecantuzer/netscaler-check**. Yayın sonrası beklenen adres: `https://emrecantuzer.github.io/netscaler-check/`. Bu adres, depo oluşturulup iş akışı başarıyla tamamlandıktan sonra kullanılabilir.

1. GitHub’da `emrecantuzer` hesabıyla boş, public `netscaler-check` deposu oluşturun; README ekleme seçeneğini boş bırakın.
2. Bu klasörde aşağıdaki komutları çalıştırın. Yalnızca projeye ait dosyalar eklenir; cihaz çıktılarınızı eklemeyin.

   ```powershell
   git init -b main
   git add .gitignore package.json README.md site scripts tests examples .github
   git commit -m "Add NetScaler bulletin checker and GitHub Pages site"
   git remote add origin https://github.com/emrecantuzer/netscaler-check.git
   git push -u origin main
   ```

3. Depoda **Settings → Pages → Build and deployment → Source → GitHub Actions** seçin.
4. **Actions → Publish GitHub Pages → Run workflow** ile yayını başlatın. İlk push, Pages etkin değilken başarısız olmuşsa bu adım yeniden çalıştırır. Sonraki `main` push’ları otomatik yayınlanır.

İş akışı önce testleri çalıştırır, ardından sadece altı izinli web dosyasını `_site/` dizinine alır. Yapılandırma, raporlar ve test dosyaları Pages artifact’ına dahil edilmez. Uygulama göreli yollar kullandığı için `/netscaler-check/` alt yolunda çalışır.

## Kurallar ve sınırlar

| CVE | Kontrol |
| --- | --- |
| 88771 | Ek ön koşul yok; sürüm değerlendirilir. |
| 88772 | DTLS vServer veya VPN üzerinde açık DTLS; tam çıktıda VPN varsayılanı açık kabul edilir. Sonraki `set ... -dtls OFF` ilgili nesneye uygulanır. |
| 88773 | LB / CS / VPN / Authentication HTTP veya SSL vServer. |
| 88774 | HTTP URL ifadeleri işaretlenir. Bültenin koşulu ile örnekleri uyuşmadığı için eşleşme olmaması inceleme gerektirir; politika bağlaması ayrıca doğrulanmalıdır. |
| 88775 | VPN veya Authentication vServer. |
| 88776 | ORACLE türünde LB vServer. |
| 88777 | FTP vServer/service/serviceGroup/monitor, LSN FTP/RTSP ALG, DNS64 ve NAT64 belirtileri. DNS policy64 bağlamaları ve diğer L7 özellikleri elle incelenir; örneklerin yokluğu kesin negatif sonuç üretmez. |
| 88778 | Bültenin TCP türleri ile açıkça devre dışı Enhanced ISN birlikte aranır. Ayar yoksa belirsizdir. Düzeltme sürümünde bile devre dışı ISN ayrıca aksiyon olarak gösterilir. |

| Dal / ürün ailesi | Düzeltme eşiği |
| --- | --- |
| 14.1 Standard | 14.1-73.37 |
| 13.1 Standard | 13.1-64.23 |
| 14.1 FIPS | 14.1-73.37 |
| 13.1 FIPS / NDcPP | 13.1-37.279 |

Build numaraları sayısal karşılaştırılır; farklı dallar birbirine karşılaştırılmaz. Tabloda olmayan dallar (eski/EOL veya yeni dallar dahil) otomatik güvenli sayılmaz. Kural kümesi 28.09.2026 tarihinde doğrulandı; canlı bülten sorgulaması yapmaz.

Ayrıştırıcı bir NetScaler komut yorumlayıcısı değildir. Tırnaklı adlar, satır devamları ve `add`/`set` seçeneklerini işler; `rm`/`unset`/`unbind` içeren işlem geçmişlerini tam çıktı saymaz. Özel CLI sarmalayıcıları, karma cihaz çıktıları, devre dışı nesnelerin erişilebilirliği, politika etkin bağlamaları, ağ erişimi ve istismar göstergeleri kapsam dışıdır. Bozuk veya kesilmiş girdileri tam çıktı olarak işaretlemeyin.

Enhanced ISN için önce `show ns tcpparam` ile canlı durumu doğrulayın. Üretici, TCP yapılandırmasında `set ns tcpparam -enhancedISNgeneration ENABLED` ayarını tarif eder. Araç bu komutu çalıştırmaz. Güncelleme ve ayar değişikliklerini kendi değişiklik yönetiminize göre uygulayın.

## Doğrulama

```powershell
node --test
node scripts/build-site.cjs
```

Testler sürüm eşiklerini, FIPS/NDcPP ayrımını, nesne bazında DTLS/ALG durumlarını, ISN çelişkilerini, eksik veriyi, rapor gizliliğini ve CLI çıkışlarını kapsar. Build komutu temiz çalışma alanı bekler; mevcut `_site` üzerine yazmaz.

## Kaynaklar

- [Citrix güvenlik bülteni CTX697096](https://support.citrix.com/external/article/CTX697096)
- [NetScaler Enhanced ISN Generation](https://docs.netscaler.com/en-us/citrix-adc/current-release/system/tcp-configurations.html#enhanced-isn-generation)
- [Citrix ek bağlam ve ihlal göstergeleri](https://community.citrix.com/techzone-blogs/110_security-updates/netscaler-adc-and-netscaler-gateway-security-bulletin-for-cve-2026-88771-through-cve-2026-88778/)
- [GitHub Pages özel iş akışı dokümantasyonu](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages)

Bağımsız topluluk aracıdır; Citrix veya NetScaler’ın resmî ürünü değildir.
