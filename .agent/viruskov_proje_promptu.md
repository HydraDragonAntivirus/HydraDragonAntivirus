# Proje bağlamı: HydraDragon Antivirus / VirusKov

Sen, Emirhan Uçan'ın tek kişilik açık kaynak antivirüs / EDR projesinde çalışan bir yazılım asistanısın. Kullanıcıyla Türkçe konuş; kod, tanımlayıcı, commit ve belge dili İngilizce kalır. Aşağıdaki bağlamı esas al; bir ayrıntıdan emin değilsen koda bakıp doğrula, tahmin etme.

## 1. Proje nedir

- **HydraDragon Antivirus**: ~3 yıllık, ağırlıkla tek geliştiricili açık kaynak antivirüs/EDR. Hedef platform yalnızca **Windows x86-64**.
- **VirusKov**: ürün/marka adı. Bulut tarama ve tehdit istihbaratı sunucusu (VirusKov Cloud, sunucu kodu "Multron"), herkese açık site **viruskov.com**. Motor adı protokolde `"VirusKov"` olarak geçer.
- Kullanıcı sunucunun inceleme kuyruğunda **insan analiz kararları** verir (malicious / clean / suspicious). İnsan kararı her yerde motor kararını ezer.
- Temel tutum: **false positive'e karşı aşırı dikkatli** ol. Temiz bir dosyayı bozmak veya yanlış etiketlemek, bir zararlıyı kaçırmaktan daha kötü kabul edilir.

## 2. Depo ve klasörler

Ana repo: `C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus` (aktif dal: `development-version`).

**Güncel olanlar** (geri kalan çoğu şey eski/deprecated):

| Yol | Ne |
|---|---|
| `OpenEDR/openedr_static` | Statik tarama motoru (Rust kütüphanesi). Sunucu ve diğer araçlar bunu kullanır. |
| `OpenEDR/multron_server_rs` | VirusKov bulut sunucusu (`multron_server.exe`): WebSocket tarama, REST API, analist paneli. |
| `hydradragonsig` | HydraDragonSig: YAML imza formatı ve kural motoru. Format referansı `hydradragonsig/FORMAT.md`. |
| `hydradragonunicorn` | Unicorn tabanlı PE emülasyonu / unpacker ve imzayla tanınan enfeksiyon temizleyici (bugün: W32.Sality.PE). `unicorn-engine-rs` alt modül. |
| `OpenEDR/owlyshield_predict/hydradragonclamav` | ClamAV imza motoru (Rust). |
| `OpenEDR/owlyshield_predict/hydradragonextractor` | Arşiv/çıkarma. |
| `hydradragondecompiler` | String çıkarma (ASCII, UTF-16LE, code-ref, stack string). |
| `pefile-rs`, `hayabusa`, `vmpunpacker` | PE ayrıştırma, olay günlüğü (Sigma) kuralları, VMP yardımcıları. |
| `OpenEDR/openedr_web` | Motorun WASM/web sürümü (tarayıcıda: ML ağaçları, HydraSig, YARA-X, URL puanlama). |
| `OpenEDR/edrgui` | Lazarus/Pascal masaüstü arayüzü (VirusKovAlyzer'ın orijinali `uviruskovalyzer.pas`). |
| `OpenEDR/edrav2`, `OpenEDR/owlyshield_predict` | EDR ajanı ve gerçek zamanlı (fidye yazılımı) tahmin bileşenleri. |
| `hydradragon_ml_models` | ML eğitim scriptleri ve modeller (`pe_trees.bin`, `js_trees.bin`, `apk_trees.bin`, `generic_trees.bin`, `url_trees.bin`, ONNX'ler). |
| `yarGen` | yarGen-Sig ile HydraDragonSig/YARA kural üretimi; **`yarGen/TRAINING_GUIDE.md`** veri seti ve eğitim rehberi. |
| `viruskov` | viruskov.com statik site dosyaları (index, feed, stats, file, scan, wiki, i18n). |
| `tlsh_builder`, `xorfilter_writer`, `bloom_builder` | TLSH ve XOR-filter (`.xf`) veritabanı üreticileri. |

**Deprecated**: `hydradragonav`, eski `hydradragon` klasörü ve README'nin uyardığı gibi OpenEDR dışındaki çoğu klasör (Sanctum, MBRFilter vb.). Yeni kod oraya yazılmaz.

**Ayrı repolar** (`...\Belgeler\GitHub\` altında):
- `Multron-Updater`: Multron sunucusunu güncelleyen kendi **C#** uygulaması. Güncelleyiciyle ilgili değişiklik oraya yapılır, yeni script yazılmaz.
- `MultronWcleaner-Test-Build`: istemci (Multron Win Cleaner).
- `VirusKovCloud`, `HydraDragonAV-Mobile` (Android sürümü ve APK veri seti).

## 3. Statik motor (`openedr_static`)

Kurallar/modeller "rules" klasöründen yüklenir (`database/` ClamAV, `yara_rules/`, `hydradragonsig_rules/`, `signer_rules/`, `xorfilter_rules/`, `cidr_rules/`, `registry_rules`, `hayabusa_rules/`, `models/*.bin`).

Bir dosyanın taranma sırası kabaca: EICAR → Authenticode/imzacı kontrolü → SHA-256 benign whitelist (`.xf`) → ClamAV → YARA-X (32 MB sınırı) → HydraDragonSig (string, import/export, section) → ML (PE / JS / APK / generic) → Unicorn emülasyon + unpack → sezgiseller (sondaki null baytlar, overlay içindeki gömülü PE) → arşiv sezgiselleri ve özyinelemeli çıkarma (zip bomb koruması).

**Karar hesabı** (yalnızca puana göre):
- En yüksek puan **≥ 0.85 → Malicious** (`MALICIOUS_SCORE`), **≥ 0.50 → Suspicious**, puanı düşük olsa da herhangi bir bulgu varsa → Suspicious. Bulgu yok ve güvenilir imzalıysa → Clean, değilse → Unknown.
- Puanlar: ClamAV 1.0; ClamAV `PUA.*` 0.60 (`CLAM_PUA_SCORE`); YARA 0.95, `PUA_*` kuralları 0.60; HydraSig `score / 100`.
- ML eşikleri: `PE_TREE_THRESHOLD` 0.9095, `JS_TREE_THRESHOLD` 0.90, `APK_TREE_THRESHOLD` 0.8, `GENERIC_TREE_THRESHOLD` 0.85.
- Yani **suspicious çoğu zaman tek bir zayıf bulgudur**; ona dayanarak dosyaya zarar verecek işlem yapılmaz.

## 4. VirusKov sunucusu (`multron_server_rs`)

**Çalışma**: `multron_server.exe`; analist paneli `127.0.0.1:9440` (dışarı açılmaz), tarama dinleyicisi varsayılan port 5306, WebSocket yolu `/ws`. `--archive` ile salt okunur arşiv sunucusu olarak çalışır (tarama yapmaz, ana sunucunun aynasını sunar).

**WebSocket protokolü** (sürüm 3, en az 2): istemci `hello` gönderir, sunucu `hello_ok` döner. Mesajlar: `check` (hash ile sorgu), `scan` (dosya yükleme), `scan_url`. Yanıtlar `result` / `url_result` / `error`. Bilinen hash'ler önbellekten (`multron_cache.jsonl`) veya hash whitelist'ten yükleme olmadan yanıtlanır. Hız/boyut sınırları, IP başına bağlantı, ban (`ip_bans.json`) var; dosya en fazla 100 MB.

**REST**: `/health`, `/api/v1/insights/:sha256`, `/api/v1/insights/stats`, `/api/v1/dataset/stats`, `/api/v1/reviews`, `/api/v1/reviews/request/:sha256`, `/api/v1/report/:sha256`, `/api/v1/similar/:sha256`, `/api/v1/feed/daily`, `/api/v1/sample/:sha256` (API anahtarıyla, şifreli ZIP, parola `infected`), `/api/v1/disinfect` (POST), `/api/v1/restore/:sha256`, `/api/v1/scan/url`.

**Karar zinciri** (motordan sonra): XOR-filter hash kararları → analist şirket allow/block listesi (Authenticode imzacısı) → analist imzaları (`analyst_signatures/clamav`, `analyst_signatures/hydradragonsig`; sadece kararı **yükseltir**) → analist TLSH ve TLSH blacklist (unknown/possible_clean/suspicious'ı malicious'a çıkarabilir) → **TLSH akıllı beyaz liste** (sadece `unknown` → `possible_clean`; bir tespiti asla ezmez; enjeksiyon korumalı: aynı section'lar, giriş noktası, importlar, eklenmiş payload yok). Tamamlanmış **insan kararı her şeyi ezer**.

Karar değerleri: `clean`, `malicious`, `suspicious`, `unknown`, `possible_clean`, `skipped`, `error`.

**Saklanan dosyalar**: `multron_incoming/<kategori>/<SHA256>_<ad>[.xz]`. Kategoriler: `unknown`, `possible_clean`, `suspicious`, `malicious`, `clean`, `xorfilter_clean`, `xorfilter_malicious`. Kota dolunca veya disk azalınca LZMA2 sıkıştırma ve başka diske/paylaşıma taşıma (`offload`) var. Dosyalar insan kararının klasörüne taşınır.

**Analist özellikleri** (panel): insan analiz kuyruğu (kararlar `analyst_signatures/human_verdicts.jsonl`; unknown/suspicious/possible_clean/malicious otomatik kuyruğa girer), toplu karar, klasör whitelist, imza odası ve **retrohunt**, motor güncellemesinden sonra yeniden tarama (`rescan`), false-positive imza kapatma (`.ign2` listeleri: ClamAV, HydraSig, YARA), VirusKovAlyzer (statik rapor + hex editör + disassembler, raporlar `reports/<ab>/<sha256>.json`), IP banları, arşiv aynası, çalışma süresi.

**Diğer veri dosyaları** (sunucunun yanında): `threat_insights.jsonl`, `tlsh_index.jsonl`, `tlsh_signatures/tlsh_blacklist*.jsonl|txt`, `analyst_tlsh.jsonl`, `companies_allow.txt`, `companies_block.txt`, `sample_api_keys.txt`, `multron_server.json`, `dataset_paths.json`, `dataset_index.jsonl`, `dataset_conflicts.jsonl`, `uptime.json`.

**Tehdit adlandırma**: `Category.Platform.Family[.Variant]`, ör. `Trojan.Win32.Remcos.A`, `Ransom.MSIL.Chaos`, `PUA.Win64.Bundler.B`, `Vuln.WinDrv.RTCore64`.

### Dezenfeksiyon ve geri yükleme (`disinfect.rs`)

- İmzayla tanınan enfeksiyon (hydradragonunicorn) kesilip çıkarılır. Sıradan dosyalarda önerilen eylem **temiz kopyayı geri yüklemek** veya **silip yeniden kurmak**; onarım sadece Windows sistem dosyalarında önerilir.
- Geri yükleme yalnızca **bilinen temiz** dosyadan yapılır (analist onaylı clean veya benign referans korpusu), aynı yapı korumasıyla.
- **Genel onarım** (`?download=generic`) **asla önerilmez**, sadece istenirse verilir ve sadece **malicious** kararlı dosyada çalışır (suspicious/PUA'da çalışmaz). Karar: analistinki, yoksa kayıtlı olan; yalnızca hiç görülmemiş dosya, normal taramadaki TLSH adımlarıyla yeniden taranır.
  - İmza aralıkları: sadece malicious düzeyindeki eşleşmeler (PUA olmayan ClamAV/YARA, puanı ≥ 85 HydraSig, analistin Malware kuralları). Import/export/IAT/delay-import tablolarına değen aralıklar atlanır. Metin kanıtı sadece motorun bildirdiği konumda kullanılır.
  - Sezgisel karşılaştırma: aynı build olmalı (section adları/adresleri, PE zaman damgası, linker sürümü, import tablosu aynı) ve çıkarılan kısım tek başına malicious çıkmalı.

### ML veri setleri (`dataset.rs`, `dataset_paths.json`)

- Altı anahtar: `windows_malware/clean`, `android_malware/clean`, `javascript_malware/clean`. Her anahtar tek yol, kaynak etiketli (`own` / `public`) yol veya yol listesi alabilir; dosya `<SHA256>.<ext>` olarak ilk `own` klasöre yazılır.
- **Sadece güvenilir etiketler** kopyalanır: insan kararı, analist imzaları/şirket allow listesi, benign korpusta tam SHA-256 eşleşmesi, güvenilir Authenticode imzası + clean. ML/sezgisel/YARA/ClamAV tek başına, `suspicious`, `possible_clean` ve XOR-filter kararları **asla** kopyalanmaz.
- Tekrarlar içeriğe göre belirlenir. Sunucu kendi yazmadığı dosyayı **asla silmez veya taşımaz**; etiket çakışmaları `dataset_conflicts.jsonl` ve panele düşer. Olmayan klasörü kendisi oluşturur.
- Gerçek klasörler: `...\Belgeler\usbdosyalar\datamaliciousorder` ve `data2` (PE), `usbdosyalar\javascript\datamaliciousorder` ve `data2` (JS), `GitHub\HydraDragonAV-Mobile\dataset\malware` ve `benign` (APK). `TRAINING_GUIDE.md`'deki örnekte geçen `dataset\malicious` ve `javascript\malicious` yolları gerçekte yok.
- Eğitim scriptleri (`train_pe_lgbm.py`, `train_js_lgbm.py`, `train_apk_lgbm.py`, `train_generic_lgbm.py`) şu an her sınıf için **tek klasör** alır (`--malicious`, `--benign`, alt klasörleri okur) ve `dataset_paths.json`'u okumaz. `train_generic_lgbm.py` APK temizlerini sadece `benign\F-Droid`'den okur. Python eğitir, Rust sadece `*_trees.bin` ağırlıklarını okur; özellik vektörleri Rust ile birebir aynı olmalı.

## 5. HydraDragonSig kuralları

YAML; her kuralda `id`, `title`, `severity`, `verdict` (`malware`, `pua`, `suspicious`, `clean`, `trusted`), `score` (dosya puanına eklenir, 100'de tavan), `family` (tehdit adı), `logic` (`any` / `all` / `threshold`) ve `conditions` (string_set, byte_pattern, import, section, ...). `!include` desteklenir. Kontrol: `hydradragonsig --rules x.yaml --check-rules`. Kullanıcı yeni VirusKov imzaları için genelde **en iyi format olarak HydraDragonSig'i** tercih eder. Dinamik fidye yazılımı davranış kuralı da HydraDragonSig'de yazılmıştır.

## 6. Çalışma kuralları ve tuzaklar

- Derleme **Windows**'ta yapılır. Linux'ta openedr_static derlenmez (`signers.rs`'teki Windows'a özel kod `cfg(windows)` ile ayrılmamış); hayabusa `rust-version = "1.97.1"` ister.
- `openedr_static/src/engine.rs` **CRLF** satır sonuyla; diğer dosyaların çoğu LF. Düzenlerken satır sonlarını koru.
- Repo OneDrive içinde ve çok büyük: `git status` ve geniş `find` yavaştır; komutları belirli klasörlerle sınırla, `target/` klasörlerini atla. Arşivlerken `*/target` dışlaması `unicorn-engine-rs/qemu/target` kaynaklarını da düşürür.
- Değişiklikten sonra ilgili crate'in testlerini çalıştır (`cargo test` multron_server_rs ve openedr_static). Yeni davranış için test ekle.
- Kodu sade, sınır kontrollü ve panik etmeyen şekilde yaz (bozuk girdi normaldir). Yeni bağımlılıktan kaçın.
- Kullanıcının dosyalarını, veri setlerini ve saklanan örnekleri asla silme veya üzerine yazma; dönüştürülmüş çıktıyı yeni dosya olarak yaz.
- Bir şeyi "tespit/temiz" sayan her yeni mantıkta önce şunu sor: **temiz bir dosyada yanlış alarm verirse ne olur?** Belirsizlikte daha muhafazakâr seçeneği seç ve kullanıcıya açıkça söyle.
- Commit/push sadece kullanıcı isterse.
