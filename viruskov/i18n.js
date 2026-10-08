/**
 * VIRUSKOV Multilingual (i18n) Engine
 * Supported languages: Turkish ('tr'), English ('en')
 */

(function () {
  const STORAGE_KEY = 'viruskov_lang';

  const translations = {
    tr: {
      // Top Strip
      'top.active': 'VIRUSKOV CORE: TELEMETRY & ML ACTIVE',
      'top.arch': 'MİMARİ: HYBRID RING-0 EDR + GELİŞMİŞ ML MOTORU',
      'top.founder': 'KURUCU:',
      'top.repo': 'GITHUB REPO →',
      'top.soc_status': 'VIRUSKOV SOC INTELLIGENCE • WSS:5306 • ECS 9.5.4',
      'top.sync_rate': 'GÖZLEM: HER 8 SANİYEDE BİR OTOMATİK SENKRONİZE',

      // Navigation
      'nav.home': 'Ana Sayfa',
      'nav.scanner': 'Canlı Tarayıcı',
      'nav.threat_intel': 'Threat Intelligence',
      'nav.stats': '📊 İstatistikler & SOC',
      'nav.history': 'Tarihçe & Dürüst Kronoloji',
      'nav.evolution': 'Teknik Evrim',
      'nav.ransom': 'Fidye Yazılımı Kuralı',
      'nav.manifesto': 'Manifesto',
      'nav.mimari': 'Mimari',
      'nav.community': 'Ekip & İttifak',
      'nav.wiki': 'Wiki & Destek',
      'nav.wiki_docs': 'Wiki & Dokümantasyon',
      'nav.scan_file_btn': '⚡ DOSYA TARA',
      'nav.wiki_btn': 'WİKİ →',
      'nav.repo_btn': 'REPO ↗',
      'nav.stats_btn': '📊 İSTATİSTİKLER',
      'nav.project_lead': 'Proje Lideri:',

      // Stats Hero
      'stats.title': 'Tehdit Telemetrisi & Canlı İstatistikler',
      'stats.desc': 'VirusKov küresel telemetri ağı, tersine mühendislik motoru, entropi analizi ve davranışsal kurallarla elde edilen canlı tehdit metrikleri.',

      // Stat Cards
      'stat.total_hashes': 'Benzersiz SHA-256 Hash',
      'stat.observed_hashes': 'Gözlemlenen Benzersiz Hash',
      'stat.malicious': 'Engellenen Zararlı (Malicious)',
      'stat.suspicious': 'Şüpheli / Sezgisel (Suspicious)',
      'stat.clean': 'Doğrulanmış Temiz (Clean)',
      'stat.unknown': 'İmzasız / Bilinmeyen (Unknown)',

      // Ratio Panel
      'ratio.title': 'Global Tehdit Dağılım Oranları',
      'ratio.total_sightings': 'Toplam Gözlem:',
      'ratio.malicious': 'Zararlı (Malicious):',
      'ratio.suspicious': 'Şüpheli (Suspicious):',
      'ratio.clean': 'Temiz (Clean):',
      'ratio.unknown': 'Bilinmeyen (Unknown):',
      'spec.standard': 'VERİ STANDARDİZASYONU',
      'spec.engine': 'MOTOR MİMARİSİ',
      'spec.protocol': 'BULUT PROTOKOLÜ',
      'spec.origin': 'ORİJİN & GÜVENLİK',

      // History Panel
      'history.title': 'Yerel Oturum Tarama Geçmişi & Raporları',
      'history.desc': 'Bu tarayıcı üzerinden taranan dosyaların kaydedilen sonuçları, skorları ve ECS logları.',
      'history.export': '📥 JSON İndir',
      'history.clear': '🗑️ Geçmişi Temizle',
      'history.filter_all': 'Tümü',
      'history.filter_mal': '🚨 Zararlı',
      'history.filter_susp': '⚠️ Şüpheli',
      'history.filter_clean': '✅ Temiz',
      'history.filter_unk': 'ℹ️ Bilinmeyen',
      'history.search_ph': 'Dosya adı veya hash ara...',
      'history.th_time': 'Zaman',
      'history.th_name': 'Dosya Adı',
      'history.th_size': 'Boyut',
      'history.th_verdict': 'Karar',
      'history.th_score': 'Skor',
      'history.th_sig': 'Tespit İmzası / Detay',
      'history.th_hash': 'SHA-256',
      'history.th_action': 'İşlem',
      'history.empty': 'Henüz bu tarayıcıda taranmış dosya kaydı yok.',
      'history.empty_filter': 'Filtreye uygun dosya kaydı bulunamadı.',
      'history.modal_title': '📄 Tarama Rapor Detayı (ECS 9.5.4)',

      // Quick Hash Lookup
      'lookup.title': 'Anlık Telemetri Hash Sorgulayıcı (OpenTIP)',
      'lookup.desc': 'SHA-256 sorgulayarak VirusKov telemetri havuzundaki anlık kaydı kontrol edin.',
      'lookup.placeholder': '64 karakterli SHA-256 hash girin (örn: cf89be2f5702f70de92fbc861579d945c632a1c05d0ef60a9dfb24f2a818912c)...',
      'lookup.btn': 'SORGULA ↗',

      // Scanner Section (index.html & scan/index.html)
      'scan_page.title': 'VIRUSKOV | Canlı Tehdit Tarayıcısı & URL Analiz Masası',
      'scan_page.meta_desc': 'VirusKov EDR canlı dosya analizi, OpenTIP hash sorgulama ve saf Makine Öğrenimi (ML) + Dinamik Whitelist destekli yeni nesil URL tarayıcısı.',
      'scan_page.top_badge': '🛡️ %100 MAKİNE ÖĞRENİMİ (ML) + DİNAMİK WHITELIST',
      'scan_page.hero_title': 'VirusKov Canlı URL & Web Tehdit Taraması',
      'scan_page.hero_desc': 'Geleneksel imza tabanlı URL kara listeleri başkaları tarafından tekrar tekrar kullanıldığı ve meşru sitelere gereksiz yere virüs/phishing damgası vurup yüksek Yanlış Pozitif (False Positive - FP) ürettiği için VirusKov URL Tarayıcısı, statik imzaları tamamen terk etmiş; Makine Öğrenimi (ML), Dinamik Whitelist ve Domain Liveness (Aktiflik) mimarisine geçmiştir.',
      'scan_page.url_ph': 'URL veya alan adı girin (örn: https://example.com)...',
      'scan_page.url_btn': '⚡ TARA ↗',
      'scan_page.privacy_note': '🔒 Güvenlik & Yasal Uyarı: Sitelerin görünümleri kalıcı depolanmaz; yalnızca canlı DNS/HTTP durumu sorgulanır.',
      'scan_page.fp_report': 'FP/FN Bildirimi: viruskov@viruskov.com ↗',
      'scan_page.tab_url': '🔗 CANLI URL ANALİZİ (ML & WHITELIST)',
      'scan_page.tab_file': '⚡ DOSYA ANALİZİ (WEBSOCKET)',
      'scan_page.tab_hash': '🔍 HASH SORGULA (OPENTIP)',
      'scan_page.tab_history': '📊 TARAMA GEÇMİŞİ',
      'scan_page.history_title': 'Oturum Tarama Geçmişi & Loglar',
      'scan_page.history_clear': 'Geçmişi Temizle',
      'scan_page.th_time': 'Zaman',
      'scan_page.th_target': 'Hedef',
      'scan_page.th_type': 'Tür',
      'scan_page.th_verdict': 'Karar',
      'scan_page.th_score': 'Skor',
      'scan_page.th_detail': 'Detay',
      'scan_page.th_hash': 'SHA-256',
      'scan_page.support_title': '📬 Destek & Yanlış Pozitif / Negatif (FP/FN) Masası',
      'scan_page.support_desc': 'Eski imza listelerinin başkaları tarafından tekrar kullanılması ve meşru sitelere/dosyalara yanlış alarm (FP) üretmesi sebebiyle VirusKov; Makine Öğrenimi (ML) ve Dinamik Whitelist modelini benimsemiştir. Multron Server çekirdeğinde yerleşik URL tarayıcısı bulunmaktadır (özellikle PDF ve belgelere gömülü bağlantılara karşı tarama yapar). Sorularınız veya hatalı tespit bildirimleriniz için doğrudan viruskov@viruskov.com adresine yazabilirsiniz.',
      'scan_page.history_empty': 'Henüz taranmış kayıt yok.',
      'ti.tag': 'CANLI BULUT TARAYICI & TEHDİT İSTİHBARATI',
      'ti.title': 'VirusKov Global Telemetri & Zararlı Analiz Motoru',
      'ti.desc': 'Gerçek zamanlı bulut tarama motoru: PE başlık analizi, Q24 Shannon entropi eşlemesi ve küresel telemetri havuzu.',
      'ti.tab_scan': '⚡ CANLI DOSYA ANALİZİ',
      'ti.tab_lookup': '🔍 HASH SORGULA (OPENTIP)',
      'ti.tab_stats': '📊 TÜM İSTATİSTİKLER & GEÇMİŞ →',
      'ti.cloud_online': 'CLOUD ENGINE ONLINE (api.viruskov.com)',

      // Dropzone
      'drop.title': 'Analiz edilecek dosyayı buraya sürükleyin veya seçmek için tıklayın',
      'drop.types': 'PE, EXE, DLL, ZIP, APK, ELF veya şüpheli belgeler (Maksimum 50 MB)',
      'drop.tip': '💡 <b>İpucu:</b> Eklenti (AdBlock / uBlock) engellemesi veya bağlantı hatası yaşarsanız lütfen sayfayı <b>gizli sekmeden (Incognito)</b> açıp deneyin.',

      // Scanner Status Flow
      'scan.preparing': 'Dosya hazırlanıyor...',
      'scan.hashing': 'İstemci tarafında SHA-256 kriptografik özeti çıkarılıyor...',
      'scan.handshaking': 'VirusKov Cloud Engine ile el sıkışılıyor...',
      'scan.checking': 'Bulut önbelleği sorgulanıyor...',
      'scan.checking_detail': 'Veritabanında anlık hash eşleşmesi aranıyor...',
      'scan.queuing': 'Statik analiz için sıra alınıyor...',
      'scan.queuing_detail': 'Derin PE başlık ayrıştırma ve YARA kuralları için yükleme izni istendi...',
      'scan.uploading': 'Dosya aktarılıyor...',
      'scan.deep_scanning': 'Derin analiz yapılıyor...',
      'scan.deep_detail': 'VirusKov EDR motoru PE bölümlerini, entropiyi ve davranışsal imzaları analiz ediyor...',
      'scan.stopped': 'Tarama durduruldu',
      'scan.conn_error': 'Bağlantı hatası',
      'scan.conn_error_desc': 'api.viruskov.com WebSocket uç noktasına ulaşılamadı. Eklenti (AdBlock / uBlock) engellemesi yaşıyorsanız lütfen sayfayı gizli sekmeden (Incognito) açıp tekrar deneyin.',
      'scan.conn_closed': 'Bağlantı kapandı',
      'scan.conn_closed_desc': 'Sunucu oturumu sonlandırdı. Sorun devam ederse lütfen gizli sekmeden (Incognito) deneyin.',
      'scan.invalid_url': 'Lütfen geçerli bir URL veya alan adı girin.',
      'scan.invalid_format': 'Geçersiz URL formatı.',
      'scan.url_analyzing': 'URL Makine Öğrenimi Modeli ile Analiz Ediliyor...',
      'scan.url_doh_detail': 'Cloudflare DoH ile DNS A kaydı ve HTTP liveness sorgulanıyor...',
      'scan.url_ml_eval': 'Tranco Whitelist ve Makine Öğrenimi öznitelikleri değerlendiriliyor...',
      'scan.badge_malicious_url': '🚨 MALICIOUS (ZARARLI URL)',
      'scan.badge_suspicious_url': '⚠️ SUSPICIOUS (ŞÜPHELİ ANOMALİ)',
      'scan.badge_clean_wl': '✅ CLEAN (DOĞRULANMIŞ WHITELIST)',
      'scan.badge_clean_benign': '✅ CLEAN (DOĞRULANMIŞ TEMİZ)',
      'scan.badge_unknown': 'ℹ️ UNKNOWN (LİSTEDE YOK / İMZASIZ)',
      'scan.liveness_active': '🌐 SİTE AKTİF (DNS: OK / HTTP: ONLINE)',
      'scan.liveness_inactive': '💤 SİTE PASİF VEYA ERİŞİLEMEZ',
      'scan.report_fp': '📩 Hatalı Tespit (FP/FN) Bildir',
      'scan.lbl_target': 'Hedef:',
      'scan.lbl_domain': 'Alan Adı:',
      'scan.lbl_protocol': 'Protokol:',
      'scan.lbl_entropy': 'Shannon Entropisi:',
      'scan.breakdown_title': '🛡️ Güvenlik Motorları ve ML Analiz Sonuçları',
      'scan.eng_ml': 'VirusKov ML Core Engine',
      'scan.eng_ml_cat': 'Derin Öğrenme',
      'scan.eng_wl': 'Dynamic Whitelist Verifier',
      'scan.eng_wl_cat': 'Sıfır-FP İtibar',
      'scan.eng_live': 'Domain Liveness Inspector',
      'scan.eng_live_cat': 'DNS DoH & HTTP Sondası',
      'scan.eng_homo': 'Homograph & Punycode Shield',
      'scan.eng_homo_cat': 'IDN Saldırı Kalkanı',
      'scan.eng_shannon': 'Statistical Shannon Classifier',
      'scan.eng_shannon_cat': 'Entropi Modellemesi',
      'scan.eng_antifp': 'Anti-FP Guard (Sıfır Eski İmza)',
      'scan.eng_antifp_cat': 'Sıfır Statik Kural Filtresi',
      'scan.st_malicious': 'Zararlı',
      'scan.st_suspicious': 'Şüpheli',
      'scan.st_clean': 'Temiz',
      'scan.st_unknown': 'Bilinmeyen',
      'scan.st_verified': 'Doğrulandı',
      'scan.st_unlisted': 'Listede Yok (ML İncelendi)',
      'scan.st_active': 'Site Aktif & Çevrimiçi',
      'scan.st_inactive': 'Pasif / Erişilemez',
      'scan.st_homo_detected': 'Homograf Tespit Edildi',
      'scan.st_clean_script': 'Temiz Karakter',
      'scan.st_normal': 'Olağan',
      'scan.st_antifp_passed': 'Geçti (Eski İmza Yok)',
      'scan.max_size_alert': 'Maksimum dosya boyutu 50 MB.',
      'scan.wss_connecting': 'WSS bağlantısı kuruluyor...',
      'scan.lbl_file': 'Dosya',
      'scan.lbl_size': 'Boyut',
      'scan.lbl_type_url': 'URL',
      'scan.lbl_type_file': 'DOSYA',
      'scan.file_fp_note': 'Hatalı tespit (FP/FN) durumunda raporlayın:',
      'lookup.alert_sha': 'Lütfen geçerli bir 64 karakterli SHA-256 girin.',
      'lookup.querying': 'Sorgulanıyor...',
      'lookup.score': 'Skor:',
      'lookup.sig': 'İmza:',
      'lookup.prevalence': 'Yayılım:',
      'lookup.sightings': 'gözlem',
      'lookup.unknown_note': 'ℹ️ UNKNOWN • Bu hash henüz telemetri havuzunda görülmemiş.',
      'lookup.conn_err': 'Bağlantı hatası: ',

      // Results
      'res.malicious_badge': '🚨 MALICIOUS (ZARARLI YAZILIM)',
      'res.suspicious_badge': '⚠️ SUSPICIOUS (ŞÜPHELİ / SEZGİSEL)',
      'res.clean_badge': '✅ CLEAN (DOĞRULANMIŞ TEMİZ)',
      'res.unknown_badge': 'ℹ️ UNKNOWN (BİLİNMEYEN DOSYA - İMZA EŞLEŞMESİ YOK)',
      'res.threat_sig': 'Tespit İmzası:',
      'res.stat_breakdown': '📊 Statik Analiz & Telemetri Dağılımı',
      'res.static_parsing': 'Statik Ayrıştırma:',
      'res.sig_status': 'İmza Durumu:',
      'res.telemetry_status': 'Telemetri Durumu:',
      'res.scan_duration': 'Tarama Süresi:',
      'res.static_detail': 'Statik Detay / Çıkarım:',
      'res.filename': 'Dosya Adı:',
      'res.filesize': 'Boyut:',
      'res.engine': 'Motor:',
      'res.verdict': 'Karar:',
      'res.ecs_standard': 'Standart:',
      'res.telemetry_query_btn': 'TELEMETRİDE SORGULA →',

      // Footer
      'footer.copy': '© 2026 <b>VIRUSKOV</b> • Açık Kaynak Kurumsal EDR & Antivirüs Sistemi.',
      'footer.lead': 'Kurucu & Proje Lideri: <b>Emirhan Uçan</b>',

      // Wiki Specific
      'wiki.top_engine': 'VIRUSKOV WIKI &bull; MOTOR: PTM / PATTERNSMATCHING v2',
      'wiki.top_focus': 'ODAK KURAL: <span style="color: var(--accent-red);">MLE_RANSOM_BEHAVIOR</span> &bull; baseType 1000008',
      'wiki.top_back': '&larr; ANA SAYFA',
      'wiki.nav_kunya': 'Künye',
      'wiki.nav_mimari': 'Mimari',
      'wiki.nav_anatomi': 'Anatomi',
      'wiki.nav_suzgecler': 'Süzgeçler',
      'wiki.nav_sayac': 'Sayaç',
      'wiki.nav_entropy': 'Entropi',
      'wiki.nav_kernel': 'Kernel',
      'wiki.nav_yanit': 'Yanıt',
      'wiki.nav_neden': 'Neden Mükemmel',
      'wiki.nav_sinirlar': 'Sınırlar',
      'wiki.nav_sss': 'SSS',
      'wiki.btn_stats': '📊 İSTATİSTİKLER',
      'wiki.btn_home': 'ANA SAYFA',
      'wiki.btn_support': 'DESTEK',
      'wiki.btn_repo': 'REPO',
      'wiki.btn_inspect_code': 'KAYNAK KODU İNCELE',
      'wiki.btn_back_home': '&larr; VIRUSKOV ANA SAYFA',
      'wiki.btn_top': 'BAŞLIĞA DÖN',
      'wiki.toc_title': '&#9642; İÇİNDEKİLER',
      'wiki.toc_1': '1 &mdash; Künye',
      'wiki.toc_2': '2 &mdash; Bir Cümlede',
      'wiki.toc_3': '3 &mdash; Neden Davranış',
      'wiki.toc_4': '4 &mdash; Uçtan Uca Mimari',
      'wiki.toc_5': '5 &mdash; PTM Motoru',
      'wiki.toc_5_1': '5.1 &mdash; Yönergeler',
      'wiki.toc_5_2': '5.2 &mdash; Operasyonlar',
      'wiki.toc_5_3': '5.3 &mdash; Joker Eşleme',
      'wiki.toc_6': '6 &mdash; Kural Anatomisi',
      'wiki.toc_6_1': '6.1 &mdash; Aşama 1: Okuma',
      'wiki.toc_6_2': '6.2 &mdash; Aşama 2: Aday',
      'wiki.toc_6_3': '6.3 &mdash; Aşama 3: Değerlendirme',
      'wiki.toc_6_4': '6.4 &mdash; Aşama 4: Karar',
      'wiki.toc_6_5': '6.5 &mdash; Aşama 5: Temizlik',
      'wiki.toc_7': '7 &mdash; Dokuz Süzgeç',
      'wiki.toc_8': '8 &mdash; distinctCounter',
      'wiki.toc_9': '9 &mdash; Dosya Alanları',
      'wiki.toc_10': '10 &mdash; Shannon Entropisi',
      'wiki.toc_11': '11 &mdash; Beyaz Liste',
      'wiki.toc_12': '12 &mdash; Kernel Tarafı',
      'wiki.toc_13': '13 &mdash; Neden İki Aşamalı',
      'wiki.toc_14': '14 &mdash; Yanıt Zinciri',
      'wiki.toc_15': '15 &mdash; Neden Mükemmel',
      'wiki.toc_16': '16 &mdash; Dürüst Sınırlar',
      'wiki.toc_17': '17 &mdash; Komşu Kurallar',
      'wiki.toc_18': '18 &mdash; Analist El Kitabı',
      'wiki.toc_19': '19 &mdash; SSS',
      'wiki.toc_20': '20 &mdash; Kaynak Haritası',
      'wiki.toc_home': '&larr; Ana Sayfa',
      'wiki.toc_support': 'Destek &amp; Bağış',
      'wiki.crumb': '<a href="../index.html">VIRUSKOV</a> / WIKI / TESPİT KURALLARI / <span style="color: var(--accent-red);">MLE_RANSOM_BEHAVIOR</span>',
      'wiki.article_title': 'MLE_RANSOM_<span class="hl">BEHAVIOR</span><br>Fidye Yazılımı Tespit Kuralının Tam Anatomisi',
      'wiki.article_sub': 'OpenEDR &times; Hydra Dragon çekirdeği &bull; PTM / PatternsMatching v2 politika motoru<br>Kural Kimliği: <span class="c-red">RANSOM_BEHAVIOR</span> &nbsp;|&nbsp; Yayın Olay Tipi: <span class="c-red">MLE_RANSOM_BEHAVIOR</span> &nbsp;|&nbsp; baseType: <span class="c-red">1000008</span><br>Politika Kaynağı: <code>OpenEDR/edrav2/iprj/edrdata/ptm.local.src</code> &nbsp;&bull;&nbsp; Satır 4636 &ndash; 5129',
      'wiki.lead': '<strong>MLE_RANSOM_BEHAVIOR</strong>, bir dosyanın hash\'ine, derleyicisine ya da paketleyicisine bakmaz. Çekirdekte gördüğü <strong>tek şey davranıştır</strong>: bir süreç, kullanıcının kişisel dosyalarına <strong>60 saniye içinde en az 3 ayrı hedefe</strong> yazıyor, yeniden adlandırıyor ya da siliyor; bu hedefler <strong>metin dosyası değil</strong> ve <strong>şifrelenmiş gibi yüksek entropili</strong> veri taşıyor. Bu üçlü &mdash; <em>kitle &times; hacim &times; içerik</em> &mdash; eşleştiği anda motor, saldırganın <strong>proses imajını karantinaya alır ve süreci anında öldürür</strong>. Bu sayfa, bunun her tek satırını, her tek süzgecini ve her bilinen sınırını açar.',
      'wiki.h2_1': '<span class="num">01</span> Künye',
      'wiki.h2_2': '<span class="num">02</span> Bir Cümlede',
      'wiki.h2_3': '<span class="num">03</span> Neden Bu Kural Bir İmza Değil, Bir Davranış Kuralı?',
      'wiki.h2_4': '<span class="num">04</span> Uçtan Uca Mimari: Olayın Yolculuğu',
      'wiki.h2_5': '<span class="num">05</span> Altyapı: PTM (PatternsMatching) Motoru',
      'wiki.h2_6': '<span class="num">06</span> Kuralın Anatomisi: 16 Madde, 5 Aşama',
      'wiki.h2_7': '<span class="num">07</span> Dokuz Süzgeç, Tek Tek',
      'wiki.h2_8': '<span class="num">08</span> <code>distinctCounter</code>: Kayan Pencerede Ayrı Değer Sayacı',
      'wiki.h2_9': '<span class="num">09</span> Dosya Nesnesi: Hangi Alana Bakılıyor?',
      'wiki.h2_10': '<span class="num">10</span> Shannon Entropisi: Q24 Sabit Nokta ile Hesaplama',
      'wiki.h2_11': '<span class="num">11</span> Beyaz Liste ve Uzantı Gözcüsü',
      'wiki.h2_12': '<span class="num">12</span> Kernel Tarafı: Hangi IRP, Hangi Olay?',
      'wiki.h2_13': '<span class="num">13</span> Neden İki Ara Olay Var?',
      'wiki.h2_14': '<span class="num">14</span> Yanıt Zinciri: Tespitten Sonrası Ne Olur?',
      'wiki.h2_15': '<span class="num">15</span> Neden Mükemmel Bir Ransomware Kuralı?',
      'wiki.h2_16': '<span class="num">16</span> Dürüst Sınırlar ve Bilinen Kusurlar',
      'wiki.h2_17': '<span class="num">17</span> Komşu Kurallar: Tek Başına Yaşamaz',
      'wiki.h2_18': '<span class="num">18</span> Analist El Kitabı',
      'wiki.h2_19': '<span class="num">19</span> Sık Sorulan Sorular',
      'wiki.h2_20': '<span class="num">20</span> Kaynak Haritası',
      'wiki.support_title': 'Bu Doküman Açık Kaynak Topluluğu İçin Yazıldı',
      'wiki.support_text': '<strong>MLE_RANSOM_BEHAVIOR</strong>, fidye yazılımlarının işletim sistemi çekirdeğindeki davranışlarını açığa çıkaran kritik bir savunma kalkanıdır. Sorularınız, hata bildirimleriniz veya katkılarınız için doğrudan proje liderine ulaşabilirsiniz:',
      'wiki.footer_copy': '&copy; 2026 <strong>VIRUSKOV</strong> &bull; Açık Kaynak Kurumsal EDR &amp; Antivirüs Sistemi.<br>Wiki: <strong>MLE_RANSOM_BEHAVIOR</strong> &mdash; kaynak kodla birebir doğrulanmış teknik dokümantasyon.<br>Kurucu &amp; Proje Lideri: <strong>Emirhan Uçan</strong>.',

      // Portal Sections (index.html)
      'hero.meta_badge': '<span>⚡</span> AÇIK KAYNAK SAVUNMA MANİFESTOSU & KURUMSAL EDR EVRİMİ',
      'hero.title': 'AÇIK KAYNAK ANTİVİRÜS TARİHİNDE BÖYLE BİR ZİRVE GÖRÜLMEMİŞTİ<br><span class="strike">GİZLİLİKLE GÜVENLİK DEVRİ BİTTİ</span><br><span class="highlight-red">ARTIK GERÇEK TEHDİTLERE KAFA TUTMA VAKTİ</span>',
      'hero.lead': 'Antivirüsler kapalı kutu olarak dağıtılıyor. Kullanıcı motorun ne yaptığını göremiyor, saldırgan görebiliyor. <em>Security by Obscurity</em> işi zorlaştırmıyor; sadece kullanıcıyı körleştiriyor.',
      'hero.subtext': 'İlk <em>Antivirus.sln</em> 15 Nisan 2023\'te açıldı. <strong>Turko Antivirus</strong> ve <strong>Hydra Dragon</strong>\'dan sonra aynı depoya <strong>Sanctum, OpenEDR, Owlyshield, Ring-0 Kernel ve Genelleştirilmiş Makine Öğrenimi</strong> girdi. Aradaki yol tarihleriyle aşağıda.',
      'hero.btn_history': 'DÜRÜST TARİHÇEYİ İNCELE &darr;',
      'hero.btn_ransom': 'MLE_RANSOM_BEHAVIOR KURALI &darr;',
      'hero.btn_wiki': 'DOKÜMANTASYON WİKİSİ &nearr;',
      'hero.btn_code': 'KAYNAK KODLARINI İNCELE &nearr;',
      'hero.stat1_lbl': 'Antivirus.sln Başlangıç Kabulü & Gelişim',
      'hero.stat2_val': '%100 AÇIK',
      'hero.stat2_lbl': 'Denetlenebilir C / C++ & Rust',
      'hero.stat3_lbl': 'BYOVD & Kernel Seviyesi Koruma',
      'hero.stat4_lbl': 'Statik PE Başlıkları + Dinamik Davranış',
      'ti.section_tag': 'CANLI TOPLULUK TELEMETRİSİ &amp; OPENTIP',
      'ti.section_title': 'VirusKov Threat Intelligence &amp; Hash Lookup',
      'ti.section_desc': 'VirusKov uç nokta tarayıcılarından toplanan gerçek zamanlı tehdit yayılım (prevalence) veritabanı. VirusKov küresel istihbarat ağında SHA-256 hash sorgulayın veya canlı telemetri akışını takip edin:',
      'hist.tag': 'BELGELİ & ŞEFFAF KRONOLOJİ',
      'hist.title': 'Viruskov\'un Gerçek ve Sansürsüz Tarihçesi',
      'hist.desc': 'Başlangıç bir Avast forumu hesabıydı. Sonra 1,5 yıl satranç, birkaç başarısız proje ve uzun bir Discord geçmişi geldi. Aşağıda ne olduğu, ne zaman olduğu ve bağlantıları ne olduğuyla birlikte var:',
      'hist.filter_all': 'TÜMÜ (Kronolojik)',
      'hist.filter_roots': 'Ön Geçmiş & Temeller (2019-2022)',
      'hist.filter_birth': '2023 Doğuş (Antivirus.sln & Hydra)',
      'hist.filter_alliances': '2024 Dostlar & İttifak',
      'hist.filter_kernel': 'Teknik & Kernel Çağı',
      'hist.search_ph': 'Tarih, kişi, motor veya link ara...',
      'evo.tag': 'KOD VE MOTOR MİMARİSİ ADIMLARI',
      'evo.title': 'Teknik Motor Evrimi: Hash\'ten Kernel EDR\'a',
      'evo.desc': 'Hash eşleştirmesiyle başladı; yerine kernel, kural motoru ve makine öğrenimi geldi. Süreç:',
      'manif.tag': 'TEHDİT VE DİRENİŞ ANALİZİ',
      'manif.title': 'Neden Kapalı Antivirüsler Çöküyor?',
      'manif.desc': 'Kutunun kapalı olması, içinde ne olduğunu göstermez. Viruskov\'daki fark şu:',
      'arch.tag': 'MÜHENDİSLİK ÇEKİRDEĞİ',
      'arch.title': 'Gerçek ve Repodan Güç Alan Özellikler',
      'arch.desc': 'Repo genelinde derlenmiş ve aktif olarak entegre edilmiş kurumsal modüller:',
      'team.tag': 'DOSTLAR, KATKIDA BULUNANLAR VE İTTİFAK',
      'team.title': 'Topluluk ve Dayanışma Masası',
      'team.desc': 'Bu depoya katkı verenler ve destekçiler:',
      'ransom.tag': 'TESPİT KURALLARI WİKİSİ &bull; ÖZEL DOKÜMANTASYON',
      'ransom.title': 'MLE_RANSOM_BEHAVIOR: Fidye Yazılımı Kuralının Tam Anatomisi',
      'ransom.desc': 'Bu projenin en iddialı kuralı, imza değil — davranıştır. Tamamını, her detayıyla, kaynak koddan doğrulanmış biçimde <a href="wiki/index.html" style="color: var(--accent-red); font-weight: 700;">VIRUSKOV Wiki</a> sayfamızda belgeledik. Aşağıda kuralın özeti ve mimari haritası var.',
      'wiki_sec.title': '<span class="text-cyan">▤</span> Viruskov Wiki &amp; Destek Masası',
      'wiki_sec.badge': 'KAYNAK KODLA DOĞRULANMIŞ',
      'wiki_sec.notice': '<strong>BİLGİLENDİRME:</strong> Daha önce bu bölümde bir bağış politikası yer alıyordu. Artık bağış <strong>hiçbir aracı platform, komisyon veya üçüncü taraf hesap üzerinden yürütülmüyor</strong>. Projeye katkıda bulunmak, ek kural yazmak, ya da finansal destek göstermek isteyen <strong>herkes</strong> doğrudan proje liderine ulaşır: <strong>viruskov@viruskov.com</strong>. Aracısız, komisyonsuz, şeffaf.',
      'wiki_sec.card_tag': 'WİKİ &bull; 20 BÖLÜM',
      'wiki_sec.card_title': 'MLE_RANSOM_BEHAVIOR — Tam Dokümantasyon',
      'wiki_sec.card_desc': 'Kuralın 16 maddesi, 5 aşaması, 9 süzgütü, distinctCounter semantiği, Q24 Shannon entropi hesabı, kernel IRP eşlemesi, yanıt zinciri, 12 gerekçe ve bilinen sınır/kusurların tam listesi. Kaynak satırlarıyla birlikte.'
    },

    en: {
      // Top Strip
      'top.active': 'VIRUSKOV CORE: TELEMETRY & ML ACTIVE',
      'top.arch': 'ARCHITECTURE: HYBRID RING-0 EDR + ADVANCED ML ENGINE',
      'top.founder': 'FOUNDER:',
      'top.repo': 'GITHUB REPO →',
      'top.soc_status': 'VIRUSKOV SOC INTELLIGENCE • WSS:5306 • ECS 9.5.4',
      'top.sync_rate': 'SIGHTINGS: AUTO-SYNCED EVERY 8 SECONDS',

      // Navigation
      'nav.home': 'Home',
      'nav.scanner': 'Live Scanner',
      'nav.threat_intel': 'Threat Intelligence',
      'nav.stats': '📊 Statistics & SOC',
      'nav.history': 'History & Timeline',
      'nav.evolution': 'Technical Evolution',
      'nav.ransom': 'Ransomware Rule',
      'nav.manifesto': 'Manifesto',
      'nav.mimari': 'Architecture',
      'nav.community': 'Team & Alliance',
      'nav.wiki': 'Wiki & Support',
      'nav.wiki_docs': 'Wiki & Documentation',
      'nav.scan_file_btn': '⚡ SCAN FILE',
      'nav.wiki_btn': 'WIKI →',
      'nav.repo_btn': 'REPO ↗',
      'nav.stats_btn': '📊 STATISTICS',
      'nav.project_lead': 'Project Lead:',

      // Stats Hero
      'stats.title': 'Threat Telemetry & Live Statistics',
      'stats.desc': 'Live telemetry metrics derived from the VirusKov global threat intelligence network, reverse engineering engine, entropy analysis, and behavioral rules.',

      // Stat Cards
      'stat.total_hashes': 'Unique SHA-256 Hashes',
      'stat.observed_hashes': 'Observed Unique Hashes',
      'stat.malicious': 'Blocked Malware (Malicious)',
      'stat.suspicious': 'Suspicious / Heuristics',
      'stat.clean': 'Verified Clean Files',
      'stat.unknown': 'Unsigned / Unknown Files',

      // Ratio Panel
      'ratio.title': 'Global Threat Distribution Ratios',
      'ratio.total_sightings': 'Total Sightings:',
      'ratio.malicious': 'Malicious:',
      'ratio.suspicious': 'Suspicious:',
      'ratio.clean': 'Clean:',
      'ratio.unknown': 'Unknown:',
      'spec.standard': 'DATA STANDARDIZATION',
      'spec.engine': 'ENGINE ARCHITECTURE',
      'spec.protocol': 'CLOUD PROTOCOL',
      'spec.origin': 'ORIGIN & SECURITY',

      // History Panel
      'history.title': 'Local Session Scan History & Reports',
      'history.desc': 'Recorded scan verdicts, threat scores, and ECS documents of files scanned in this browser.',
      'history.export': '📥 Download JSON',
      'history.clear': '🗑️ Clear History',
      'history.filter_all': 'All',
      'history.filter_mal': '🚨 Malicious',
      'history.filter_susp': '⚠️ Suspicious',
      'history.filter_clean': '✅ Clean',
      'history.filter_unk': 'ℹ️ Unknown',
      'history.search_ph': 'Search filename or hash...',
      'history.th_time': 'Time',
      'history.th_name': 'Filename',
      'history.th_size': 'Size',
      'history.th_verdict': 'Verdict',
      'history.th_score': 'Score',
      'history.th_sig': 'Threat Signature / Detail',
      'history.th_hash': 'SHA-256',
      'history.th_action': 'Action',
      'history.empty': 'No scanned files recorded in this browser yet.',
      'history.empty_filter': 'No matching scan records found.',
      'history.modal_title': '📄 Scan Report Details (ECS 9.5.4)',

      // Quick Hash Lookup
      'lookup.title': 'Instant Telemetry Hash Lookup (OpenTIP)',
      'lookup.desc': 'Query any SHA-256 hash to inspect live sightings across the VirusKov community telemetry pool.',
      'lookup.placeholder': 'Enter 64-character SHA-256 hash (e.g. cf89be2f5702f70de92fbc861579d945c632a1c05d0ef60a9dfb24f2a818912c)...',
      'lookup.btn': 'LOOKUP ↗',

      // Scanner Section (index.html & scan/index.html)
      'scan_page.title': 'VIRUSKOV | Live Threat Scanner & URL Analysis Workbench',
      'scan_page.meta_desc': 'VirusKov EDR live file inspection, OpenTIP hash lookup, and pure Machine Learning (ML) + Dynamic Whitelist next-gen URL scanner.',
      'scan_page.top_badge': '🛡️ 100% MACHINE LEARNING (ML) + DYNAMIC WHITELIST',
      'scan_page.hero_title': 'VirusKov Live URL & Web Threat Scanner',
      'scan_page.hero_desc': 'Because legacy signature-based URL blacklists get reused by third parties and falsely flag benign websites producing high False Positives (FP), the VirusKov URL Scanner has eliminated static signatures in favor of Machine Learning (ML), Dynamic Whitelist, and Domain Liveness architecture.',
      'scan_page.url_ph': 'Enter URL or domain (e.g., https://example.com)...',
      'scan_page.url_btn': '⚡ SCAN ↗',
      'scan_page.privacy_note': '🔒 Security & Privacy Notice: Web page views are not persistently stored; only live DNS/HTTP status is inspected.',
      'scan_page.fp_report': 'Report FP/FN: viruskov@viruskov.com ↗',
      'scan_page.tab_url': '🔗 LIVE URL SCAN (ML & WHITELIST)',
      'scan_page.tab_file': '⚡ FILE ANALYSIS (WEBSOCKET)',
      'scan_page.tab_hash': '🔍 HASH LOOKUP (OPENTIP)',
      'scan_page.tab_history': '📊 SCAN HISTORY',
      'scan_page.history_title': 'Session Scan History & Logs',
      'scan_page.history_clear': 'Clear History',
      'scan_page.th_time': 'Time',
      'scan_page.th_target': 'Target',
      'scan_page.th_type': 'Type',
      'scan_page.th_verdict': 'Verdict',
      'scan_page.th_score': 'Score',
      'scan_page.th_detail': 'Detail',
      'scan_page.th_hash': 'SHA-256',
      'scan_page.support_title': '📬 Support & False Positive/Negative (FP/FN) Desk',
      'scan_page.support_desc': 'To eliminate false positives caused by recycled legacy signatures, VirusKov relies strictly on Machine Learning (ML) and Dynamic Whitelisting. The Multron Server core incorporates this URL engine (especially targeting PDF and document embedded links). For inquiries or reports, contact viruskov@viruskov.com directly.',
      'scan_page.history_empty': 'No scanned records yet.',
      'ti.tag': 'LIVE CLOUD SCANNER & THREAT INTELLIGENCE',
      'ti.title': 'VirusKov Global Telemetry & Malware Analysis Engine',
      'ti.desc': 'Real-time cloud scanning engine: PE header parsing, Q24 Shannon entropy mapping, and global telemetry pool.',
      'ti.tab_scan': '⚡ LIVE FILE SCAN',
      'ti.tab_lookup': '🔍 HASH LOOKUP (OPENTIP)',
      'ti.tab_stats': '📊 ALL STATISTICS & HISTORY →',
      'ti.cloud_online': 'CLOUD ENGINE ONLINE (api.viruskov.com)',

      // Dropzone
      'drop.title': 'Drag & drop file to analyze or click to browse',
      'drop.types': 'PE, EXE, DLL, ZIP, APK, ELF or suspicious documents (Max 50 MB)',
      'drop.tip': '💡 <b>Tip:</b> If you experience adblocker (uBlock/AdBlock) or extension connection blocks, please open in an <b>Incognito window</b>.',

      // Scanner Status Flow
      'scan.preparing': 'Preparing file...',
      'scan.hashing': 'Computing client-side SHA-256 cryptographic digest...',
      'scan.handshaking': 'Handshaking with VirusKov Cloud Engine...',
      'scan.checking': 'Querying cloud cache...',
      'scan.checking_detail': 'Searching real-time hash signatures in database...',
      'scan.queuing': 'Queuing for static analysis...',
      'scan.queuing_detail': 'Requested upload slot for deep PE header inspection and YARA rules...',
      'scan.uploading': 'Uploading file...',
      'scan.deep_scanning': 'Performing deep analysis...',
      'scan.deep_detail': 'VirusKov EDR engine analyzing PE sections, entropy, and behavioral signatures...',
      'scan.stopped': 'Scan stopped',
      'scan.conn_error': 'Connection error',
      'scan.conn_error_desc': 'Could not connect to api.viruskov.com WebSocket. If an adblocker (AdBlock/uBlock) is active, please try in Incognito mode.',
      'scan.conn_closed': 'Connection closed',
      'scan.conn_closed_desc': 'Server terminated the session. Please retry or open in an Incognito window.',
      'scan.invalid_url': 'Please enter a valid URL or domain.',
      'scan.invalid_format': 'Invalid URL format.',
      'scan.url_analyzing': 'Inspecting URL with Machine Learning Model...',
      'scan.url_doh_detail': 'Querying DNS A record via Cloudflare DoH & probing HTTP liveness...',
      'scan.url_ml_eval': 'Evaluating Tranco Whitelist & Machine Learning features...',
      'scan.badge_malicious_url': '🚨 MALICIOUS (THREAT URL)',
      'scan.badge_suspicious_url': '⚠️ SUSPICIOUS (ANOMALY)',
      'scan.badge_clean_wl': '✅ CLEAN (WHITELIST VERIFIED)',
      'scan.badge_clean_benign': '✅ CLEAN (VERIFIED BENIGN)',
      'scan.badge_unknown': 'ℹ️ UNKNOWN (UNLISTED / NO SIGNATURE)',
      'scan.liveness_active': '🌐 SITE ACTIVE (DNS: OK / HTTP: ONLINE)',
      'scan.liveness_inactive': '💤 SITE INACTIVE / UNREACHABLE',
      'scan.report_fp': '📩 Report False Positive (FP/FN)',
      'scan.lbl_target': 'Target:',
      'scan.lbl_domain': 'Domain:',
      'scan.lbl_protocol': 'Protocol:',
      'scan.lbl_entropy': 'Shannon Entropy:',
      'scan.breakdown_title': '🛡️ Security Engines & ML Analysis Breakdown',
      'scan.eng_ml': 'VirusKov ML Core Engine',
      'scan.eng_ml_cat': 'Deep Learning',
      'scan.eng_wl': 'Dynamic Whitelist Verifier',
      'scan.eng_wl_cat': 'Zero-FP Reputation',
      'scan.eng_live': 'Domain Liveness Inspector',
      'scan.eng_live_cat': 'DNS DoH & HTTP Probe',
      'scan.eng_homo': 'Homograph & Punycode Shield',
      'scan.eng_homo_cat': 'IDN Attack Defense',
      'scan.eng_shannon': 'Statistical Shannon Classifier',
      'scan.eng_shannon_cat': 'Entropy Modeling',
      'scan.eng_antifp': 'Anti-FP Guard (Zero Reused Lists)',
      'scan.eng_antifp_cat': 'Zero Rule Filter',
      'scan.st_malicious': 'Malicious',
      'scan.st_suspicious': 'Suspicious',
      'scan.st_clean': 'Clean',
      'scan.st_unknown': 'Unknown',
      'scan.st_verified': 'Verified',
      'scan.st_unlisted': 'Unlisted (ML Checked)',
      'scan.st_active': 'Site Active & Online',
      'scan.st_inactive': 'Inactive / Unreachable',
      'scan.st_homo_detected': 'Homograph Detected',
      'scan.st_clean_script': 'Clean Script',
      'scan.st_normal': 'Normal',
      'scan.st_antifp_passed': 'Passed (No Reused Signatures)',
      'scan.max_size_alert': 'Maximum file size is 50 MB.',
      'scan.wss_connecting': 'Establishing WSS connection...',
      'scan.lbl_file': 'File',
      'scan.lbl_size': 'Size',
      'scan.lbl_type_url': 'URL',
      'scan.lbl_type_file': 'FILE',
      'scan.file_fp_note': 'Report false positives/negatives (FP/FN):',
      'lookup.alert_sha': 'Please enter a valid 64-character SHA-256.',
      'lookup.querying': 'Querying...',
      'lookup.score': 'Score:',
      'lookup.sig': 'Signature:',
      'lookup.prevalence': 'Prevalence:',
      'lookup.sightings': 'sightings',
      'lookup.unknown_note': 'ℹ️ UNKNOWN • This hash has not been seen in the telemetry pool yet.',
      'lookup.conn_err': 'Connection error: ',

      // Results
      'res.malicious_badge': '🚨 MALICIOUS (THREAT DETECTED)',
      'res.suspicious_badge': '⚠️ SUSPICIOUS (HEURISTIC DETECTION)',
      'res.clean_badge': '✅ CLEAN (VERIFIED BENIGN)',
      'res.unknown_badge': 'ℹ️ UNKNOWN (NO SIGNATURE MATCH)',
      'res.threat_sig': 'Threat Signature:',
      'res.stat_breakdown': '📊 Static Analysis & Telemetry Breakdown',
      'res.static_parsing': 'Static Parsing:',
      'res.sig_status': 'Signature Status:',
      'res.telemetry_status': 'Telemetry Status:',
      'res.scan_duration': 'Scan Time:',
      'res.static_detail': 'Static Detail / Extracted:',
      'res.filename': 'Filename:',
      'res.filesize': 'Size:',
      'res.engine': 'Engine:',
      'res.verdict': 'Verdict:',
      'res.ecs_standard': 'Standard:',
      'res.telemetry_query_btn': 'QUERY IN TELEMETRY →',

      // Footer
      'footer.copy': '© 2026 <b>VIRUSKOV</b> • Open Source Enterprise EDR & Antivirus System.',
      'footer.lead': 'Founder & Project Lead: <b>Emirhan Uçan</b>',

      // Wiki Specific
      'wiki.top_engine': 'VIRUSKOV WIKI &bull; ENGINE: PTM / PATTERNSMATCHING v2',
      'wiki.top_focus': 'FOCUS RULE: <span style="color: var(--accent-red);">MLE_RANSOM_BEHAVIOR</span> &bull; baseType 1000008',
      'wiki.top_back': '&larr; HOME',
      'wiki.nav_kunya': 'Dossier',
      'wiki.nav_mimari': 'Architecture',
      'wiki.nav_anatomi': 'Anatomy',
      'wiki.nav_suzgecler': 'Filters',
      'wiki.nav_sayac': 'Counter',
      'wiki.nav_entropy': 'Entropy',
      'wiki.nav_kernel': 'Kernel',
      'wiki.nav_yanit': 'Response',
      'wiki.nav_neden': 'Why Effective',
      'wiki.nav_sinirlar': 'Limitations',
      'wiki.nav_sss': 'FAQ',
      'wiki.btn_stats': '📊 STATISTICS',
      'wiki.btn_home': 'HOME',
      'wiki.btn_support': 'SUPPORT',
      'wiki.btn_repo': 'REPO',
      'wiki.btn_inspect_code': 'INSPECT SOURCE CODE',
      'wiki.btn_back_home': '&larr; VIRUSKOV HOME',
      'wiki.btn_top': 'BACK TO TOP',
      'wiki.toc_title': '&#9642; TABLE OF CONTENTS',
      'wiki.toc_1': '1 &mdash; Dossier',
      'wiki.toc_2': '2 &mdash; In One Sentence',
      'wiki.toc_3': '3 &mdash; Why Behavioral',
      'wiki.toc_4': '4 &mdash; End-to-End Architecture',
      'wiki.toc_5': '5 &mdash; PTM Engine',
      'wiki.toc_5_1': '5.1 &mdash; Directives',
      'wiki.toc_5_2': '5.2 &mdash; Operations',
      'wiki.toc_5_3': '5.3 &mdash; Wildcard Matching',
      'wiki.toc_6': '6 &mdash; Rule Anatomy',
      'wiki.toc_6_1': '6.1 &mdash; Stage 1: Read',
      'wiki.toc_6_2': '6.2 &mdash; Stage 2: Candidate',
      'wiki.toc_6_3': '6.3 &mdash; Stage 3: Evaluation',
      'wiki.toc_6_4': '6.4 &mdash; Stage 4: Verdict',
      'wiki.toc_6_5': '6.5 &mdash; Stage 5: Cleanup',
      'wiki.toc_7': '7 &mdash; Nine-Gate Filter',
      'wiki.toc_8': '8 &mdash; distinctCounter',
      'wiki.toc_9': '9 &mdash; File Object Fields',
      'wiki.toc_10': '10 &mdash; Shannon Entropy',
      'wiki.toc_11': '11 &mdash; Whitelist & Extension Watcher',
      'wiki.toc_12': '12 &mdash; Kernel Integration',
      'wiki.toc_13': '13 &mdash; Why Two Sub-Events',
      'wiki.toc_14': '14 &mdash; Incident Response Lifecycle',
      'wiki.toc_15': '15 &mdash; Why Highly Effective',
      'wiki.toc_16': '16 &mdash; Honest Limitations & Flaws',
      'wiki.toc_17': '17 &mdash; Sibling Detection Rules',
      'wiki.toc_18': '18 &mdash; SOC Analyst Handbook',
      'wiki.toc_19': '19 &mdash; Frequently Asked Questions',
      'wiki.toc_20': '20 &mdash; Source Map',
      'wiki.toc_home': '&larr; Home',
      'wiki.toc_support': 'Support &amp; Donate',
      'wiki.crumb': '<a href="../index.html">VIRUSKOV</a> / WIKI / DETECTION RULES / <span style="color: var(--accent-red);">MLE_RANSOM_BEHAVIOR</span>',
      'wiki.article_title': 'MLE_RANSOM_<span class="hl">BEHAVIOR</span><br>Full Technical Anatomy of Behavioral Ransomware Rule',
      'wiki.article_sub': 'OpenEDR &times; Hydra Dragon Core &bull; PTM / PatternsMatching v2 Policy Engine<br>Rule ID: <span class="c-red">RANSOM_BEHAVIOR</span> &nbsp;|&nbsp; Published Event Type: <span class="c-red">MLE_RANSOM_BEHAVIOR</span> &nbsp;|&nbsp; baseType: <span class="c-red">1000008</span><br>Policy Source: <code>OpenEDR/edrav2/iprj/edrdata/ptm.local.src</code> &nbsp;&bull;&nbsp; Lines 4636 &ndash; 5129',
      'wiki.lead': '<strong>MLE_RANSOM_BEHAVIOR</strong> does not look at a file\'s hash, compiler, or packer. At the ring-0 kernel level, <strong>behavior is all it sees</strong>: a process modifying, renaming, or deleting user personal files across <strong>at least 3 distinct targets within 60 seconds</strong>; targets that are <strong>not plain text</strong> and carry <strong>high-entropy, encrypted payload data</strong>. Once this trinity &mdash; <em>target &times; velocity &times; content entropy</em> &mdash; matches, the engine immediately <strong>quarantines the offending binary image and terminates the process</strong>. This page breaks down every single line, every filter gate, and every known limitation.',
      'wiki.h2_1': '<span class="num">01</span> Dossier & Metadata',
      'wiki.h2_2': '<span class="num">02</span> In One Sentence',
      'wiki.h2_3': '<span class="num">03</span> Why This Rule is Pure Behavior, Not Signatures',
      'wiki.h2_4': '<span class="num">04</span> End-to-End Architecture: The Event Lifecycle',
      'wiki.h2_5': '<span class="num">05</span> Foundation: PTM (PatternsMatching) Policy Engine',
      'wiki.h2_6': '<span class="num">06</span> Rule Anatomy: 16 Directives, 5 Lifecycle Stages',
      'wiki.h2_7': '<span class="num">07</span> The Nine-Gate Filter Chain, Deconstructed',
      'wiki.h2_8': '<span class="num">08</span> <code>distinctCounter</code>: Distinct Value Counter in Sliding Window',
      'wiki.h2_9': '<span class="num">09</span> The File Object: Inspected Kernel Attributes',
      'wiki.h2_10': '<span class="num">10</span> Shannon Entropy: Fixed-Point Q24 Arithmetic in Kernel',
      'wiki.h2_11': '<span class="num">11</span> Whitelists & Known Extension Watchers',
      'wiki.h2_12': '<span class="num">12</span> Kernel Space: Which IRP Maps to Which Event?',
      'wiki.h2_13': '<span class="num">13</span> Why Two Intermediate Internal Events Exist',
      'wiki.h2_14': '<span class="num">14</span> Response Chain: What Happens Upon Positive Verdict?',
      'wiki.h2_15': '<span class="num">15</span> Why This is an Effective Ransomware Mitigation Rule',
      'wiki.h2_16': '<span class="num">16</span> Honest Limitations, Evasion Vectors & Workarounds',
      'wiki.h2_17': '<span class="num">17</span> Sibling Rules: Defense in Depth',
      'wiki.h2_18': '<span class="num">18</span> Incident Response Analyst Handbook',
      'wiki.h2_19': '<span class="num">19</span> Frequently Asked Questions (FAQ)',
      'wiki.h2_20': '<span class="num">20</span> Source Code & Directory Map',
      'wiki.support_title': 'Authored for the Global Cyber Security Community',
      'wiki.support_text': '<strong>MLE_RANSOM_BEHAVIOR</strong> is a critical active defense shield that exposes ransomware actions at the OS kernel level. For questions, bug reports, or telemetry contributions, reach out directly to the project lead:',
      'wiki.footer_copy': '&copy; 2026 <strong>VIRUSKOV</strong> &bull; Open Source Enterprise EDR &amp; Antivirus System.<br>Wiki: <strong>MLE_RANSOM_BEHAVIOR</strong> &mdash; source-verified technical documentation.<br>Founder &amp; Project Lead: <strong>Emirhan Uçan</strong>.',

      // Portal Sections (index.html)
      'hero.meta_badge': '<span>⚡</span> OPEN SOURCE DEFENSE MANIFESTO & ENTERPRISE EDR EVOLUTION',
      'hero.title': 'AN UNPRECEDENTED PINNACLE IN OPEN SOURCE ANTIVIRUS HISTORY<br><span class="strike">THE ERA OF SECURITY BY OBSCURITY IS OVER</span><br><span class="highlight-red">TIME TO CONFRONT REAL THREATS HEAD-ON</span>',
      'hero.lead': 'Antivirus products are distributed as black boxes. Users cannot see what the engine is doing, while attackers can. <em>Security by Obscurity</em> does not slow down threats; it only blinds the user.',
      'hero.subtext': 'The first <em>Antivirus.sln</em> was created on April 15, 2023. Following <strong>Turko Antivirus</strong> and <strong>Hydra Dragon</strong>, the repository integrated <strong>Sanctum, OpenEDR, Owlyshield, Ring-0 Kernel and Generalized Machine Learning</strong>. Full timeline with dates below.',
      'hero.btn_history': 'EXPLORE HONEST CHRONOLOGY &darr;',
      'hero.btn_ransom': 'MLE_RANSOM_BEHAVIOR RULE &darr;',
      'hero.btn_wiki': 'DOCUMENTATION WIKI &nearr;',
      'hero.btn_code': 'INSPECT SOURCE CODE &nearr;',
      'hero.stat1_lbl': 'Antivirus.sln Inception & Continuous Evolution',
      'hero.stat2_val': '100% OPEN',
      'hero.stat2_lbl': 'Auditable C / C++ & Rust',
      'hero.stat3_lbl': 'BYOVD & Kernel-Level Defense',
      'hero.stat4_lbl': 'Static PE Headers + Dynamic Behavior',
      'ti.section_tag': 'LIVE COMMUNITY TELEMETRY &amp; OPENTIP',
      'ti.section_title': 'VirusKov Threat Intelligence &amp; Hash Lookup',
      'ti.section_desc': 'Real-time threat prevalence telemetry aggregated from VirusKov endpoint sensors. Query SHA-256 hashes across the VirusKov threat intelligence pool or inspect live telemetry:',
      'hist.tag': 'VERIFIED & TRANSPARENT CHRONOLOGY',
      'hist.title': 'The True and Uncensored History of VirusKov',
      'hist.desc': 'It began with an Avast forum account. Then 1.5 years of chess, several early iterations, and a documented Discord history. Here is exactly what happened, when it took place, and all verified references:',
      'hist.filter_all': 'ALL (Chronological)',
      'hist.filter_roots': 'Origins & Foundations (2019-2022)',
      'hist.filter_birth': '2023 Inception (Antivirus.sln & Hydra)',
      'hist.filter_alliances': '2024 Alliances & Community',
      'hist.filter_kernel': 'Technical & Kernel Era',
      'hist.search_ph': 'Search date, person, engine, or link...',
      'evo.tag': 'CODE & ENGINE ARCHITECTURE STEPS',
      'evo.title': 'Technical Engine Evolution: From Hash to Kernel EDR',
      'evo.desc': 'Started with basic hash matching; replaced with kernel drivers, policy rule engines, and machine learning. Progression:',
      'manif.tag': 'THREAT & RESILIENCE ANALYSIS',
      'manif.title': 'Why Closed Antiviruses Fail',
      'manif.desc': 'A black box does not prove resilience. Here is the architectural distinction in VirusKov:',
      'arch.tag': 'ENGINEERING CORE',
      'arch.title': 'Engine Capabilities Built from the Repository',
      'arch.desc': 'Enterprise security modules actively compiled and integrated across the codebase:',
      'team.tag': 'ALLIES, CONTRIBUTORS & ALLIANCE',
      'team.title': 'Community & Solidarity Table',
      'team.desc': 'Codebase contributors, testers, and open-source allies:',
      'ransom.tag': 'DETECTION RULES WIKI &bull; DEDICATED DOCUMENTATION',
      'ransom.title': 'MLE_RANSOM_BEHAVIOR: Full Anatomy of the Ransomware Rule',
      'ransom.desc': 'The core strength of this project is behavior, not static signatures. Fully documented and verified directly from source in our <a href="wiki/index.html" style="color: var(--accent-red); font-weight: 700;">VIRUSKOV Wiki</a>. Below is an architectural overview:',
      'wiki_sec.title': '<span class="text-cyan">▤</span> VirusKov Wiki &amp; Support Desk',
      'wiki_sec.badge': 'SOURCE-VERIFIED',
      'wiki_sec.notice': '<strong>NOTICE:</strong> Sponsorship and donations are not processed through third-party platforms or commissions. Anyone wishing to contribute rules or offer support reaches the project lead directly: <strong>viruskov@viruskov.com</strong>. Direct, transparent, zero middleman.',
      'wiki_sec.card_tag': 'WIKI &bull; 20 CHAPTERS',
      'wiki_sec.card_title': 'MLE_RANSOM_BEHAVIOR — Full Documentation',
      'wiki_sec.card_desc': '16 rule directives, 5 stages, 9 filter gates, distinctCounter semantics, Q24 fixed-point Shannon entropy, kernel IRP mapping, and incident response chain. Source lines included.'
    }
  };

  function getCurrentLang() {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved === 'en' || saved === 'tr') return saved;
    } catch (_) {}
    return 'en';
  }

  function t(key) {
    const lang = getCurrentLang();
    if (translations[lang] && translations[lang][key] !== undefined) {
      return translations[lang][key];
    }
    if (translations.en && translations.en[key] !== undefined) {
      return translations.en[key];
    }
    if (translations.tr && translations.tr[key] !== undefined) {
      return translations.tr[key];
    }
    return null;
  }

  function applyLanguage(lang) {
    if (lang !== 'tr' && lang !== 'en') lang = 'tr';
    try {
      localStorage.setItem(STORAGE_KEY, lang);
    } catch (_) {}

    document.documentElement.lang = lang;

    // Update data-i18n text content
    document.querySelectorAll('[data-i18n]').forEach((el) => {
      if (el.tagName === 'TITLE') return;
      const key = el.getAttribute('data-i18n');
      const val = t(key);
      if (val !== null && val !== undefined && val !== key) {
        if (typeof val === 'string' && val.includes('<') && val.includes('>')) {
          el.innerHTML = val;
        } else {
          el.textContent = val;
        }
      }
    });

    // Safely update document.title based on active page
    try {
      if (window.location.pathname.includes('scan') || document.querySelector('#paneUrl')) {
        const scanTitle = t('scan_page.title');
        if (scanTitle && scanTitle !== 'scan_page.title') document.title = scanTitle;
      }
    } catch (_) {}

    // Update data-i18n-placeholder
    document.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
      const key = el.getAttribute('data-i18n-placeholder');
      const val = t(key);
      if (val !== null && val !== undefined && val !== key) el.setAttribute('placeholder', val);
    });

    // Update data-i18n-title
    document.querySelectorAll('[data-i18n-title]').forEach((el) => {
      const key = el.getAttribute('data-i18n-title');
      const val = t(key);
      if (val !== null && val !== undefined && val !== key) el.setAttribute('title', val);
    });

    // Update switcher buttons UI
    document.querySelectorAll('.lang-btn').forEach((btn) => {
      const btnLang = btn.getAttribute('data-lang');
      if (btnLang === lang) {
        btn.classList.add('active');
      } else {
        btn.classList.remove('active');
      }
    });

    // Trigger custom event for dynamic components (charts, tables)
    window.dispatchEvent(new CustomEvent('viruskov_lang_changed', { detail: { lang } }));
  }

  function init() {
    const currentLang = getCurrentLang();
    applyLanguage(currentLang);

    // Bind all language switch buttons
    document.querySelectorAll('.lang-btn').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const selected = btn.getAttribute('data-lang');
        applyLanguage(selected);
      });
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // Expose globally
  window.ViruskovI18n = {
    t,
    getLang: getCurrentLang,
    setLang: applyLanguage
  };
})();
