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

      // Scanner Section (index.html)
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
      'wiki.footer_copy': '&copy; 2026 <strong>VIRUSKOV</strong> &bull; Açık Kaynak Kurumsal EDR &amp; Antivirüs Sistemi.<br>Wiki: <strong>MLE_RANSOM_BEHAVIOR</strong> &mdash; kaynak kodla birebir doğrulanmış teknik dokümantasyon.<br>Kurucu &amp; Proje Lideri: <strong>Emirhan Uçan</strong>.'
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

      // Scanner Section (index.html)
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
      'wiki.footer_copy': '&copy; 2026 <strong>VIRUSKOV</strong> &bull; Open Source Enterprise EDR &amp; Antivirus System.<br>Wiki: <strong>MLE_RANSOM_BEHAVIOR</strong> &mdash; source-verified technical documentation.<br>Founder &amp; Project Lead: <strong>Emirhan Uçan</strong>.'
    }
  };

  function getCurrentLang() {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved === 'en' || saved === 'tr') return saved;
    } catch (_) {}
    return 'tr';
  }

  function t(key) {
    const lang = getCurrentLang();
    return (translations[lang] && translations[lang][key]) || (translations.tr && translations.tr[key]) || key;
  }

  function applyLanguage(lang) {
    if (lang !== 'tr' && lang !== 'en') lang = 'tr';
    try {
      localStorage.setItem(STORAGE_KEY, lang);
    } catch (_) {}

    document.documentElement.lang = lang;

    // Update data-i18n text content
    document.querySelectorAll('[data-i18n]').forEach((el) => {
      const key = el.getAttribute('data-i18n');
      const val = t(key);
      if (val !== undefined) {
        if (val.includes('<') && val.includes('>')) {
          el.innerHTML = val;
        } else {
          el.textContent = val;
        }
      }
    });

    // Update data-i18n-placeholder
    document.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
      const key = el.getAttribute('data-i18n-placeholder');
      const val = t(key);
      if (val !== undefined) el.setAttribute('placeholder', val);
    });

    // Update data-i18n-title
    document.querySelectorAll('[data-i18n-title]').forEach((el) => {
      const key = el.getAttribute('data-i18n-title');
      const val = t(key);
      if (val !== undefined) el.setAttribute('title', val);
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
