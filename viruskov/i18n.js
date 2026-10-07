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
      'footer.lead': 'Kurucu & Proje Lideri: <b>Emirhan Uçan</b>'
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
      'footer.lead': 'Founder & Project Lead: <b>Emirhan Uçan</b>'
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
