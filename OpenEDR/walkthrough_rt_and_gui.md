# HydraDragon Antivirus: Real-Time Protection & Pending Actions Refactor Walkthrough

## 1. Mimari Yanıt: "Kernelden okuyup baytları atmak mantıklı olur mu?"

**Net Yanıt: HAYIR (Tam dosya baytlarını kernelden kullanıcı moduna aktarmak anti-patterndir ve tehlikelidir).**

### Neden Tam Bayt Akışı Yapılmaz?
1. **Kernel Pool Tüketimi & BSOD Riski:**
   - 53.000 dosya kopyalanırken veya 50-100 MB'lık dosyalar yazılırken, sürücü içinde Non-Paged / Paged Pool belleğe bu baytları kopyalamak kernel hafızasını tüketir ve sistemin mavi ekran vermesine (`PAGE_FAULT_IN_NONPAGED_AREA`, `MUST_SUCCEED_POOL_EMPTY`) sebep olur.
2. **IPC / Ring Buffer Darboğazı:**
   - Gigabaytlarca ham baytı ring buffer veya inverted call IOCTL üzerinden user-mode'a taşımak ciddi CPU tüketimi, context switch ve double buffering maliyeti getirir.

### Sektör Standardı EDR Yaklaşımı (Defender, CrowdStrike, SentinelOne):
1. **Sadece Header Kontrolü (Kernel-Side):**
   - Kernel yalnızca ilk 256 bayt – 4 KB başlığı okur (`MZ` sihirli baytları).
2. **`IRP_MJ_CLEANUP` (Post-Cleanup Tetikleme):**
   - Dosya kopyalanırken veya yazılırken tarama başlatılmaz. Kopyalayan process son handle'ı kapattığında (`IRP_MJ_CLEANUP`), dosya diske tam yazılmış ve kilit açılmış olur.
3. **Paylaşımlı Okuma (`FILE_SHARE_READ`):**
   - Kullanıcı modundaki daemon servis, kernelden sadece **dosya yolu ve process bilgilerini** alır. Eklediğimiz `read_file_shared` ile dosyayı çakışmasız okur.

---

## 2. Arka Plan Daemon Tarama Motoru (`daemon_scan.rs`)

`clamscan` mantığında senkron (her I/O olayında thread'i 150ms uyutup bekleyen) yapı tamamen kaldırıldı ve **`clamd` tarzı asenkron thread pool mimarisine** geçildi.

### Yapılan Değişiklikler:
- [daemon_scan.rs](file:///c:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/OpenEDR/owlyshield_predict/src/daemon_scan.rs):
  - 4 adet paralel arka plan tarayıcı thread'i oluşturuldu.
  - **LRU Deduplication:** Aynı dosya yolu için 3 saniye içindeki yinelenen kernel olayları (Create, Write, SetInfo, Close) tek göreve indirgendi (53.000 dosya kopyalamada olay fırtınasını önler).
  - Önce hızlı **ML motoru** (`fast_detect_path`), ardından **ClamAV derin arşiv tarayıcısı** (`rt_scan_file`) çalıştırılır.
  - Zararlı tespit edildiğinde `threat_handler.quarantine_only` veya `kill_and_quarantine` ile karantinaya alınır.
- [worker.rs](file:///c:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/OpenEDR/owlyshield_predict/src/worker.rs):
  - `process_io` içindeki bloklayıcı `rt_scan_file` döngüsü kaldırıldı; olaylar mikrosaniyeler içinde `daemon_scan::enqueue_scan` kuyruğuna aktarılır. Kernel I/O boru hattı hiçbir zaman tıkanmaz.
- [run.rs](file:///c:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/OpenEDR/owlyshield_predict/src/windows/run.rs):
  - Sürücü başlatılırken `daemon_scan::init_daemon_scanner` ile thread havuzu ayağa kaldırıldı.

---

## 3. Makine Öğrenimi (ML) ve Model Yükleme Düzeltmeleri

- [fast_detect.rs](file:///c:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/OpenEDR/owlyshield_predict/src/ml/fast_detect.rs):
  - `fast_detect_path(path_str)` fonksiyonu eklenerek arka plan daemon işçilerinin doğrudan dosya yolundan ML tespiti yapması sağlandı.
  - Kayıt defteri yolları (`HKLM\SOFTWARE\Owlyshield\SDK`), modül dizini ve Program Files kontrol edilerek model bulunma garantilendi.
  - Kalıcı `OnceLock` zehirlenmesi 3 saniyelik yeniden deneme mekanizmasıyla değiştirildi.

---

## 4. Pascal GUI (`urep.pas` & `detectionnotifier.cpp`)

### Karşılanan Kullanıcı İstekleri:
1. **Tek Pencere (İkinci pencere ve popuplar kaldırıldı):**
   - `TAlertForm.ShowAlert` çağrıları tamamen kaldırıldı. Tüm durum bildirimleri doğrudan `TRepForm` üzerindeki `StatusLbl` alanına yazdırılıyor.
2. **Karantina / Hariç Tutma İşlemleri Yalnızca "Apply Actions" ile Çalışır:**
   - "Quarantine", "Ignore", "Quarantine All" ve "Ignore All" tıklandığında hemen RPC/DLL çağrılmaz.
   - Seçilen satırlar `FStagedActions` listesine kaydedilir ('Q' veya 'I') ve `ActionsView` güncellenir.
   - Yalnızca kullanıcı **"Apply Actions"** butonuna bastığında tüm hazırlanan aksiyonlar toplu olarak çalıştırılır.
3. **Duplicate (Mükerrer) Satır Gösterimi Giderildi:**
   - `RefreshPendingList` ve `PendingCount` içine `SeenKeys: TStringList` mekanizması eklenerek aynı dosya yolunun `ActionsView` listesinde birden fazla kez gösterilmesi engellendi.
4. **"Lookup failed" Durumunda Taramayı Kesmeme:**
   - `detectionnotifier.cpp`: `getFileReputationBulk` RPC çağrısında `pFls` null olsa dahi (çevrimdışı / cloud hatası) işlem durdurulmuyor; `nVerdict = 4` (Lookup failed) olarak işaretlenip yerel ML + ClamAV motorlarının sonuçları döndürülüyor.
   - `urep.pas`: `TRepWalkThread.FlushBatch` içinde HTTP bağlantı hatası oluşursa `PushFailedRows` çağrılarak dosyalar `Lookup failed` olarak ekleniyor ve dizin taraması kesilmeden sonuna kadar devam ediyor.
