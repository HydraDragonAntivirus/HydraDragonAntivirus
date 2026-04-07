# Tasarım ve Revizyon Planı: Tactical Tech-Noir (EDR Dashboard Pivot)

## 1. Vizyon ve Konsept (PİVOT EDİLDİ)

Hedef kitle beklentileri doğrultusunda konsept, "Kullanıcı dostu basit antivirüs" çizgisinden, açık kaynaklı, şeffaf ve analistlere yönelik "Profesyonel EDR (Endpoint Detection and Response) Dashboard" yapısına pivot edilmiştir. "Tactical Tech-Noir" stili (Kömür grisi, keskin hatlar, kan kırmızı vurgular) korunmakta, ancak içerik tamamen teknik veri ve canlı metriklerle doldurulmaktadır.

## 2. Tasarım Sistemi & Stil Kararları

* **Geometri:** 4px - 6px (micro-radius) ile hafif yumuşatılmış köşeler.
* **Renk Paleti:**
  * **Zemin:** Zifiri Karanlık (`#09090B`), Bento kutuları (`#121216`).
  * **Terminal/Matrix Log:** Zemin (`#000000`), Metin (`#22C55E` - Tok Yeşil).
  * **Aksiyon & Otorite:** Buz Beyazı (`#F8F9FA`), Otorite Yeşili (`#10B981`).
* **Tipografi:** Panellerde "Inter/Roboto", Terminal/Log ve Metrik gösterimlerinde katı "Courier New" veya "Consolas" (Monospace).

## 3. Yeni EDR Arayüz Yerleşimi (Zenginleştirilmiş Bento Grid)

* **Sol Navigasyon (Aynı):** Operasyonel sadelik için klasik menü.
* **Üst Bento (Kalkan & Donanım):**
  * Sol taraf: Devasa sistem savunma kalklanı ve Hızlı Tarama aksiyonu.
  * Sağ taraf: `psutil` destekli aktif CPU ve RAM tüketimi progress barları.
* **Orta Bento (Veri Akışı & İstihbarat):**
  * Sol: Tehdit İstihbarat Paneli (Hayabusa/ClamAV güncellik tarihi, YARA imza sayısı).
  * Sağ: Motor Tarama İstatistikleri (Dosya/Saniye, o an taranan path).
* **Alt Geniş Bento (Canlı Terminal):** Gelişelişmiş "Matrix" tarzı log penceresi. Sistem eylemleri, hook bildirimleri saniye saniye akacak.

## 4. Gerçek Motor Entegrasyon Mimarisi (KIRMIZI ÇİZGİYE UYGUN)

* Hiçbir backend kodu değiştirilmez/silinmez.
* **`asyncio` + `threading` Köprüsü:**
  * UI asenkron fonksiyonlara kilitlenmemesi (UI Freezing) için bağımsız bir Background Thread içinde `asyncio` Event Loop koşulur.
  * Arayüz (CustomTkinter) `after()` metotlarıyla periyodik olarak UI bileşenlerini günceller.
  * `engine.py` deki asenkron yapı (`update_definitions_async` vb.) `asyncio.run_coroutine_threadsafe()` ile bu thread'e gönderilir.
* **Terminal Log Sync:** CustomTkinter Textbox "Read-Only" tutulur, Queue ile arka plandan gelen stringler anında panele yazdırılır.

## 5. Ürünleştirme, Yetkilendirme ve Derleme (Faz 4)

* **Privilege Escalation:** Her açılışta `ctypes.windll.shell32.IsUserAnAdmin()` kontrolü yapılır. İzin alınmadıysa kritik EDR servislerinin kısıtlanabileceği bildirilerek arayüz "Sınırlı (DANGER)" uyarısıyla açılır.
* **First Run Setup (İlk Kurulum):** Hacker dostu minimal tasarımda; VirusTotal API Key ve Custom YARA Rules gibi analiz araçlarının yapılandırılması için `hydra_config.json` üretilir.
* **Paketleme (Pyinstaller):** `customtkinter`, `asyncio`, GUI modülleri ve Lazy import edilen motor bileşenleri için `--hidden-import` parametrelerini tam içeren `build_dashboard.py` yapılandırılmıştır.

## 6. Uygulama Aşamaları

1. **Aşama 1 (Tamamlandı):** Temel MVP iskeletinin oluşturulması.
2. **Aşama 2 (Tamamlandı):** Canlı CPU/RAM, İstihbarat panelini ve Matrix Terminal arayüzünü içeren Advanced UI inşası.
3. **Aşama 3 (Tamamlandı):** `engine.py` fonksiyonlarının Queue & Asyncio_threadsafe pattern'i kullanılarak UI'ye bağlanması (Graceful degradation).
4. **Aşama 4 (Tamamlandı):** Setup (Konfig), Admin Kontrol mekanizması ve `build_dashboard.py` kodlanmasıyla EDR'nin üretime (Production) hazır, paketlenebilir hale getirilmesi.
hı
hı
