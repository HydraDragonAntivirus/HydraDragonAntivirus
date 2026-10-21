# VirusKov analist rehberi (VDS)

Bu rehber, multron sunucusunun çalıştığı VDS'teki analist için (insan ya da yapay zekâ).
Kapsam: VirusKovAlyzer ile dosya analizi, false positive (FP) çözümü ve dashboard API'sine
analist anahtarıyla istek atma. Tüm uç noktaların tam listesi `API.md`'de; HydraDragonSig
kural formatı bu klasördeki `HYDRADRAGONSIG_FORMAT.md`'de.

> **Temel kural:** Örnek dosyaları hiçbir zaman doğrudan çalıştırma. Her analiz
> VirusKovAlyzer üzerinden yapılır: dosya okunur, emülasyon (Unicorn) izole çalışır,
> düzenlemeler yalnızca `alyzer_edited/` altına kopya olarak kaydedilir.

---

## 1. Dashboard API'sine bağlanma

Dashboard API'si **yalnızca sunucunun kendi makinesinden** çalışır.

| Kural | Ne olur |
|---|---|
| Adres `http://127.0.0.1:9440` olmalı (VDS'in public IP'si değil) | Aksi halde `403 dashboard is only available on this computer` |
| `Host` başlığı `127.0.0.1`, `localhost` ya da `[::1]` olmalı | Aksi halde aynı 403 |
| Her **POST** isteğinde `X-Multron-Dashboard: 1` başlığı | Yoksa `403 forbidden` (gövde yalnızca `forbidden`) |
| Karar/kural değiştiren POST'larda `X-Multron-Analyst-Key: <anahtar>` | Yoksa `401 analyst key required` |
| GET istekleri | Hiçbir başlık gerekmez |
| Gövde | JSON, `Content-Type: application/json` |

Aynı VDS'te farklı bir makineden (başka bir VM'den) bağlanılamaz. Gerekirse SSH tüneli:
`ssh -N -L 9440:127.0.0.1:9440 <kullanıcı>@<vds>` ve sonra `http://127.0.0.1:9440`.

### Analist anahtarı

- Anahtarlar sunucu exe'sinin yanındaki `analyst_keys.txt` dosyasında: her satır
  `<anahtar> <analist adı>`, anahtar en az 16 karakter, `#` yorum.
- Yapay zekâ analistinin satırı `[ai]` ile biter: `<anahtar> Claude [ai]`. Bu kararlar
  public istatistiklerde "AI destekli" olarak ayrı sayılır.
- Dosya her istekte yeniden okunur; anahtar eklemek için sunucuyu yeniden başlatmak gerekmez.
- Karar kaydedilirken analist adı **anahtarın sahibidir**; gövdedeki `analyst` alanı yok sayılır.
- Anahtar gerektiren uç noktalar: `/api/review`, `/api/review/start`, `/api/review/release`,
  `/api/review/delete`, `/api/reviews/bulk`, `/api/reviews/requeue`, `/api/signatures`,
  `/api/signatures/delete`, `/api/imphash-signatures`, `/api/imphash-signatures/delete`,
  `/api/fp/ignore`, `/api/fp/unignore`, `/api/companies`, `/api/rules`, `/api/bans/add`,
  `/api/bans/remove`, `/api/ml-thresholds`.

Anahtarın çalıştığını doğrula:

```bash
curl -s http://127.0.0.1:9440/api/analyst/whoami -H "X-Multron-Analyst-Key: <anahtar>"
# {"enforced": true, "analyst": "Claude", ...}  -> analyst boşsa anahtar tanınmadı
```

### Hata kodları

| Yanıt | Sebep | Çözüm |
|---|---|---|
| `403` + `dashboard is only available on this computer` | Public IP / yanlış `Host` / başka makine | `http://127.0.0.1:9440` kullan |
| `403` + yalnızca `forbidden` | POST'ta `X-Multron-Dashboard: 1` yok | Başlığı ekle |
| `401` + `analyst key required` | Anahtar yok, yanlış ya da o sunucunun `analyst_keys.txt`'inde değil | `whoami` ile kontrol et; satırın başında boşluk olmasın, anahtar ≥16 karakter |
| `403` + `archive server: read-only` | Arşiv sunucusuna yazma | Değişikliği ana sunucuda yap |

### Örnek istemci

```python
import requests

BASE = "http://127.0.0.1:9440"
KEY = "<analist anahtarı>"
H = {"X-Multron-Dashboard": "1", "X-Multron-Analyst-Key": KEY}

def get(path, **params):
    r = requests.get(BASE + path, params=params, headers=H, timeout=120)
    r.raise_for_status()
    return r.json()

def post(path, body=None, **params):
    r = requests.post(BASE + path, params=params, json=body or {}, headers=H, timeout=600)
    if r.status_code >= 400:
        raise RuntimeError(f"{path}: {r.status_code} {r.text[:300]}")
    return r.json()
```

```powershell
$H = @{ "X-Multron-Dashboard" = "1"; "X-Multron-Analyst-Key" = "<anahtar>" }
Invoke-RestMethod -Method Post "http://127.0.0.1:9440/api/review" -Headers $H `
  -ContentType "application/json" -Body '{"sha256":"<sha256>","verdict":"clean"}'
```

---

## 2. VirusKovAlyzer ile analiz

VirusKovAlyzer, sunucuda tutulan bir dosyayı (ya da sunucudaki bir yolu) açar ve her
görünümü ayrı bir uç noktadan verir. Dosya açılınca bir `token` döner; sonraki bütün
istekler bu token ile yapılır.

### 2.1 Sıradaki dosyayı al

```python
q = get("/api/reviews", limit=50, engine_verdict="malicious,suspicious,unknown")
item = q["pending"][0]                 # en eski bekleyen dosya; sonraki sayfa: offset=q["next_offset"]
sha = item["sha256"]                   # ayrıca: file_names, engine_verdict, detections, signer, folders
post("/api/review/start", {"sha256": sha})   # dosyayı üzerime al (başkası aynı anda bakmasın)
```

Filtreler: `ext=exe,dll`, `not_ext=...`, `folder=...`, `not_folder=found.000,\\temp\\`.

### 2.2 Aç ve önce özet rapora bak

```python
doc = post("/api/alyzer/open", {"sha256": sha})
tok = doc["token"]
```

`open` yanıtında statik rapor, motorun ve varsa insanın kararı, son taramadaki imzacı var.
Önce şunlara bak:

1. **Hangi motor ne dedi:** ClamAV / YARA / HydraSig imza adı mı, yoksa yalnızca
   `MalwareNet.PE.HighConfidence` (ML) mi? Yalnızca ML ise FP olasılığı yüksektir (bkz. §3.3).
2. **İmza (Authenticode):** Geçerli ve bilinen bir yayıncı mı? İmzalı + temiz itibar = büyük
   olasılıkla temiz. Geçerli imza tek başına temiz demek değildir (çalınmış sertifikalar var).
3. **Dosya türü ve paketleme:** .NET mi (CLR header, tek import `mscoree.dll`), paketli mi
   (yüksek entropi, az import), installer mı (NSIS / SFX)?

### 2.3 Görünümler

| Uç nokta | Ne için |
|---|---|
| `GET /api/alyzer/strings?token=..&unknown=1` | Yalnızca **bilinmeyen** string'ler (temiz dosyalarda görülenler elenir). URL, IP, komut satırı, registry yolu, mutex, fidye notu metni burada çıkar. `q=` ile filtrele. |
| `GET /api/alyzer/decompile?token=..` | Kodun adresle referans verdiği string'ler, yığında kurulan string'ler (stack strings), karakteristik opcode kalıpları (API hashing, PEB gezme, dolaylı syscall). Gizlenmiş zararlıda strings'ten çok daha fazlasını gösterir. |
| `GET /api/alyzer/archive?token=..` | Arşiv/installer içeriği ve arşiv sezgiselleri (şifreli yem, RLO adlar). Bir üyeyi açmak: `POST /api/alyzer/archive/open {"token", "name"}` → yeni token. |
| `POST /api/alyzer/unpack {"token"}` | Unicorn emülasyonu: dosyayı emülatörde çalıştırır, bellek imajını döker ve yeni belge olarak açar. Paketli dosyalarda gerçek içeriği görmek için. |
| `GET /api/alyzer/disasm?token=..&at=entry&count=200` | Disassembly (x86/x64/ARM/ARM64). `at=` sanal adres (`401000`) ya da dosya ofseti (`o:400`). |
| `GET /api/alyzer/bytes?token=..&offset=0&len=4096` | Ham baytlar (en fazla 1 MB). |
| `GET /api/alyzer/search?token=..&pattern=4d5a90` | Bayt kalıbı arama (hex). |
| `POST /api/alyzer/scan {"token"}` | Açık dosyayı motorla **şimdi** tara (önbelleğe/telemetriye yazmaz). İmza ya da eşik değişikliğinden sonra sonucu görmek için. |
| `GET /api/fp/detections/<sha256>` | Son sonuçta hangi imzaların, hangi motordan geldiği. |
| `GET /api/reviews/similar/<sha256>` | TLSH ile benzer dosyalar ve kararları. |
| `GET /api/insights/<sha256>` | Telemetri: kaç kez, nerede, hangi adla görüldü. |

### 2.4 Analiz sırası (önerilen)

1. `open` → motor kararı, imza, tür.
2. `strings?unknown=1` → göze çarpan IOC'ler (URL/IP/domain, komutlar, registry Run anahtarları,
   şüpheli API adları, kripto cüzdanı, fidye notu).
3. Paketliyse `unpack` → açılan yeni belgede 2. adımı tekrarla.
4. Installer/arşivse `archive` → üyeleri tek tek aç, en büyük/çalıştırılabilir üyeden başla.
5. `decompile` → stack strings, API hashing, PEB gezme gibi gizleme izleri.
6. Gerekirse `disasm` ile giriş noktası ve şüpheli fonksiyonlar.
7. `similar` ve `insights` ile bağlam: aynı aileden başka örnek var mı, kaç makinede görüldü?

### 2.5 Kararı kaydet

```python
post("/api/review", {
    "sha256": sha,
    "verdict": "malicious",                    # malicious | suspicious | clean
    "threat_name": "Stealer.Win32.Lumma.A",    # zararlı için zorunlu biçim, aşağıya bak
    "note": "Kısa, herkese açık gerekçe",
    "internal_note": "İç not (IOC'ler, adımlar)",
})
```

- Bıraktığın dosyayı kuyruğa geri ver: `POST /api/review/release {"sha256"}`.
- Kararı sil: `POST /api/review/delete {"sha256"}`.
- Kayıtla birlikte: tutulan dosya kararın klasörüne taşınır, TLSH analist listesi güncellenir,
  aynı içerik ML dataset klasörlerindeyse kararın etiketine taşınır.

**Tehdit adı biçimi:** `Category.Platform.Family[.Variant]`

- Category: `Trojan, Backdoor, RAT, Ransom, Wiper, Worm, Virus, Rootkit, Bootkit, Exploit,
  Downloader, Dropper, Loader, Stealer, Spyware, Keylogger, Banker, Miner, Botnet, Phishing,
  Adware, PUA, HackTool, Riskware, Vuln, Packed, Generic, Test`
- Platform: `Win32, Win64, MSIL, WinDrv, Linux, MacOS, Android, iOS, Java, JS, VBS, PowerShell,
  Batch, Python, AutoIt, Office, PDF, HTML, LNK, Script, Multi`
- .NET zararlıları için platform `MSIL`.

**Karar ölçütleri:**

| Karar | Ne zaman |
|---|---|
| `malicious` | Zararlı davranış ya da bilinen aile kanıtı var (IOC, açılmış payload, aile imzası). |
| `suspicious` | Şüpheli ama kanıt yetersiz (PUA benzeri, gizlenmiş ama davranışı görünmeyen). |
| `clean` | Meşru yazılım: bilinen yayıncı, tutarlı sürüm bilgisi, zararlı davranış izi yok. Emin değilsen `clean` verme. |

---

## 3. False positive (FP) çözümü

Önce FP'yi **hangi katmanın** verdiğini bul: `GET /api/fp/detections/<sha256>` ya da
`open` yanıtındaki motor listesi. Çözüm katmana göre değişir.

### 3.1 Tek dosya için: clean kararı (her zaman ilk adım)

```python
post("/api/review", {"sha256": sha, "verdict": "clean", "note": "Meşru: <yayıncı / ürün>"})
```

İnsan kararı motor kararını her zaman geçersiz kılar. Bu, o tek hash'i düzeltir ve dosyayı ML
eğitimi için temiz etiketiyle işaretler.

### 3.2 İmza FP'si (ClamAV / YARA / HydraSig)

Bir imza birden fazla temiz dosyayı yakalıyorsa imzayı FP listesine ekle:

```python
post("/api/fp/ignore", {
    "kind": "clamav",            # clamav | hydrasig | yara
    "name": "<imza adı, /api/fp/detections çıktısından birebir>",
    "reason": "Temiz <ürün> dosyalarında FP",
    "sha256": sha, "file_name": "<dosya adı>",
})
post("/api/engine/reload")       # liste motor yüklenirken okunur; reload şart
post("/api/rescan", {"sha256": sha})   # eski karar önbellekte; yeniden tara
```

- Listeler bellekte tutulur; **`/api/engine/reload` olmadan etkili olmaz** (süreci yeniden başlatmak gerekmez).
- Reload'dan önce verilmiş kararlar önbellekte kalır (14 gün); etkilenen dosyaları `rescan` et.
- Mevcut listeler: `GET /api/fp/lists`. Kaldırmak: `POST /api/fp/unignore {"kind","file","name"}` + reload.
- Bir imzayı **yalnızca** gerçekten FP üretiyorsa ignore et; genel, çok dosya yakalayan bir
  aile imzasını tek bir FP yüzünden kapatma, önce clean kararıyla o dosyayı düzelt.

### 3.3 ML FP'si (`MalwareNet.PE.HighConfidence`, `MalwareNet.JS...`, APK)

ML kararları `.ign2` listelerinden **etkilenmez**. Sıra:

1. Dosyaya `clean` kararı ver (§3.1).
2. Dosyayı ML FP klasörüne koy (eğitimde temiz örnek olarak kullanılır):
   `usbdosyalar\ml_fp_benign\windows` (PE) ya da `...\ml_fp_benign\javascript` (JS).
3. Model yeniden eğitilince o tür dosyalar düzelir.
4. Gerekirse eşik: `POST /api/ml-thresholds {"pe": 0.92, "js": null, "apk": null}`
   (null = varsayılan; PE 0.90, JS 0.90, APK 0.80). Eşiği yükseltmek FP'yi azaltır ama
   zararlı kaçırmayı artırır; tek bir dosya için eşik değiştirme.

`open` / `alyzer/scan` çıktısındaki ML açıklaması, skoru hangi özelliklerin yukarı ittiğini
gösterir. Bilinen FP kalıpları:

- **Paketli/elle yazılmış küçük araçlar** (az import, IAT girdisi yok, yüksek entropi): model
  packer kabuğuna tepki verir. Örnek: GRC ValiDrive (PECompact).
- **.NET uygulamaları** (tek import `mscoree.dll`, 8 baytlık IAT): her .NET exe'si dışarıdan aynı
  görünür. Örnek: Remove Empty Directories (RED2).

### 3.4 İmzacı (signer) kaynaklı

- İmzası geçerli ve yayıncısı `signer_rules/trusted_signers.yaml`'de olan dosyalar ML'e gitmeden
  temiz sayılır. Meşru bir yayıncının dosyaları sürekli FP alıyorsa yayıncıyı bu listeye eklemeyi
  öner (listeyi kendin değiştirme; ana analist onaylar).
- Şirket izin/engel listeleri: `GET /api/companies`, `POST /api/companies`.

### 3.5 Kendi imzanı yazmak (zararlı için)

`POST /api/signatures`, `kind` şunlardan biri: `yara`, `hydradragonsig`, `clamav_ndb`, `clamav_ldb`.

```python
post("/api/signatures", {
    "kind": "hydradragonsig",
    "name": "Stealer.Win32.Lumma.A",
    "source": open("lumma.yaml", encoding="utf-8").read(),
})
```

- İsim, tehdit adı biçiminde olmalı.
- ClamAV ve HydraDragonSig hemen yeniden kurulur; YARA canlı motora eklenir.
- Kaydedilen her imza, tutulan bütün dosyalarda retrohunt ile denenir (`GET /api/retrohunt`).
  Retrohunt'ta temiz dosya yakalıyorsa imzayı daralt ya da sil (`/api/signatures/delete`).
- HydraDragonSig kural formatı: `HYDRADRAGONSIG_FORMAT.md`. İmzayı yalnızca o aileye özgü
  string/bayt kombinasyonlarından kur; temiz yazılımlarda da geçen string'leri tek başına kullanma.
- Import hash imzası (PE): `POST /api/imphash-signatures {"sha256", "threat"}`. .NET'te ve
  temiz dosyaların imphash'inde reddedilir.

---

## 4. Hızlı kontrol listesi

- [ ] `whoami` anahtarımı tanıyor mu?
- [ ] Dosyayı `review/start` ile üzerime aldım mı?
- [ ] Hangi motor işaretledi (imza mı, ML mi)?
- [ ] İmza ve yayıncı kontrol edildi mi?
- [ ] Paketliyse `unpack`, installer'sa `archive` ile içine bakıldı mı?
- [ ] Bilinmeyen string'ler ve `decompile` çıktısı incelendi mi?
- [ ] Karar ve tehdit adı (`Category.Platform.Family`) kaydedildi mi?
- [ ] FP ise doğru katmanda çözüldü mü (clean kararı → imza ignore + reload + rescan / ML FP klasörü)?
