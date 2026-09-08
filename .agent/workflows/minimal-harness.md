---
description: 2023 taktigi - minimal harness ile katman bisect ve PDB'li CPU teshi.
---

# Minimal-Harness ile Bug Teşhisi (2023 taktiği)

Tahmin yok, yarıyı böl: edrsvc yok, DLL tek başına, katman katman kapat, PDB ile ölç.

> Çekirdek kural: tıkandığında parçaları **kırparak** ilerle — bozuk kısım
> gidene kadar component çıkar, gidiş noktasını bulunca oradan devam et.

## 1. Minimal çağıran

`OpenEDR/owlyshield_predict/examples/minimal_firewall.rs` — `firewall::run()` çağırır.

```powershell
cargo build --release --example minimal_firewall
# ADMIN shell:
.\target\release\examples\minimal_firewall.exe
```

Filtre `true` — tüm trafik diverte olur. Ctrl-C handle'ı kapatır, trafik döner.

## 2. Katman merdiveni (settings, derleme yok)

`C:\ProgramData\edrsvc\firewall_settings.json` + servis/harness restart. Her adım 2-3 dk trafik:

1. Baz CPU'yu yaz.
2. `tls_proxy.auto_start=false` → proxy yok (düştü = MITM tarafı).
3. `auto_start=true` + `mitm_all_traffic=false` + `monitored_hosts=[]` → proxy boşta.
4. `save_all_logs=false` → log writer kapalı.
5. `models/` klasörünü taşı (`pe_model.mpk`, `js_model.mpk` yoksa inference atlanır).

## 3. Yakalama (VM ya da local)

```cmd
wpr -start CPU -filemode
:: 30-60sn bozuk halde bekle
wpr -stop C:\Temp\cpu.etl
```

## 4. PDB ile çözüm (dev makinede)

DLL+PDB aynı klasörde olmalı (`target\release`). Derleme profili:
`[profile.release] debug = "line-tables-only"`.

```powershell
$dbh = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\dbh.exe"
$sp = "<target\release dizini>"; $dll = "$sp\owlyshield_ransom.dll"
& $dbh -s:$sp $dll 'x *sembol_parcasi*'   # adres bul
& $dbh -s:$sp $dll 'laddr <hexadres>'     # adres -> dosya:satir
```

Export-relative offset hesabı: `baz_adres + offset = hedef`, sonra `laddr hedef`.
Örn: `set_mitm(0x141a070)+0x4f1210 = 0x190B280` → `laddr 190B280`.

## 5. Tuzaklar (öğrenildi, tekrar düşme)

- System Informer `modül!sembol+0x...` isimleri PDB'siz VM'de **export-tabanlıdır**;
  `set_mitm_enabled+0x4f...` gibi +MB offsetler anlamsızdır, gerçek adresi PDB ile çöz.
- Offsetler **derlemeye özeldir**; eski sample'ı yeni PDB ile çözmek çöp verir (fs.rs/capstone datasına düşer).
- Kesin isim için PDB'yi DLL'nin yanına koy (VM dahil) ya da ham `modül+offset` satırlarını dev makinede çöz.
- Stack tek frame'e düşerse (`ntdll!ZwWaitForAlertByThreadId` gibi) walk başarısızdır;
  aynı hot TID'nin IP satırından 5-10 örnek topla, dağılıma bak.
- Soğuk thread (binlerce cycles) ile yakan thread'i (milyarlarca cycles) karıştırma.
- `aws-lc` jitter CPU yakarsa derleme anahtarı (pin YOK, sürüm aynı kalır):
  `owlyshield_predict/.cargo/config.toml` içinde `[env] AWS_LC_SYS_NO_JITTER_ENTROPY = "1"`,
  sonra aws-lc-sys fingerprintlerini silip `cargo build --release`.
  Doğrulama: yeni PDB'de `x *jent_read_entropy*` boş, `x *opt_out_cpu_jitter_get_seed*` dolu dönmeli.
- Steer edilip accept'e dönmeyen SYN'lerde `netstat -ano | findstr 8877`:
  `SYN_RECEIVED` yığılması = SYN-ACK gidemiyor. Sebebi steer'da SRC'yi de
  127.0.0.1'e yazmaktı (o porta bağlı soket yok) — SADECE DST yazılır,
  dönüş bacağı NAT tablosuyla düzelir.
- `Cargo.lock` sessizce eski haline dönebilir; derlemeden önce `aws-lc-rs`/`aws-lc-sys`
  sürümlerini kilitte doğrula.
- 2026-09 vakası: `rules.yaml` içindeki `!include emerging-all.yaml metadata_only`
  satırındaki modifier kodda yok sayılıyordu → 50.422 ET kuralı her pakette koşuyor,
  worker'lar yetişemeyip kernel kuyruğu taşıyordu (`allowed` ama ölü trafik + DNS
  sürünmesi). Çözüm: `sdk.rs` include ayrıştırıcı modifier'a uyuyor (kural
  eklemiyor, sadece `monitored_sites` birleştiriyor).
