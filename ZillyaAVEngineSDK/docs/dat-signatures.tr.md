# Zillya AVEngine `.dat` Imza Dosyalari

`bin\aveng` klasoru yalnizca DLL ve EXE dosyalari degil, motorun algilama veritabanlarini da icerir. SDK tarafinda bu klasor `TCoreInit_Interface` icindeki iki alanla motora verilir:

- `EPath`: antivirus engine DLL/EXE dosyalarinin bulundugu klasor.
- `VPath`: virus veritabani ve imza dosyalarinin bulundugu klasor.

Bu pakette iki alan da pratikte `aveng` klasorunu isaret eder. `CoreMain.DLL`, tarama baslatilirken `.dat` dosyalarini kendi kapali formatinda yukler.

## Format hakkinda

Bu dosyalar metin tabanli YARA, ClamAV `.ndb` veya kolayca elle duzenlenebilir imza listeleri degildir. Ornek ilk baytlar sunu gosterir:

- `vs000005.dat`: `5A 49 4C 32`, yani ASCII `ZIL2`
- `vl005.dat`: `5A 49 4C 31`, yani ASCII `ZIL1`
- `wlist.dat`: `5A 49 4C 33`, yani ASCII `ZIL3`
- `release.dat`: duz metin yayin zamani, bu pakette `2020.02.25 14:31`
- `vs000001.dat`: `DELETED`

Bu nedenle `.dat` dosyalari Zillya motorunun kapali ikili veritabani bloklari olarak ele alinmali; elle degistirilmemeli, yeniden adlandirilmamali ve tek tek secilerek karistirilmamalidir.

## Dosya gruplari

- `vsNNNNNN.dat`: asil malware imza veritabani bloklari. Buyuk dosyalar ana imza setini, daha yuksek numarali kucuk dosyalar ise ek veya artimli veritabani parcalarini temsil eder.
- `vlNNN.dat`: virus adlari, aile etiketleri veya algilama metaverisi gibi motorun imza sonucunu anlamlandirmasina yardimci ek veritabani dosyalari olarak kullanilir.
- `wlist.dat` ve `wf001.dat`: adlandirmaya ve konuma gore whitelist / guvenilir nesne yardimci verileri olarak ele alinmali.
- `nexcl.dat`: motorun dislama veya ozel kural yardimci verileri icin kullanilan kucuk bir ikili veridir.
- `fr001.dat`, `pa001.dat`, `vpedia_*.dat`: motorun ek kaynak, paket veya yerellestirilmis virus ansiklopedisi/metaveri dosyalari.
- `release.dat` ve `avbd.ver`: imza setinin yayin tarihi/surum bilgisini tasiyan kucuk metaveri dosyalari.

## Operasyonel notlar

- `.dat` seti tutarli bir butun olarak dagitilmalidir. Eksik veya uyumsuz parcalar algilama kaybina ya da `CoreInit` hatasina yol acabilir.
- Guncelleme gerekiyorsa tek tek dosya duzenlemek yerine guvenilir kaynaktan gelen tam veritabani setiyle degistir.
- Dagitimdan once `license.rtf` kosullarini kontrol et; imza veritabanlari ve motor DLL'leri uzerinde yeniden dagitim kisitlari olabilir.
- Uygulama tarafinda yeni imza konumu kullanmak icin `CoreInit` cagrilarinda `VPath` alanini ilgili klasore ver.
