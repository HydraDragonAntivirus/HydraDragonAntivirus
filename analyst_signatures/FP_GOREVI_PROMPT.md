# FP görevi (kullanıcı promptu, 2026-10-24)

Orijinal istek:

> 127.0.0.1:9440 gir antimalware_docs bak, `<analist anahtarı> Claude [ai]` bu api keyi kullan
> benim serverımda ve false positiveleri hallet imza tabanlı olanları (virüs imzaları gerçek ve
> insan analizine sahip olanlar gerçek; false positive verenler genelde yeni tespitler ve bana sor
> bariz false positive değilse ve viruskovalyzer kullan bu promptu kaydet docs klasörüne) birde
> şuna dikkat et analist imzalarıda false positive veriyor onları da düzeltip hallet

Ek mesajlar:

> makine öğrenimi olanlar kalsın

> onları genel olarak false positive işaretle ve false positive sebebiyle söyle birde kaynak kodu
> lazımsa buradan bak https://github.com/HydraDragonAntivirus/HydraDragonAntivirus

## Özet kurallar

- Kapsam: yalnızca **imza tabanlı** tespitler (ClamAV / YARA / HydraSig / analist imzaları).
  ML tespitleri (`MalwareNet.*`) **kapsam dışı, dokunulmaz**.
- Gerçek virüs imzaları ve insan analizi olan kararlar gerçek kabul edilir.
- FP'ler genelde yeni tespitlerdir; analist imzaları da FP verebilir, onlar da düzeltilir.
- Analiz VirusKovAlyzer ile yapılır (dosyalar asla çalıştırılmaz).
- Bariz FP değilse kullanıcıya sorulur.
- FP olarak işaretlenen her imza için sebep yazılır ve kullanıcıya raporlanır.
- Anahtar: `antimalware_server/analyst_keys.txt` içindeki `Claude [ai]` satırı (bu dosyaya düz yazılmadı).
