# HydraDragonIDE practical fix

Bu paket, yüklediğin kırık dosyalardan tek parça çalışan proje iskeleti üretmek için toparlandı.

## Uygulanan ana düzeltmeler

- Root `Cargo.toml` artık Yew/WASM frontend bağımlılıklarıyla ayrıldı.
- `src-tauri/Cargo.toml` ayrı backend crate olarak düzenlendi.
- Kırık monolitik `src-tauri/src/main.rs` yerine ince giriş dosyası bırakıldı: `hydradragonide::run()`.
- Gerçek backend komutları modüler `src-tauri/src/lib.rs` üzerinden toplandı.
- Frontend'in invoke ettiği komutlar backend'de eşleştirildi:
  - `compute_entropy`
  - `extract_strings`
  - `parse_headers`
  - `scan_yara`
  - `disassemble_at`
  - `xor_*`
  - `base64_*`
- Shell ve opener plugin kayıtları backend'e eklendi.
- Trunk + Tauri yapılandırması tamamlandı.
- `build.py` düzeltilip `src-tauri/target/...` altındaki gerçek çıktı yoluna göre güncellendi.

## Bu pakette ne var

- Tek root frontend crate
- Ayrı `src-tauri/` backend crate
- Hex + disasm + YARA + XOR + Base64 + entropy + strings + PE/ELF headers akışı
- Tek pencere IDE düzeni

## Dürüst not

Bu ortamda Rust toolchain olmadığı için burada derleme testi yapamadım. Yapılan iş yapısal ve kaynak düzeyinde fix'tir; yerel makinede `cargo`, `rustup`, `trunk`, `cargo-tauri` ile build etmen gerekir.
