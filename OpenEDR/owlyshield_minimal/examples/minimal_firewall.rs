// Minimal harness: firewall engine standalone, edrsvc.exe yok.
// Derle: cargo build --release --example minimal_firewall
// Calistir (ADMIN shell): .\target\release\examples\minimal_firewall.exe
// Bisect: C:\ProgramData\edrsvc\firewall_settings.json degistir, yeniden baslat.
// Profil: ayri admin shell'de `wpr -start CPU -filemode`, 30-60sn trafik,
// `wpr -stop C:\Temp\cpu.etl` -> WPA ile PDB'li analiz.
// Durdurma: Ctrl-C (divert handle kapanir, trafik normale doner).
fn main() {
    owlyshield_ransom::firewall::run();
}
