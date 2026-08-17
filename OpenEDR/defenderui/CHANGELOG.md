# Changelog

All notable changes to **DefenderUI** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- 📦 **Single-file self-contained publish** — kullanıcılar artık .NET Runtime kurmadan tek bir `DefenderUI.exe` ile uygulamayı çalıştırabilir.
  - Tüm mimariler için (`win-x86`, `win-x64`, `win-arm64`) [`Properties/PublishProfiles/`](Properties/PublishProfiles/) altında `PublishSingleFile=true`, `SelfContained=true`, `IncludeNativeLibrariesForSelfExtract=true`, `IncludeAllContentForSelfExtract=true` ve `EnableCompressionInSingleFile=true` ayarlarıyla hazır profiller.
  - Lokal kullanım: `dotnet publish -c Release -p:Platform=x64 -p:PublishProfile=win-x64`.
- 🚀 **Release workflow'u** ([`.github/workflows/release.yml`](.github/workflows/release.yml)) artık her mimari için hem tek dosyalık `DefenderUI-<arch>.exe` hem de tam içerikli `DefenderUI-<arch>.zip` arşivini GitHub Release'e otomatik olarak ekler.
- 🔔 **MainWindow** başlık çubuğundaki `NotificationsButton` artık çalışıyor — `IToastService` üzerinden bilgi toast'u gösteren bir `Click` handler eklendi.

### Fixed
- 🛡️ **P0 — `App` kurucu sırası (K1):** `InitializeComponent()` artık `ConfigureServices()`'ten önce çağrılıyor; UI dispatcher'a bağlı olan ViewModel'lerin güvenli şekilde resolve edilmesini sağlar.
- 🧵 **P0 — `ScanViewModel.RunOnUi` null-safety (K3):** `DispatcherQueue.GetForCurrentThread()` null dönerse çağrı anında tekrar resolve edilir; çökmelerin önüne geçildi.
- 🧹 **P0 — `ScanService` double-dispose + event güvenliği (K4, U25):** `_cts` / `_pauseGate` `ObjectDisposedException` ile korunuyor; `ProgressChanged` / `ScanCompleted` / `ScanCancelled` çağrıları `try/catch` içinde ve `ScanCompleted` / `ScanCancelled` artık `ResetState()` öncesi fire ediliyor.
- 🔁 **P0 — `ActualThemeChanged` event leak'leri (K12):** [`StatusHeroCard`](Controls/StatusHeroCard.xaml.cs), [`ProtectionModuleCard`](Controls/ProtectionModuleCard.xaml.cs), [`ActivityListItem`](Controls/ActivityListItem.xaml.cs), [`StatCard`](Controls/StatCard.xaml.cs), [`FeatureTileCard`](Controls/FeatureTileCard.xaml.cs), [`ScanModeCard`](Controls/ScanModeCard.xaml.cs) ve [`StatusPill`](Controls/StatusPill.xaml.cs) artık tema-değişim aboneliklerini `Loaded`/`Unloaded` çiftinde named method üzerinden yönetiyor — control kaldırıldığında handler sökülüyor.
- 🎨 **P0 — `Styles/Colors.xaml` HighContrast eksik key'ler (K11):** HighContrast tema sözlüğüne Light/Dark'ta var olan tüm `Color x:Key` girdileri (`AccentColor`, `SuccessColor`, `WarningColor`, `DangerColor`, `InfoColor`, `TextPrimaryColor` vb.) HC-uyumlu değerlerle eklendi.
- 🧯 **P1 — `App.OnUnheadledException` (K2):** `e.Handled = true` yalnızca Release'te uygulanıyor; Debug'ta exception'lar artık debugger'a düşüyor.
- ♻️ **P1 — Shutdown'da `ServiceProvider.Dispose` (K5):** `MainWindow.Closed` üzerinde DI container'ı `IDisposable.Dispose()` ile temizliyor.
- 🛎️ **P1 — `ToastHost` çift subscribe koruması (K6):** `OnLoaded` başında `Loaded -= OnLoaded;` eklendi; aynı kontrol yeniden visual tree'ye eklendiğinde çift abonelik riskini kaldırır.
- 🧼 **P1 — `ScanPage.AddPathButton_Click` artık `async void` değil (K8):** Gerçek bir await içermediği için method senkron hale getirildi.
- 📏 **P1 — `AnimationHelper.StartGlowPulse` / `CenterAnchor` `SizeChanged` leak (U7, U8):** Attached `DependencyProperty` (`GlowSizeChangedHandlerProperty`, `CenterAnchorHandlerProperty`) ile mevcut handler cache'lenip yeniden atanırken detach ediliyor; aynı element'i birden fazla kez animate etmek artık handler biriktirmiyor.
- 📌 **P1 — `DefenderUI.csproj` paket sürümleri pinlendi (U22):** `Microsoft.WindowsAppSDK` → `1.8.260317003`, `Microsoft.Windows.SDK.BuildTools` → `10.0.28000.1721`, `CommunityToolkit.Mvvm` → `8.4.2`, `Microsoft.Extensions.DependencyInjection` → `9.0.15`. Reproducible build için floating `*` kaldırıldı.
- ℹ️ **P1 — Dashboard disabled `ToggleSwitch` UX (U27):** Koruma modülleri özetindeki pasif switch'e yapılandırmanın Koruma sayfasından yapılması gerektiğini belirten `ToolTip` ve yumuşatılmış opaklık eklendi.

---

## [1.0.0] — 2026-04-17

### Added
- 🎉 **Initial public release** of DefenderUI — a premium WinUI 3 antivirus UI concept.
- **Seven fully-featured pages**:
  - **Dashboard** — Hero protection status card, KPI row (scanned files, blocked threats, quarantined items, security score), real-time protection panel, last scan summary, update status, recent activity log, and alert InfoBars.
  - **Scan** — Four scan types (Quick, Full, Custom, USB), circular progress ring with percentage and scan-line effect, file count / elapsed / ETA display, live detected-threats list, and Pause/Stop/Continue controls.
  - **Protection** — Six protection modules (Real-time, Web, File, Ransomware, Email, Network) with per-module toggles, descriptions, and statistics.
  - **Quarantine** — Card-based threat list with risk badges, search & filter, bulk delete, and restore/delete per item.
  - **Reports** — Segmented time filter (7 / 30 / 90 days), trend charts, summary KPI cards, and threat-type distribution.
  - **Update** — Version info, update hero card, manual update with progress bar, and update history.
  - **Settings** — Eight categories (General, Protection, Notifications, Update, Privacy, Appearance, Scheduled Scans, Exclusions) with left-rail navigation.
- **Premium design system**:
  - Dark theme with Mica backdrop (native Windows 11 look & feel)
  - Custom color tokens, typography scale, and reusable card / button styles
  - Rounded corners, soft shadows, elevation cards
- **Comprehensive animation system** powered by the Windows Composition API (GPU-accelerated, 60 fps):
  - Staggered entrance animations on page navigation
  - Card hover lift with translation and shadow elevation
  - Button spring-back press/release effects
  - Ripple effect from pointer position
  - Continuous glow pulse on hero status card
  - Progress shimmer on scan / update bars
  - Vertical scan-line across the scan progress ring
  - Odometer count-up on KPI numbers
  - Smooth fade + slide page transitions
- **Full MVVM architecture** built on `CommunityToolkit.Mvvm` (`[ObservableProperty]`, `[RelayCommand]`).
- **Dependency Injection** via `Microsoft.Extensions.DependencyInjection` (services and view-models registered in `App.xaml.cs`).
- **Mock data service** (`MockDataService`) providing realistic sample data for every page — tarama, tehdit, güncelleme ve rapor verilerini simüle eder.
- **Accessibility** — `AutomationProperties` on interactive controls, keyboard navigation, and theme-resource-driven colors for proper contrast.
- **Supported architectures**: `x86`, `x64`, `ARM64`.
- **Packaging**: Unpackaged (`WindowsPackageType=None`) for easy `dotnet run` launch.

### Documentation
- `README.md` with badges, feature list, screenshots section, and getting-started guide
- `ARCHITECTURE.md` documenting project structure, pages, MVVM layers, and design tokens
- `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`
- GitHub issue templates (bug / feature), PR template, and issue-chooser config

---

[Unreleased]: https://github.com/caymazyusuf72/defenderui/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/caymazyusuf72/defenderui/releases/tag/v1.0.0