# Screenshots

This folder holds screenshots used by the project [`README.md`](../../README.md) and documentation.

## How to contribute screenshots

Run the app locally (see [`README.md` — Getting Started](../../README.md#-getting-started)) and capture the following pages in **dark mode** at a **1280×800** (or larger) window size:

| Filename | Page | What to capture |
|---|---|---|
| `dashboard.png` | Dashboard | Hero status card + KPI row + recent activity |
| `scan.png` | Scan | Scan in progress — progress ring + scan-line animation frame |
| `protection.png` | Protection | All 6 protection module toggles |
| `quarantine.png` | Quarantine | Threat list with risk badges |
| `reports.png` | Reports | Animated charts / trend section |
| `update.png` | Update | Update hero + history list |
| `settings.png` | Settings | A representative settings category |

### Guidelines

- **Format:** PNG (lossless)
- **Size:** Keep each file under ~500 KB (use `pngquant` or similar if needed)
- **Window chrome:** Either crop out the Windows title bar, or keep it consistent across all shots
- **Content:** Only use the mocked sample data — no personal information
- **Animations:** For animated effects, consider capturing a short GIF (≤ 3 MB) and naming it `<page>.gif`

Once added, reference them from [`README.md`](../../README.md) using relative paths like `.github/screenshots/dashboard.png`.

> Screenshots are optional for a local build but highly encouraged for showcasing the project on GitHub.