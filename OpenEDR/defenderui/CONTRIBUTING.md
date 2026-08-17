# Contributing to DefenderUI

First off — **thank you for considering contributing to DefenderUI!** 🎉

DefenderUI is a community-driven WinUI 3 UI/UX showcase, and every contribution, whether it's a typo fix, a new animation, a bug report, or a full-blown feature, is genuinely appreciated.

This document lays out the guidelines to make contributing smooth for everyone.

---

## 📋 Table of Contents

- [Code of Conduct](#-code-of-conduct)
- [How Can I Contribute?](#-how-can-i-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Features](#suggesting-features)
  - [Submitting Pull Requests](#submitting-pull-requests)
- [Development Setup](#-development-setup)
- [Coding Style](#-coding-style)
- [Commit Message Convention](#-commit-message-convention)
- [Pull Request Process](#-pull-request-process)
- [Project Architecture](#-project-architecture)

---

## 📜 Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the maintainers.

---

## 🤝 How Can I Contribute?

### Reporting Bugs

Before opening a bug report:

1. **Search existing issues** to make sure it hasn't already been reported.
2. **Reproduce the bug** on the latest `main` branch.
3. **Collect information:** OS version, .NET version, architecture, reproduction steps.

Then open an issue using the [**Bug Report template**](.github/ISSUE_TEMPLATE/bug_report.yml). Good bug reports include:

- A clear, descriptive title
- Exact steps to reproduce
- Expected behavior vs. actual behavior
- Screenshots or short screen recordings (GIF) if the bug is visual
- Relevant log output or exception text

### Suggesting Features

Have an idea for a new animation, page, control, or polish pass? We'd love to hear it.

Open an issue using the [**Feature Request template**](.github/ISSUE_TEMPLATE/feature_request.yml) and include:

- The problem / motivation your idea solves
- A clear description of the proposed solution
- (Optional) mockups, sketches, or reference screenshots from other apps

### Submitting Pull Requests

Pull requests are the best way to propose concrete changes. For non-trivial changes, please open an issue first to discuss the approach — this saves everyone time.

---

## 🛠️ Development Setup

### Prerequisites

- **Windows 11** (or Windows 10 build 19041+)
- **.NET 9 SDK** — [Download](https://dotnet.microsoft.com/download/dotnet/9.0)
- **Developer Mode** enabled: `Settings → System → For developers`
- **Visual Studio 2022** with the *Windows App SDK C# Templates* workload, or **VS Code** with the C# Dev Kit extension

### Build

```powershell
# Clone your fork
git clone https://github.com/caymazyusuf72/defenderui.git
cd defenderui

# Detect architecture
$Platform = $env:PROCESSOR_ARCHITECTURE

# Restore & build
dotnet restore
dotnet build -c Debug -p:Platform=$Platform
```

### Run

```powershell
dotnet run -c Debug -p:Platform=$Platform
```

See [`README.md`](README.md) for more build/run details.

---

## 🎨 Coding Style

### C# Conventions

- **Nullable reference types** are enabled project-wide — respect nullability annotations.
- **File-scoped namespaces** where applicable.
- **`var`** for obvious types, explicit types when clarity matters.
- **`async`/`await`** all the way down — avoid `.Result` and `.Wait()`.
- **`[ObservableProperty]`** and **`[RelayCommand]`** attributes (from `CommunityToolkit.Mvvm`) instead of hand-writing boilerplate.
- **Guard clauses** over nested `if` pyramids.
- **XML doc comments** on public APIs.
- Follow the analyzer rules enabled by the project (StyleCop/CA*/IDE*).

### XAML Conventions

- Prefer **`x:Bind`** over `Binding` for performance and compile-time safety.
- Use **`x:Load`** to defer expensive visual trees that aren't immediately needed.
- Add **`AutomationProperties.Name`** / **`AutomationProperties.HelpText`** on all interactive controls for accessibility.
- Keep **resource dictionaries** organized — colors, typography, card styles, button styles, and animations live in separate files under `Styles/`.
- Use **`ThemeResource`** for any color/brush references so light/dark theming keeps working.
- Virtualized lists (`ItemsRepeater`, `ListView`) for any collection that could exceed ~50 items.

### Folder Layout

Please respect the existing folder layout (see [ARCHITECTURE.md](ARCHITECTURE.md)):

```
Views/          XAML pages
ViewModels/     MVVM view-models
Models/         POCOs / enums
Services/       Mock data + (future) DI-registered services
Helpers/        Attached properties, converters, composition effects
Styles/         Resource dictionaries
Controls/       Reusable custom controls
Assets/         Icons / images
```

### Animations

Animations are a **key identity feature** of this project. When adding or modifying animations:

- Prefer the **Composition API** (`Windows.UI.Composition`) for GPU-accelerated, 60 fps motion.
- Keep durations short — typically **150–400 ms**.
- Use **easing functions** (cubic, back, spring) — avoid linear where it feels robotic.
- Respect the user's **"Reduce motion"** system setting where applicable.
- Don't block the UI thread.

---

## 📝 Commit Message Convention

We follow **[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)**. This keeps history readable and enables automated changelog generation.

### Format

```
<type>(<optional scope>): <short summary>

<optional body>

<optional footer(s)>
```

### Types

| Type | Purpose |
|---|---|
| `feat` | A new feature or user-visible improvement |
| `fix` | A bug fix |
| `docs` | Documentation only |
| `style` | Formatting, whitespace, missing semicolons — no code logic change |
| `refactor` | Code restructuring without functional changes |
| `perf` | Performance improvement |
| `test` | Adding or updating tests |
| `build` | Build system, packages, or CI configuration |
| `chore` | Misc. maintenance |

### Examples

```
feat(scan): add pulse glow effect around scan progress ring
fix(dashboard): kpi odometer restarts incorrectly on navigation
docs(readme): update build command for ARM64
refactor(helpers): extract ripple effect into attached property
```

---

## 🔁 Pull Request Process

1. **Fork** the repository and create a feature branch from `main`:
   ```powershell
   git checkout -b feat/my-awesome-animation
   ```
2. **Make your changes** following the style guide above.
3. **Build locally** and make sure there are no new warnings:
   ```powershell
   $Platform = $env:PROCESSOR_ARCHITECTURE
   dotnet build -c Debug -p:Platform=$Platform
   ```
4. **Test the app manually** — click through every page the change could affect.
5. **Update docs** if you changed behavior or added a feature ([`README.md`](README.md), [`ARCHITECTURE.md`](ARCHITECTURE.md), [`CHANGELOG.md`](CHANGELOG.md) under `[Unreleased]`).
6. **Write a descriptive PR title** following the commit convention.
7. **Fill in the PR template** completely, including screenshots/GIFs for any UI change.
8. **Respond to review feedback** — we'll usually respond within a few days.

### PR Checklist

- [ ] The PR description clearly explains the *what* and the *why*.
- [ ] `dotnet build` passes with zero new warnings.
- [ ] UI changes include before/after screenshots or a short GIF.
- [ ] New public APIs have XML doc comments.
- [ ] Accessibility hasn't regressed (keyboard nav, AutomationProperties).
- [ ] `CHANGELOG.md` has an entry under `[Unreleased]` if user-visible.

---

## 🏛️ Project Architecture

Please read [`ARCHITECTURE.md`](ARCHITECTURE.md) before making structural changes. It covers:

- Page-by-page responsibilities
- MVVM layer boundaries
- DI registration
- Design tokens (colors, typography, spacing)
- Mock data contracts

---

## ❓ Questions?

If something's unclear, open a [Discussion](https://github.com/caymazyusuf72/defenderui/discussions) or a regular issue tagged `question`. There are no silly questions — if the docs didn't answer it, that's a doc bug worth fixing.

---

**Thank you again for helping make DefenderUI better!** 🛡️✨