#!/usr/bin/env python3
"""
HydraDragon Firewall Build Script
Run as Administrator for WinDivert driver
Usage:
    python build.py              # debug build
    python build.py --release    # release build
    python build.py --release --run  # release build + launch
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

# ── Colours ────────────────────────────────────────────────────────────────────
CYAN    = "\033[96m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
RED     = "\033[91m"
MAGENTA = "\033[95m"
GRAY    = "\033[90m"
RESET   = "\033[0m"

def cyan(s):    return f"{CYAN}{s}{RESET}"
def yellow(s):  return f"{YELLOW}{s}{RESET}"
def green(s):   return f"{GREEN}{s}{RESET}"
def red(s):     return f"{RED}{s}{RESET}"
def magenta(s): return f"{MAGENTA}{s}{RESET}"
def gray(s):    return f"{GRAY}{s}{RESET}"

def header(msg): print(cyan("=" * 48)); print(cyan(f"  {msg}")); print(cyan("=" * 48))
def step(n, msg): print(yellow(f"\n[{n}] {msg}"))
def ok(msg):   print(green(f"      {msg}"))
def warn(msg): print(yellow(f"  WARNING: {msg}"))
def fail(msg): print(red(f"  ERROR: {msg}")); sys.exit(1)

# ── Dependency checks ──────────────────────────────────────────────────────────

def prompt_install(name: str, install_cmd: list) -> None:
    """Ask the user whether to install a missing tool."""
    answer = input(f"\n  {yellow(f'`{name}` is not installed. Install it now? [Y/n]: ')}")
    answer = answer.strip().lower()
    if answer not in ("", "y", "yes"):
        fail(f"`{name}` is required. Install it manually and re-run.")
    print(yellow(f"      Running: {' '.join(install_cmd)}"))
    result = subprocess.run(install_cmd)
    if result.returncode != 0:
        fail(f"Installation of `{name}` failed.")
    # Refresh PATH in-process for tools installed to ~/.cargo/bin
    cargo_bin = Path.home() / ".cargo" / "bin"
    if str(cargo_bin) not in os.environ.get("PATH", ""):
        os.environ["PATH"] = str(cargo_bin) + os.pathsep + os.environ.get("PATH", "")
    if not shutil.which(name):
        fail(f"`{name}` still not found after install — restart your terminal and re-run.")
    ok(f"`{name}` installed: {shutil.which(name)}")

def check_tool(name: str, install_cmd: list) -> str:
    """Return the full path to `name`, prompting to install if missing."""
    path = shutil.which(name)
    if path:
        print(gray(f"      {name} found: {path}"))
        return path
    prompt_install(name, install_cmd)

def check_rustup_target(target: str):
    result = subprocess.run(
        ["rustup", "target", "list", "--installed"],
        capture_output=True, text=True
    )
    if target in result.stdout:
        print(gray(f"      rustup target {target} already installed"))
        return
    print(yellow(f"      Installing rustup target {target}..."))
    run(["rustup", "target", "add", target])

def check_dependencies():
    step("0/4", "Checking dependencies...")

    check_tool("cargo",   ["winget", "install", "Rustlang.Rustup"])
    check_tool("rustup",  ["winget", "install", "Rustlang.Rustup"])
    check_tool("trunk",   ["cargo", "install", "trunk"])

    # Tauri CLI is optional — only needed for `cargo tauri dev/build`.
    # This script calls `cargo build` directly, but warn if it's missing.
    tauri_cli = shutil.which("cargo-tauri")
    if tauri_cli:
        print(gray(f"      cargo-tauri found: {tauri_cli}"))
    else:
        answer = input(f"\n  {yellow('`cargo-tauri` is not installed. Install it now? [Y/n]: ')}").strip().lower()
        if answer in ("", "y", "yes"):
            run(["cargo", "install", "tauri-cli"])
            ok("cargo-tauri installed.")
        else:
            warn("`cargo-tauri` skipped — `cargo tauri dev/build` won't work without it.")

    check_rustup_target("wasm32-unknown-unknown")
    ok("All required dependencies present.")

# ── Helpers ────────────────────────────────────────────────────────────────────

def run(cmd: list, cwd: Path = None, env: dict = None):
    merged_env = {**os.environ, **(env or {})}
    result = subprocess.run(cmd, cwd=cwd, env=merged_env)
    if result.returncode != 0:
        fail(f"Command failed (exit {result.returncode}): {' '.join(str(c) for c in cmd)}")

def robust_copy(src: Path, dst: Path):
    if src.exists():
        try:
            shutil.copy2(src, dst)
            print(gray(f"      Copied {src.name} → {dst}"))
        except Exception as e:
            warn(f"Failed to copy {src} → {dst}: {e}")
            warn("Hint: Make sure the application is not running.")
    else:
        warn(f"Source not found: {src}")

# ── Build steps ────────────────────────────────────────────────────────────────

def build_ui(script_dir: Path):
    step("1/4", "Building UI with Trunk...")
    ui_dir = script_dir / "ui"
    dist_dir = script_dir / "dist"
    if not ui_dir.exists():
        fail(f"UI directory not found: {ui_dir}")
    run(["trunk", "build", "--dist", str(dist_dir)], cwd=ui_dir)
    ok("UI build complete!")

def build_rust(script_dir: Path, release: bool, windivert_path: Path):
    flag = "release" if release else "debug"
    step("2/4", f"Building Rust backend ({flag})...")
    cmd = ["cargo", "build"]
    if release:
        cmd.append("--release")
    run(
        cmd,
        cwd=script_dir,
        env={
            "WINDIVERT_PATH":    str(windivert_path),
            "WINDIVERT_LIB_DIR": str(windivert_path),
        }
    )
    ok("Rust build complete!")

def copy_windivert(script_dir: Path, release: bool, windivert_path: Path):
    step("3/4", "Copying WinDivert runtime files...")
    target_dir = script_dir / "target" / ("release" if release else "debug")
    for fname in ["WinDivert.dll", "WinDivert64.sys"]:
        robust_copy(windivert_path / fname, target_dir / fname)

    # Also mirror the exe into the everything/ folder for easy deployment
    exe_src = target_dir / "hydradragonfirewall.exe"
    robust_copy(exe_src, windivert_path / "hydradragonfirewall.exe")

# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="HydraDragon Firewall Build Script")
    parser.add_argument("--release", action="store_true", help="Build in release mode")
    parser.add_argument("--run",     action="store_true", help="Launch the app after building")
    args = parser.parse_args()

    # Enable ANSI colours on Windows
    if sys.platform == "win32":
        os.system("")

    header("HydraDragon Firewall Build System")

    script_dir    = Path(__file__).resolve().parent
    windivert_path = (script_dir / ".." / "everything").resolve()

    check_dependencies()
    build_ui(script_dir)
    build_rust(script_dir, args.release, windivert_path)
    copy_windivert(script_dir, args.release, windivert_path)

    target_dir = script_dir / "target" / ("release" if args.release else "debug")
    exe = target_dir / "hydradragonfirewall.exe"

    step("4/4", "Build Successful!")
    print(cyan(f"\n  Executable: {exe}"))
    print(cyan("=" * 48))
    print(yellow("  IMPORTANT: Run the executable as Administrator"))
    print(yellow("  for WinDivert network capture to work!"))
    print(cyan("=" * 48))

    if args.run:
        print(magenta("\n  Launching application (UAC prompt expected)..."))
        os.startfile(str(exe))  # Windows ShellExecute — triggers UAC RunAs


if __name__ == "__main__":
    main()
