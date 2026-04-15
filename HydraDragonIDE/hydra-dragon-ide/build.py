#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
HydraDragonIDE Build Script
Usage:
    python build.py              # debug build
    python build.py --release    # release build
    python build.py --run        # debug build + launch
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

def check_tool(name: str) -> str:
    path = shutil.which(name)
    if path:
        print(gray(f"      {name} found: {path}"))
        return path
    fail(f"`{name}` is not installed. Please install it and re-run.")

def check_dependencies():
    step("0/3", "Checking dependencies...")
    check_tool("cargo")
    check_tool("trunk")
    
    # Check for wasm32 target
    result = subprocess.run(["rustup", "target", "list", "--installed"], capture_output=True, text=True)
    if "wasm32-unknown-unknown" not in result.stdout:
        print(yellow("      Installing wasm32-unknown-unknown target..."))
        subprocess.run(["rustup", "target", "add", "wasm32-unknown-unknown"])
    
    ok("All dependencies present.")

# ── Build steps ────────────────────────────────────────────────────────────────

def build_ui(release: bool):
    step("1/3", f"Building UI with Trunk ({ 'release' if release else 'debug' })...")
    cmd = ["trunk", "build"]
    if release:
        cmd.append("--release")
    
    result = subprocess.run(cmd)
    if result.returncode != 0:
        fail("UI build failed.")
    ok("UI build complete!")

def build_backend(release: bool):
    step("2/3", f"Building Tauri backend ({ 'release' if release else 'debug' })...")

    # `cargo build` in debug mode still points the Tauri app at `build.devUrl`,
    # which causes a "connection refused" error unless `trunk serve` is running.
    # `cargo tauri build --debug --no-bundle` builds a normal debug executable
    # against `frontendDist` without starting the dev loop or requiring localhost.
    cmd = ["cargo", "tauri", "build", "--no-bundle"]
    if release:
        pass
    else:
        cmd.append("--debug")

    result = subprocess.run(cmd)
    if result.returncode != 0:
        fail("Backend build failed.")
    ok("Backend build complete!")

# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="HydraDragonIDE Build Script")
    parser.add_argument("--release", action="store_true", help="Build in release mode")
    parser.add_argument("--run",     action="store_true", help="Launch the app after building")
    args = parser.parse_args()

    header("HydraDragonIDE Build System")
    
    script_dir = Path(__file__).resolve().parent
    os.chdir(script_dir)

    check_dependencies()
    build_ui(args.release)
    build_backend(args.release)

    target_dir = script_dir / "target" / ("release" if args.release else "debug")
    exe = target_dir / "hydradragonide.exe"

    step("3/3", "Build Successful!")
    if exe.exists():
        print(cyan(f"\n  Executable: {exe}"))
    else:
        warn(f"Executable not found at {exe}. Check your build output.")
    
    print(cyan("=" * 48))

    if args.run:
        if exe.exists():
            print(magenta("\n  Launching application..."))
            subprocess.Popen([str(exe)])
        else:
            fail("Cannot run: Executable not found.")

if __name__ == "__main__":
    main()
