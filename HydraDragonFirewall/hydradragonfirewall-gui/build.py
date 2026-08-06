#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
HydraDragon Firewall Build Script

Expected layout:
  HydraDragonAntivirus/
    hydradragon/
      HydraDragonFirewall/                 deploy folder; WinDivert already exists here
    HydraDragonFirewall/
      hydradragonfirewall/                 this build.py lives here

Rules:
  - No `everything` folder.
  - No hardcoded absolute deploy path.
  - No WinDivert copy.
  - No WinDivert source-folder validation in HydraDragonFirewall project root.
  - WINDIVERT_PATH points to the deploy folder because WinDivert is already there.
  - Only hydradragonfirewall.exe and hydradragonfirewall.dll are copied to deploy.
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

CYAN = "\033[96m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RED = "\033[91m"
MAGENTA = "\033[95m"
GRAY = "\033[90m"
RESET = "\033[0m"


def cyan(s): return f"{CYAN}{s}{RESET}"
def yellow(s): return f"{YELLOW}{s}{RESET}"
def green(s): return f"{GREEN}{s}{RESET}"
def red(s): return f"{RED}{s}{RESET}"
def magenta(s): return f"{MAGENTA}{s}{RESET}"
def gray(s): return f"{GRAY}{s}{RESET}"


def header(msg):
    print(cyan("=" * 48))
    print(cyan(f"  {msg}"))
    print(cyan("=" * 48))


def step(n, msg):
    print(yellow(f"\n[{n}] {msg}"))


def ok(msg):
    print(green(f"      {msg}"))


def warn(msg):
    print(yellow(f"  WARNING: {msg}"))


def fail(msg):
    print(red(f"  ERROR: {msg}"))
    sys.exit(1)


def run(cmd: list, cwd: Path = None, env: dict = None):
    merged_env = {**os.environ, **(env or {})}
    result = subprocess.run(cmd, cwd=cwd, env=merged_env)
    if result.returncode != 0:
        fail(f"Command failed (exit {result.returncode}): {' '.join(str(c) for c in cmd)}")


def prompt_install(name: str, install_cmd: list) -> None:
    answer = input(f"\n  {yellow(f'`{name}` is not installed. Install it now? [Y/n]: ')}")
    answer = answer.strip().lower()
    if answer not in ("", "y", "yes"):
        fail(f"`{name}` is required. Install it manually and re-run.")

    print(yellow(f"      Running: {' '.join(install_cmd)}"))
    result = subprocess.run(install_cmd)
    if result.returncode != 0:
        fail(f"Installation of `{name}` failed.")

    cargo_bin = Path.home() / ".cargo" / "bin"
    if str(cargo_bin) not in os.environ.get("PATH", ""):
        os.environ["PATH"] = str(cargo_bin) + os.pathsep + os.environ.get("PATH", "")

    if not shutil.which(name):
        fail(f"`{name}` still not found after install - restart your terminal and re-run.")

    ok(f"`{name}` installed: {shutil.which(name)}")


def check_tool(name: str, install_cmd: list) -> str:
    path = shutil.which(name)
    if path:
        print(gray(f"      {name} found: {path}"))
        return path

    prompt_install(name, install_cmd)
    return shutil.which(name) or name


def check_rustup_target(target: str):
    result = subprocess.run(
        ["rustup", "target", "list", "--installed"],
        capture_output=True,
        text=True,
    )
    if target in result.stdout:
        print(gray(f"      rustup target {target} already installed"))
        return

    print(yellow(f"      Installing rustup target {target}..."))
    run(["rustup", "target", "add", target])


def check_dependencies():
    step("0/4", "Checking dependencies...")

    check_tool("cargo", ["winget", "install", "Rustlang.Rustup"])
    check_tool("rustup", ["winget", "install", "Rustlang.Rustup"])
    check_tool("trunk", ["cargo", "install", "trunk"])

    tauri_cli = shutil.which("cargo-tauri")
    if tauri_cli:
        print(gray(f"      cargo-tauri found: {tauri_cli}"))
    else:
        answer = input(
            f"\n  {yellow('`cargo-tauri` is not installed. Install it now? [Y/n]: ')}"
        ).strip().lower()
        if answer in ("", "y", "yes"):
            run(["cargo", "install", "tauri-cli"])
            ok("cargo-tauri installed.")
        else:
            warn("`cargo-tauri` skipped - `cargo tauri dev/build` will not work without it.")

    check_rustup_target("wasm32-unknown-unknown")
    ok("All required dependencies present.")


def robust_copy(src: Path, dst: Path):
    if src.exists():
        try:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            print(gray(f"      Copied {src.name} -> {dst}"))
        except Exception as e:
            warn(f"Failed to copy {src} -> {dst}: {e}")
            warn("Hint: Make sure the application is not running.")
    else:
        warn(f"Source not found: {src}")


def resolve_layout(script_dir: Path) -> tuple[Path, Path, Path]:
    """
    build.py lives in:
      HydraDragonAntivirus/HydraDragonFirewall/hydradragonfirewall/build.py

    Derived:
      project_dir: HydraDragonAntivirus/HydraDragonFirewall
      repo_root:   HydraDragonAntivirus
      deploy_dir:  HydraDragonAntivirus/hydradragon/HydraDragonFirewall

    WinDivert is assumed to already exist in deploy_dir.
    """
    project_dir = script_dir.parent
    repo_root = project_dir.parent
    deploy_dir = repo_root / "hydradragon" / project_dir.name
    return project_dir, repo_root, deploy_dir


def build_ui(script_dir: Path, release: bool):
    step("1/4", f"Building UI with Trunk ({'release' if release else 'debug'})...")

    ui_dir = script_dir / "ui"
    dist_dir = script_dir / "dist"

    if not ui_dir.exists():
        fail(f"UI directory not found: {ui_dir}")

    cmd = ["trunk", "build", "--dist", str(dist_dir)]
    if release:
        cmd.append("--release")

    run(cmd, cwd=ui_dir)
    ok("UI build complete!")


def build_rust(script_dir: Path, release: bool, deploy_dir: Path):
    flag = "release" if release else "debug"
    step("2/4", f"Building Rust backend ({flag})...")

    target_dir = script_dir / "target" / ("release" if release else "debug")
    cmd = ["cargo", "build"]
    if release:
        cmd.append("--release")

    # WinDivert is already in deploy_dir. Use deploy_dir for the build env too.
    # Do not validate/copy WinDivert in this script.
    run(
        cmd,
        cwd=script_dir,
        env={
            "WINDIVERT_PATH": str(deploy_dir),
            "WINDIVERT_DLL_OUTPUT": str(target_dir),
        },
    )

    ok("Rust build complete!")


def deploy_firewall_only(script_dir: Path, release: bool, deploy_dir: Path):
    step("3/4", "Deploying firewall binaries only...")

    target_dir = script_dir / "target" / ("release" if release else "debug")

    # Do NOT copy WinDivert here.
    robust_copy(target_dir / "hydradragonfirewall.exe", deploy_dir / "hydradragonfirewall.exe")
    robust_copy(target_dir / "hydradragonfirewall.dll", deploy_dir / "hydradragonfirewall.dll")


def main():
    parser = argparse.ArgumentParser(description="HydraDragon Firewall Build Script")
    parser.add_argument("--release", action="store_true", help="Build in release mode")
    parser.add_argument("--run", action="store_true", help="Launch the deployed app after building")
    args = parser.parse_args()

    header("HydraDragon Firewall Build System")

    script_dir = Path(__file__).resolve().parent
    project_dir, repo_root, deploy_dir = resolve_layout(script_dir)

    check_dependencies()
    build_ui(script_dir, args.release)
    build_rust(script_dir, args.release, deploy_dir)
    deploy_firewall_only(script_dir, args.release, deploy_dir)

    target_dir = script_dir / "target" / ("release" if args.release else "debug")
    built_exe = target_dir / "hydradragonfirewall.exe"
    deployed_exe = deploy_dir / "hydradragonfirewall.exe"

    step("4/4", "Build Successful!")
    print(cyan(f"\n  Source dir:       {script_dir}"))
    print(cyan(f"  Project dir:      {project_dir}"))
    print(cyan(f"  Repo root:        {repo_root}"))
    print(cyan(f"  WinDivert path:   {deploy_dir}"))
    print(cyan(f"  Built executable: {built_exe}"))
    print(cyan(f"  Deploy folder:    {deploy_dir}"))
    print(cyan(f"  Deployed exe:     {deployed_exe}"))
    print(cyan("=" * 48))
    print(yellow("  IMPORTANT: Run the executable as Administrator"))
    print(yellow("  for WinDivert network capture to work!"))
    print(cyan("=" * 48))

    if args.run:
        print(magenta("\n  Launching deployed application (UAC prompt expected)..."))
        os.startfile(str(deployed_exe))


if __name__ == "__main__":
    main()
