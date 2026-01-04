# Sanctum EDR

![Rust Kernel Driver EDR Sanctum](imgs/evidence/sanctum-cover.webp)

The Sanctum EDR is an &#128679; **experimental and in development** &#128679; proof of concept for an EDR (Endpoint Detection and Response) tool, fully written in Rust! No
C required in this project baby!

**BREAKING CHANGE NOTIFICATION**: If you are recently updating this project, you now need to put
`sanctum.dll` in `C:\Windows\System32` (documented in below instructions).

I'm documenting this project on my [blog](https://fluxsec.red/)!

Currently, there are some features disabled (via comments, feel free to uncomment them to turn them back on) - this was due to some occasional random stability issues.
I'm currently working on another project, but I will soon be turning my attention back to the EDR.

Up until recently, the readme was in need of some tlc; given how fast the project has grown the readme was out of date and as time went on some fairly specific
configuration requirements have arose. See the Deployment Instructions section for clear details on how to install the project **to a VM**. Do not deploy this 
on your host machine, as we are tampering with the kernel (Windows 11), you may encounter system instability.

I am not accepting PR's as a rule; unless your contribution is something small / utility based. This project is primarily for my own learning - and hopefully for 
me to teach the concepts to people interested in low level Windows system security / malware devs / defensive engineering / analysts.

That said; as there is more attention on the project, please feel free to raise issues or use the discussions page as you wish. If you want some integrations, let me know
and I will look at building those in!

I'd also recommend opening the driver crate at its crate level from the Developer Command Prompt (e.g. for VSCode: `code driver`) as I have noticed some issues with
`Rust-Analyzer` if not opened in this way.

&#128679; Please note: This project is not currently designed for mass consumption; you may encounter teething issues in the deploy process - you can raise an issue
for me to fix; but I provide no guarantee it will work without issue on your deployment. This is a **POC project** first and foremost. There may be some bugs, or incomplete 
features on the main branch as I develop it. For bugs, please raise an issue. Incomplete features will be in progress, so please do not raise issues for those.

Stuck trying to build / deploy this? I made a [YouTube video](https://www.youtube.com/watch?v=BFbz6ZjGitA) showing you how!

### Limitations regarding Alt Syscalls on the driver

Thanks to some testing by [Xacone](https://github.com/Xacone), we now know that **HVCI** prevents writing to the `PspServiceDescriptorGroupTable ` structure; so this technique is **blocked** by HVCI. From my own
testing, it appears that this is still resistant to both PatchGuard and HyperGuard under VBS. I used [ssde](https://github.com/valinet/ssde/) to load my driver whilst Secure Boot and VBS were enabled, of which it is
my understanding should be enough to test it against HyperGuard. This was done with debug mode off, which should also allow PatchGuard full authority to detect and block (BugCheck) the technique.

#### Contents

- [Structure](#structure)
- [Features](#features)
- [Requirements](#requirements)
- [Deployment Instructions](#deployment-instructions)

## Structure

| Crate | Description | 
| --- | --- |
| driver | Contains the code for the Sanctum driver which is required for kernel monitoring |
| um_engine | The usermode engine of the Sanctum application which communicates with the driver, running processes, and the GUI |
| injected_dll | A DLL injected into all processes for EDR hooking (note that this is currently phased out, having being replaced with kernel-side hooking after I researched [Alt Syscalls for Windows 11](https://fluxsec.red/alt-syscalls-for-windows-11)). I will leave this in the project for legacy / blog post reasons, I have spent a lot of time hooking functions and writing about it on my blog, so good to keep in |
| gui | A GUI for the Sanctum EDR, using Tauri for rendering | 
| shared_* | Shared crates for the project, both in `std` and `no_std` environments | 
| server | Todo, this is to be the telemetry server which will receive signals from endpoints |

**Deprecated modules**

The following modules (crates) were used in the project, and documented on my
blog, but are now no longer required. If my setup guide refers to these, then
you can swiftly disregard those parts.

| Crate | Description | 
| --- | --- |
| etw_installer | The installer program for creating the ELAM PPL service (installs `sanctum_ppl_runner`) |
| sanctum_ppl_runner | A ELAM signed Protected Process Light which monitors Events Tracing for Windows Threat Intelligence provider |
| etw_consumer | Deprecated; sanctum_ppl_runner implements all required features this was intended to solve. Leaving in for learning reasons / linked to my blog post |

## Features

You can check my [YouTube channel](https://www.youtube.com/@FluxSec) for some POC videos :)

As a **summary** of features:

- [Alt Syscalls](https://fluxsec.red/alt-syscalls-for-windows-11) for kernel-side interception of syscalls
- Events Tracing for Windows: Threat Intelligence telemetry subscription
- Uses [Ghost Hunting](https://fluxsec.red/edr-syscall-hooking) to detect signs of malicious activity
- Detects tampering of NTDLL (thwarts common malware TTPs)
- Detects rootkit tampering in the kernel
- DLL injection of EDR (currently deprecated in favour of Alt Syscalls)

## Requirements:

1) Cargo (obviously..).
2) Nightly.
3) Windows Driver Kit & Developer Console (as admin for building the driver).
4) Cargo make and LLVM tools, see [Microsoft's build instructions](https://github.com/microsoft/windows-drivers-rs?tab=readme-ov-file#build-requirements) for installing these. 
5) Tauri build tools, [see the documentation](https://v2.tauri.app/reference/cli/) for official instructions.

## Deployment instructions

The installation instructions are split between your **host** and **guest**. If you are having problems deploying this, please use the discussions page or raise and issue and I will 
do my best to help / fix any bugs from the process.

They are split into instructions for a host machine and a guest VM, this is because I advise against developing & building on your deployment VM (if the driver bricks your VM and it cant
boot, then you will lose any development / environment specific setup [assuming no snapshots] that went into you being able to build this project).

If you wish to build and deploy on the same machine (VM only to save your host), then I recommend 2 VM's; one to build, one to deploy, in which case, treat the host section below as your 2nd
VM.

As an overview, the driver must be built via `cargo make`, which is a pipeline provided by Microsoft in the Windows Drivers project. The remaining crates for this 
project are built via `cargo build`.

### Guest

1) Install a clean Windows 11 VM; do so first with a Gen2 processor, Secure Boot and TPM so you can properly install windows. I would recommend installing W11 Pro when prompted. You can use either a type 1 or type 2 hypervisor.
2) Update Windows etc.
3) Disable Secure Boot and TPM.
4) Boot the VM
5) Copy over the `installer_clean_vm.ps1` script from this repo root.
6) Open PowerShell as admin, and cd into where you dropped the script.
7) Enable running of scripts on your VM via powershell `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`
8) Run `./installer_clean_vm.ps1` - this will initialise the folder structure required, pull down the static files, and enable debug mode and configure your VM for kernel debugging in WinDbg.

Now do the host instructions; we will return to the guest shortly.

### Host

This is a little involved due to the signing process. But follow along and you should be good.

#### Building and signing the driver

1) Ensure you have Visual Studio build tools installed
2) Ensure you have this repo cloned
3) Open Developer Command Prompt as Administrator (I'd recommend running `powershell` from this cmd prompt to upgrade to powershell)
4) CD into the driver crate of this repo
5) Run `.\cert.ps1` which will generate a ELAM compatible code signing certificate called `sanctum.pfx`. The cert will be located in the `driver` crate root.
6) Run `cargo make` - this will build the driver.
7) Run `.\sign.bat` - this will sign the driver.
8) Run `certmgr.exe -v target\debug\sanctum_package\sanctum.sys` which will output the certificate information of the driver:
   1) Look for the line (just on top of the half way point of the output) which has the heading: `Content Hash (To-Be-Signed Hash)::`.
   2) Note the hash that is output beneath (will be 2 lines of bytes).
   3) You want to concatenate these bytes into 1 long string. To see an example explanation, check my comment [here](https://github.com/0xflux/Sanctum/discussions/66#discussioncomment-13297486).
   4) Open `driver/build.rs` in your favourite code editor, and change the hash from what is there in your cloned copy to the hash you concatenated in the step above, again, see the above link if that doesn't make sense.
9) Run `cargo clean`.
10) Run `cargo make`.
11) Run `.\sign.bat`.

#### Building and signing your PPL service

Must be build in release mode to match the signing script - if you wanna build in debug mode make sure to edit `sign_ppl_runner.bat`.

1) Continuing on from above, go up one dir with `cd ../`.
2) Run: `cargo build --release -p sanctum_ppl_runner` - this will build the PPL service binary in `/target/release/`.
3) Sign the service binary via running `.\sign_ppl_runner.bat`.

#### Building the rest

(Feel free to build these in debug mode if you wish)

1) `cargo build --release -p elam_installer`
2) `cargo build --release -p injected_dll`
3) `cargo build --release -p um_engine`
4) `cargo tauri build --debug`

### Guest

Now to finish off, we want to move the binaries into the guest VM and run things!

1) Move `um_engine.exe`, `elam_installer`, `app` (gui) into ~Desktop\sanctum
2) Move `sanctum.sys` & `sanctum_ppl_runner.exe` into %AppData%\Sanctum
3) Move `sanctum.dll` into `C:\Windows\System32`
4) In an admin powershell terminal:
   1) cd ~Desktop\sanctum
   2) `.\elam_installer.exe` - this should work and now prompt you to reboot.
5) Reboot
6) In an admin powershell terminal:
   1) cd ~Desktop\sanctum
   2) `.\elam_installer.exe` - this time no prompt to reboot
   3) `sc.exe start sanctum_ppl_runner` - This should run your PPL service. If you have issues, check Event Viewer, or go to Services -> sanctum_ppl_runner and start it from there (may give more verbose error messages)
7) Run um_engine as admin
8) Run the GUI `app.exe` as admin
9) Now you should be good to start the driver from the GUI if all went well!

**Important Note**: `elam_installer.exe` and starting the PPL needs to be run every reboot.

### Deployment problems

If you have problems with the deployment process, please feel free to submit an issue or discussion and I will try help!