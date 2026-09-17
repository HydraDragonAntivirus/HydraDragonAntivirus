OPTIONAL vendor drop-ins for the openedr_web demo (NOT in git).
The demo degrades gracefully when a file is absent (status lights go red).

1) vendor/capstone.js  — capstone.js Emscripten build exposing global MCapstone
   - npm:  npm pack @alexaltea/capstone-js  -> copy dist/capstone.js here
   - repo: https://github.com/AlexAltea/capstone.js (python3 build.py x86)
   - used for: x86/x64 disassembly counts (add/mov/total) feeding PE features
     indices 51..53 via web_scan_bytes_ex.

2) vendor/unicorn_x86.js — unicorn.js x86 build exposing global MUnicorn
   - npm:  npm pack @alexaltea/unicorn-js  -> copy dist/unicorn_x86.js here
   - repo: https://github.com/AlexAltea/unicorn.js (python3 build.py x86)
   - CDN:  https://cdn.jsdelivr.net/npm/@alexaltea/unicorn-js/dist/unicorn_x86.js
   - used for: entry-point emulation + memory-diff unpack assist; dumped
     regions are re-scanned and merged (Unpacked: detections).

Runtime data (also NOT in git, copy from OpenMalwareScannerPortable/):
  www/models/pe_trees.bin, js_trees.bin, url_trees.bin
  www/yara_rules/valhalla-rules.yrc
  www/registry_rules/pua_registry_rules.yaml
  www/hash_rules/benign_sha256.txt
Serve this folder over http (file:// blocks fetch + wasm streaming):
  python3 -m http.server 8080   # inside www/
