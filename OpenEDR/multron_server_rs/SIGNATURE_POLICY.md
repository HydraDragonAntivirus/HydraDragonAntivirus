# VirusKov signature policy

Notes for anyone (human or AI) writing or generating signatures for the VirusKov /
Multron server (HydraDragonSig, YARA, ClamAV, TLSH, imphash).

## Specific, never generic

- A signature describes one family or one sample set, as exactly as possible.
- Generic signatures are not written. That means no heuristics, no "suspicious API
  combination" rules, no packer / installer / runtime strings, and no single
  common string.
- A specific signature does not need to be timid. Do not drop good, distinctive
  evidence just out of fear of false positives: the safeguards below exist for
  that, and they handle it.

## Why false positives are not feared here

- **String whitelist:** it holds every string of every file with a human clean
  verdict, grouped by file type (`src/string_wl.rs`). A string in that list is never
  used as evidence for that file type. VirusKovAlyzer "Only unknown strings" shows
  what is left.
- **Retrohunt:** saving a signature in the signature room matches it against every
  kept file, so a false positive shows up at once.
- **Human verdicts win:** a human clean verdict always beats any signature.
- **TLSH blacklist:** the distance is set in the dashboard (default 10, stricter is
  safer).
- **Imphash signatures:** refused for .NET, for import tables under 10 entries and
  for any imphash a clean file has.

## Still required

- Names follow `Category.Platform.Family[.Variant]` (`src/naming.rs`).
- Signatures are saved by an analyst in the signature room. Nothing is saved or
  applied automatically.
- If retrohunt finds a clean file, fix the signature; do not make it generic.
