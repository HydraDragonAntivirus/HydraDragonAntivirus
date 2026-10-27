# Threat Intelligence Master Pipeline

Domain / IP blocklists for the engine (`openedr_static` `domain_intel.rs`): one
BinaryFuse32 `.xf` per category in `OpenMalwareScannerPortable/xorfilter_rules/`.

1. Put the `hydradragon/website` lists in one folder, with the `.7z` ones unpacked
   (`MalwareDomains`, `MalwareSubDomains`, `IPv4Malware`, `DomainsPopularityWhiteList`,
   `SubDomainsPopularityWhiteList`; without the two popularity lists popular sites are
   not taken out of the blocklists).
2. Build `xorfilter_writer` (`cargo build --release` in `xorfilter_writer/`).
3. Run, then copy the `.xf` files of `<out>` to `OpenMalwareScannerPortable/xorfilter_rules/`:

```
python OpenEDR/scripts/build_all_threat_intel.py <lists folder> <out> xorfilter_writer/target/release/xorfilter_writer.exe
```

The lists are written as BinaryFuse32 (`--bf32`): the engine rejects BinaryFuse16 here,
whose one-in-65 536 false match would flag clean sites. CDN address space and the CIDR
whitelists are left out of the IP list and CIDR blacklists (`cdn_ranges/`).

# CDN ranges

```
python OpenEDR/scripts/strip_cdn_from_cidr_blacklist.py [--download] [--apply]
```

Removes CDN address space (Cloudflare, CloudFront, Fastly, Google services, Bunny) from
the `cidr_blacklist_ipv4/6.bin` tables; `--download` refreshes `cdn_ranges/` from the
providers, without `--apply` it only reports.
