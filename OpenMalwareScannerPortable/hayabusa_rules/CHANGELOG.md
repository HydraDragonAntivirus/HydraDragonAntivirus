# Changes

## v3.5.0 [2025/09/16]

- Updated all Hayabusa rules' date format to the latest Sigma specification. (#915) (@yamatosecurity)

## v2.17.0 [2024/10/19]

- Updated the Hayabusa `count` rules to correlation rules. (@yamatosecurity)

## v2.17.0 [2024/10/03]

- Bug fix: Two rules were causing errors because we deleted `rules/config/regex/LOLBAS_paths.txt`. The rules now do not reference any external file. (#730) (@yamatosecurity)

## v2.17.0 [2024/10/01]

- Deprecate the use of regular expression wordlists (`regexes` and `allowlist` fields) inside rules. Instead, the regular expressions will be in normal lists inside the rule. (#725) (@yamatosecurity)

## v2.15.0 [2024/06/04]

- The windash modifier (ex: `|windash|contains`) is now left as is and we do not convert these to more compatible rules now that Hayabusa supports windash natively as of version 2.15.0. (#646) (@fukusuket)

## v2.13.0 [2024/03/27]

- Updated the `proven_rules.txt` file. (@YamatoSecurity)

## v2.13.0 [2024/03/24]

- Newly created rules are assigned with new UUIDv4 IDs. (#629) (@fukusuket)
- Fixed a bug where `logsource_mapping.py` was creating rules with `near` conditions. (#632) (@fukusuket)
- Refactored `logsource_mapping.py` and adding unit tests. (#627) (@fukusuket)
- Updated `exclude_rules.txt`. (@fukusuket)

## v2.13.0 [2024/03/22]

- Bug fix: the `null` keyword was converted to an empty string. This may have been a regression when comments were left as is. Now `null` keywords are being convert correctly. (#620) (@fukusuket)
- `|contains|windash` modifier is now being converted to a usable form. (#622) (@fukusuket)

## v2.13.0-dev [2024/01/19]

- Comments in Sigma rules are left as is. Before, they would be stripped after conversion. (#568) (@fukusuket)
- Package management for the sigma conversion backend is now handled by [Poetry](https://python-poetry.org/) and static code analysis is performed by [Ruff](https://github.com/astral-sh/ruff). (#567) (@fukusuket)

## v2.12.0 [2023/12/19]

- Added field mapping support for registry rules (`service:`: `registry_add`, `registry_set`, `registry_event`) to detect built-in Windows event logs (`Security EID 4657`). Before, only Sysmon (`EID 12, 13, 14`) logs would be able to be detected. (#476) (@fukusuket)
- Added checks for ignoring rules that use field modifiers that Hayabusa does yet not support. (Ex: `|expand`) (#553, #554) (@fukusuket)

## v2.6.0 [2023/07/06]

- Added support for `category: antivirus`. (#456) (@fukusuket)

## v2.6.0 [2023/07/02]

There is now a field mapping check for `process_creation` rules.
There were about 60 `process_creation` rules that were being generated for `Security 4688` events, however, they were looking for fields that only exist in `Sysmon 1` so there was no need for them.
These incompatible `Security 4688` rules are no longer being created which will speed up processing time.
Also, `IntegrityLevel`, `User` and other fields are now being mapped to the correct field name and data type providing more accurate results.
This was all done thanks to Fukusuke Takahashi.

Details: https://github.com/Yamato-Security/hayabusa-rules/pull/445

## v2.5.1 [2023/05/14]

Rule converter was completely rewritten to only convert the `logsource` to `Channel` and `EventID` and leave everything else as the original sigma rule. (#396) (@fukusuket)
This makes reading the converted rules much easier as well as improves speed.

## v2.4.0 [2023/04/28]

Started to self host config files when converting rules from Sigma as the sigmac tool is deprecated and not updated anymore.

## v2.3.0 [2023/03/24]

`deprecated` and `unsupported` sigma rules are now also being added to the hayabusa-rules repository.

## v2.2.2 [2023/02/22]

Hayabusa now supports rules that use `base64offset|contains`.

## v1.8.1 [2022/12/14]

Fixed a bug when rules with fields with `null` values would not be converted properly.

## v1.8.1 [2022/12/06]

Stopped fixing regular expressions in `|re` fields during sigma rule conversion to work with the regex crate as we fixed the regular expressions upstream.

## v1.8.1 [2022/10/4]

Automatically update sigma rules daily.

## v1.4.2 [2022/07/20]

Include Channel in rule filename.

## v1.2.2 [2022/05/21]

Deprecated Japanese localization support: `title_jp`, `details_jp`, `description_jp`