- Please compile using the official VirusTotal YARA (maybe YARA-X) releases instead of yara-python to see all warnings and errors: https://github.com/VirusTotal/yara/releases
- Example: yarac64.exe compiled_rule.yar compiled_rule.yrc
- Example 2: yarac64.exe machinelearning.yar machinelearning.yrc
- Example 3: yarac64 valhalla-rules.yar valhalla-rules.yrc
- Example 4: yarac64 icewater.yar icewater.yrc
- py -3.12 compileryarax.py

- Our strongest tool for removing duplicates is YARA_Util.py: https://github.com/RandomRhythm/YARA_Rules_Util

## false_positive_remover.py examples

- Scan one YARA file against a benign sample folder:
  `py -3.12 false_positive_remover.py -y clean_rules.yar -f D:\benign_samples`

- Scan a YARA directory recursively:
  `py -3.12 false_positive_remover.py -y . -f D:\benign_samples -s`

- Skip `.yar`, `.yara`, and `.yrc` files inside the benign folder while checking false positives:
  `py -3.12 false_positive_remover.py -y . -f D:\benign_samples -s --skip-yara-files`

- Limit worker count for slower machines or smaller test runs:
  `py -3.12 false_positive_remover.py -y valhalla-rules.yar -f D:\benign_samples --workers 4`

- Scan only one rule pack and skip YARA artifacts in a mixed folder:
  `py -3.12 false_positive_remover.py -y WindowsDefender.yar -f C:\ --skip-yara-files`

py -3.12 false_positive_remover.py -y <YARA_PATH> --from-log

py -3.12 false_positive_remover.py -y <YARA_DIR> -s --from-log

- Output:
  The script logs matched false-positive rules in `removal.log` and removes those rules from the target YARA file or directory.

# For a single file
python yara_utils_pro_cli.py -f rules/generated_rules.yar --fix-limits
# For a whole directory (recursive)
python yara_utils_pro_cli.py -d ./rules -r --fix-limits
# For YARA-X
Don't forget to create HydraDragonAntivirus\\hydradragon\\yara-x and move to yara-x files here

# For Clean Excluded Rules And Duplicate Import Remover
py -3.12 YARA_Util_Exclude_Remover.py -d rules -x excluded_yara_x_rules.txt -o clean_rules
py -3.12 YARA_Util_duplicate_import.py -d rules -o clean_rules

# Warning fixer
yr fix warnings valhalla-rules.yar