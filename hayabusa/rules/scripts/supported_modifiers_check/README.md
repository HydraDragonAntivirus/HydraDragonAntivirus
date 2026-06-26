# About

This script will create a markdown table of the field modifiers being used by Sigma and tell if Hayabusa supports the modifiers or not.

# How to use
## Run locally
1. `git clone https://github.com/SigmaHQ/sigma`
2. `git clone https://github.com/Yamato-Security/hayabusa-rules.git`
3. `cd hayabusa-rules/scripts/supported_modifiers_check`
4. `poetry install --no-root`
5. `poetry run python supported-modifier.py ../../../sigma ../../../hayabusa-rules ../../doc/SupportedSigmaFieldModifiers.md`

## Run Actions
- Manual: https://github.com/fukusuket/hayabusa/actions/runs/10643011211/job/29506086051
- Schedule: `cron: '0 20 * * *'`

# Authors

* Fukusuke Takahashi
* Zach Mathis