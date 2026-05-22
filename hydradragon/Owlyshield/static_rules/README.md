# HydraDragonStatic Rules

This folder is loaded by Owlyshield through the `hydradragonstatic` library.
Firewall can edit YAML files here from the Static Signatures tab.

Keep bundled engine signatures in `engine_static_rules.yaml` and user signatures in
`user_static_rules.yaml`.

Detection mode is controlled by `STATIC_RULES_MODE`: `malware` (default) only
reports malware verdicts, while `suspicious` also reports suspicious verdicts.
