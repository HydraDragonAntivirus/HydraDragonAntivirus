#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate complete malicious vendor YAML rules with malware types"""

def main():
    # Read malvendor.db
    with open('hydradragon/Owlyshield/signature/malvendor.db', 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f.readlines() if '|' in line]
    
    # Generate individual rules for each vendor
    rules = []
    current_id = 1
    
    for line in lines:
        parts = line.split('|')
        vendor = parts[0]
        malware_type = parts[1] if len(parts) > 1 else 'Malware.Generic'
        
        # Escape quotes in vendor name
        vendor_escaped = vendor.replace('"', '\\"')
        
        # Create tag from malware type
        malware_tag = malware_type.lower().replace('.', '-')
        
        rule = f'''  - id: malicious-vendor-{current_id:04d}
    name: "Malicious Vendor: {vendor_escaped}"
    description: "Detects files signed by {vendor_escaped} (Known for: {malware_type})"
    severity: high
    condition: |
      signature.signer_name contains "{vendor_escaped}"
    tags:
      - signature
      - malware
      - certificate-abuse
      - {malware_tag}
    metadata:
      vendor: "{vendor_escaped}"
      malware_type: "{malware_type}"

'''
        rules.append(rule)
        current_id += 1
    
    # Create YAML content
    yaml_content = f'''# Malicious Vendor Detection Rules
# Auto-generated from malvendor.db - Complete database with all {len(rules)} vendors
# Each rule includes the vendor name and associated malware type
# These rules detect files signed by known malicious certificate authorities

rules:
'''
    yaml_content += ''.join(rules)
    
    # Write output
    with open('Owlyshield/hydradragonstatic/examples/malicious_vendors_complete.yaml', 'w', encoding='utf-8') as f:
        f.write(yaml_content)
    
    print(f'Created complete YAML with {len(rules)} vendor rules including malware types')

if __name__ == '__main__':
    main()
