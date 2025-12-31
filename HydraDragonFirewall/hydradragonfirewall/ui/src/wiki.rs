use leptos::*;

#[component]
pub fn RulesWiki() -> impl IntoView {
    view! { 
        <div class="glass-card" style="display: flex; flex-direction: column; overflow: hidden; padding: 0; flex: 1">
            <div class="section-header" style="background: rgba(0,0,0,0.4); padding: 20px 25px; border-bottom: 1px solid rgba(255,255,255,0.08); display: flex; align-items: center; justify-content: space-between">
                <div>
                    <h3 style="margin: 0; font-size: 16px; color: var(--text-bright); display: flex; align-items: center; gap: 8px">
                        <span style="color: var(--accent-blue)">"📚"</span>
                        "Complete Rules Reference"
                    </h3>
                    <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px; opacity: 0.8">
                        "HydraDragon SDK v0.1.0 • Full Feature Documentation"
                    </div>
                </div>
            </div>
            
            <div style="flex: 1; overflow-y: auto; padding: 25px 30px; font-size: 13px; line-height: 1.7; color: #cfd8e3; background: #0c0e12">
               
                <div class="wiki-section">
                    <h4 class="wiki-title">"1. Structure & Metadata"</h4>
                    <p class="wiki-desc">"Every rule must have a unique name, description, and status. The engine uses strict YAML syntax."</p>
                    <pre class="code-block language-yaml">
"- name: 'My Unique Rule Name'
  description: 'Detailed explanation of what this rule catches'
  enabled: true   # Set to false to disable without deleting
  condition_logic: and # 'and' (default) or 'or'"
                    </pre>
                </div>

                <div class="wiki-section">
                    <h4 class="wiki-title">"2. Protocol Matching"</h4>
                    <p class="wiki-desc">"Match specific network protocols. Use 'any' to match everything."</p>
                    <pre class="code-block language-yaml">
"protocol: http    # Options: http, https, tcp, udp, icmp, arp, any"
                    </pre>
                </div>

                <div class="wiki-section">
                    <h4 class="wiki-title">"3. Actions"</h4>
                    <p class="wiki-desc">"What happens when a rule matches. You can only define one action per rule."</p>
                    <pre class="code-block language-yaml">
"action: block          # Drop the packet silently
action: allow          # Whitelist the traffic (bypass further checks)
action: ask            # Prompt the user with a popup decision
action: traffic_attack # Log as a HIGH SEVERITY attack
action: change_packet  # Modify payload content (advanced)
action: solve_packet   # Auto-fix malformed packets
action: inject_dll     # Inject monitoring DLL into the source process"
                    </pre>
                </div>

                <div class="wiki-section">
                    <h4 class="wiki-title">"4. IP Address Conditions"</h4>
                    <p class="wiki-desc">"Match Source (src_ip) or Destination (dst_ip) addresses using CIDR or exact IPs."</p>
                    <pre class="code-block language-yaml">
"conditions:
  - src_ip:
      addresses: ['192.168.1.55', '10.0.0.1']
      cidr_ranges: ['172.16.0.0/12', '10.0.0.0/8']
  - dst_ip:
      addresses: ['8.8.8.8']"
                    </pre>
                </div>

                <div class="wiki-section">
                    <h4 class="wiki-title">"5. Port Matching"</h4>
                    <p class="wiki-desc">"Filter by specific ports or port ranges."</p>
                    <pre class="code-block language-yaml">
"conditions:
  - dst_port:
      ports: [80, 443, 8080, 8443]
      ranges: [(1000, 2000), (30000, 65535)]"
                    </pre>
                </div>

                <div class="wiki-section">
                    <h4 class="wiki-title">"6. Domain & URL (Web Filter)"</h4>
                    <p class="wiki-desc">"Powerful wildcard matching for web traffic. Case-insensitive by default."</p>
                    <pre class="code-block language-yaml">
"conditions:
  - domain:
      domains: ['*.google.com', 'tracking.*', 'ads.example.com']
  - url:
      patterns: ['*/login.php', '*?query=malicious*']"
                    </pre>
                </div>

                 <div class="wiki-section">
                    <h4 class="wiki-title">"7. Content Inspection & Encoding"</h4>
                    <p class="wiki-desc">"Inspect packet payloads deeply. Supports multiple encoding layers to find hidden threats."</p>
                    <pre class="code-block language-yaml">
"# First, set the encoding mode for the rule:
encoding: base64     # Options: plain (default), base64, base58, hex, reverse

conditions:
  # This string will be searched for AFTER decoding
  - content_match: 'powershell.exe -nop -w hidden'"
                    </pre>
                </div>

                <div class="wiki-section">
                    <h4 class="wiki-title">"8. Regex Matching"</h4>
                    <p class="wiki-desc">"Use Rust-compatible Regex for complex pattern detection."</p>
                    <pre class="code-block language-yaml">
"conditions:
  - regex:
      pattern: '^POST.*admin.*'
      case_insensitive: true"
                    </pre>
                </div>

                <div class="wiki-section">
                    <h4 class="wiki-title">"9. File Type Detection"</h4>
                    <p class="wiki-desc">"Detect file headers (magic bytes) inside the stream."</p>
                    <pre class="code-block language-yaml">
"conditions:
  - file_type:
      file_types: ['exe', 'pdf', 'zip', 'png']"
                    </pre>
                </div>

                <div class="wiki-section">
                    <h4 class="wiki-title">"10. Localhost & Process Context"</h4>
                    <p class="wiki-desc">"Target specific network segments or loopback traffic types."</p>
                    <pre class="code-block language-yaml">
"localhost_type: private_c  # Matches 192.168.x.x
# Options: 
#   loopback (127.x), private_a (10.x), private_b (172.16-31)
#   private_c (192.168), any (matches all above)"
                    </pre>
                </div>

                <div class="wiki-section">
                    <h4 class="wiki-title">"11. Advanced Traffic Routines"</h4>
                    <p class="wiki-desc">"Match specific flow directions (Source -> Destination)."</p>
                    <pre class="code-block language-yaml">
"routine:
  from_ip: '192.168.1.100'
  to_ip: 'any'
  to_port: 80"
                    </pre>
                </div>

                 <hr style="border: 0; border-top: 1px solid rgba(255,255,255,0.08); margin: 30px 0" />

                 <div class="wiki-section">
                    <h4 class="wiki-title" style="color: var(--accent-red)">"🔥 Complex Example: C2 Detection"</h4>
                     <pre class="code-block language-yaml">
"- name: 'APT28 C2 Beacon Detection'
  description: 'Detects Base64 encoded beacons to suspicious TLDs'
  enabled: true
  protocol: https
  action: traffic_attack
  condition_logic: and
  encoding: base64
  conditions:
    - domain:
        domains: ['*.xyz', '*.top']
    - content_match: 'cmd=whoami'
    - dst_port:
        ports: [443, 8443]"
                    </pre>
                </div>

            </div>
            
            <style>
            ".wiki-section { margin-bottom: 35px; }"
            ".wiki-title { color: var(--accent-blue); font-size: 14px; margin: 0 0 8px 0; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase; }"
            ".wiki-desc { margin: 0 0 12px 0; color: #8b9bb4; font-size: 13px; }"
            ".code-block {
                background: #0f1115;
                padding: 15px;
                border-radius: 8px;
                border: 1px solid #2a2e35;
                font-family: 'JetBrains Mono', 'Fira Code', monospace;
                font-size: 12px;
                color: #a5d6ff;
                overflow-x: auto;
                white-space: pre-wrap;
                line-height: 1.5;
                box-shadow: inset 0 2px 8px rgba(0,0,0,0.2);
            }"
            </style>
        </div>
    }
}
