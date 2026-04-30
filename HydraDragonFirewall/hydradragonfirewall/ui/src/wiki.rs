use leptos::*;

#[component]
pub fn RulesWiki() -> impl IntoView {
    view! {
        <div class="glass-card wiki-root">

            // ── Header ──────────────────────────────────────────────────
            <div class="wiki-header">
                <div class="wiki-header-left">
                    <div class="wiki-header-icon">"📚"</div>
                    <div>
                        <h3 class="wiki-header-title">"Rules Reference"</h3>
                        <div class="wiki-header-sub">"HydraDragon SDK v0.1.0 · Full Documentation"</div>
                    </div>
                </div>
                <div class="wiki-version-chip">"v0.1.0"</div>
            </div>

            // ── Body ─────────────────────────────────────────────────────
            <div class="wiki-body">

                // 1 — Structure & Metadata
                <div class="wiki-section">
                    <div class="wiki-section-num">"01"</div>
                    <div class="wiki-section-content">
                        <h4 class="wiki-title">"Structure & Metadata"</h4>
                        <p class="wiki-desc">"Every rule must have a unique name, description, and status. The engine uses strict YAML syntax."</p>
                        <pre class="code-block">
"- name: 'My Unique Rule Name'
  description: 'Detailed explanation of what this rule catches'
  enabled: true         # Set to false to disable without deleting
  condition_logic: and  # 'and' (default) or 'or'"
                        </pre>
                    </div>
                </div>

                // 2 — Protocol Matching
                <div class="wiki-section">
                    <div class="wiki-section-num">"02"</div>
                    <div class="wiki-section-content">
                        <h4 class="wiki-title">"Protocol Matching"</h4>
                        <p class="wiki-desc">"Match specific network protocols. Use " <code class="inline-code">"any"</code> " to match everything."</p>
                        <pre class="code-block">
"protocol: http    # Options: http, https, tcp, udp, icmp, arp, any"
                        </pre>
                    </div>
                </div>

                // 3 — Actions
                <div class="wiki-section">
                    <div class="wiki-section-num">"03"</div>
                    <div class="wiki-section-content">
                        <h4 class="wiki-title">"Actions"</h4>
                        <p class="wiki-desc">"What happens when a rule matches. Only one action per rule is allowed."</p>
                        <pre class="code-block">
"action: block          # Drop the packet silently
action: allow          # Whitelist the traffic (bypass further checks)
action: ask            # Prompt the user with a popup decision
action: traffic_attack # Log as a HIGH SEVERITY attack
action: change_packet  # Modify payload content (advanced)
action: solve_packet   # Auto-fix malformed packets"
                        </pre>
                    </div>
                </div>

                // 4 — IP Address Conditions
                <div class="wiki-section">
                    <div class="wiki-section-num">"04"</div>
                    <div class="wiki-section-content">
                        <h4 class="wiki-title">"IP Address Conditions"</h4>
                        <p class="wiki-desc">"Match source (" <code class="inline-code">"src_ip"</code> ") or destination (" <code class="inline-code">"dst_ip"</code> ") using CIDR notation or exact IPs."</p>
                        <pre class="code-block">
"conditions:
  - src_ip:
      addresses: ['192.168.1.55', '10.0.0.1']
      cidr_ranges: ['172.16.0.0/12', '10.0.0.0/8']
  - dst_ip:
      addresses: ['8.8.8.8']"
                        </pre>
                    </div>
                </div>

                // 5 — Port Matching
                <div class="wiki-section">
                    <div class="wiki-section-num">"05"</div>
                    <div class="wiki-section-content">
                        <h4 class="wiki-title">"Port Matching"</h4>
                        <p class="wiki-desc">"Filter by specific ports or port ranges."</p>
                        <pre class="code-block">
"conditions:
  - dst_port:
      ports: [80, 443, 8080, 8443]
      ranges: [(1000, 2000), (30000, 65535)]"
                        </pre>
                    </div>
                </div>

                // 6 — Domain & URL
                <div class="wiki-section">
                    <div class="wiki-section-num">"06"</div>
                    <div class="wiki-section-content">
                        <h4 class="wiki-title">"Domain & URL Filtering"</h4>
                        <p class="wiki-desc">"Powerful wildcard matching for web traffic. Case-insensitive by default."</p>
                        <pre class="code-block">
"conditions:
  - domain:
      domains: ['*.google.com', 'tracking.*', 'ads.example.com']
  - url:
      patterns: ['*/login.php', '*?query=malicious*']"
                        </pre>
                    </div>
                </div>

                // 7 — Content Inspection
                <div class="wiki-section">
                    <div class="wiki-section-num">"07"</div>
                    <div class="wiki-section-content">
                        <h4 class="wiki-title">"Content Inspection & Encoding"</h4>
                        <p class="wiki-desc">"Inspect packet payloads deeply. Supports multiple encoding layers to uncover hidden threats."</p>
                        <pre class="code-block">
"# First, set the encoding mode for the rule:
encoding: base64     # Options: plain (default), base64, base58, hex, reverse

conditions:
  # This string will be searched for AFTER decoding
  - content_match: 'powershell.exe -nop -w hidden'"
                        </pre>
                    </div>
                </div>

                // 8 — Regex
                <div class="wiki-section">
                    <div class="wiki-section-num">"08"</div>
                    <div class="wiki-section-content">
                        <h4 class="wiki-title">"Regex Matching"</h4>
                        <p class="wiki-desc">"Use Rust-compatible regex for complex pattern detection."</p>
                        <pre class="code-block">
"conditions:
  - regex:
      pattern: '^POST.*admin.*'
      case_insensitive: true"
                        </pre>
                    </div>
                </div>

                // 9 — File Types
                <div class="wiki-section">
                    <div class="wiki-section-num">"09"</div>
                    <div class="wiki-section-content">
                        <h4 class="wiki-title">"File Type Detection"</h4>
                        <p class="wiki-desc">"Detect file headers (magic bytes) inside the stream."</p>
                        <pre class="code-block">
"conditions:
  - file_type:
      file_types: ['exe', 'pdf', 'zip', 'png']"
                        </pre>
                    </div>
                </div>

                // 10 — Localhost & Context
                <div class="wiki-section">
                    <div class="wiki-section-num">"10"</div>
                    <div class="wiki-section-content">
                        <h4 class="wiki-title">"Localhost & Process Context"</h4>
                        <p class="wiki-desc">"Target specific network segments or loopback traffic types."</p>
                        <pre class="code-block">
"localhost_type: private_c  # Matches 192.168.x.x
# Options:
#   loopback   → 127.x
#   private_a  → 10.x
#   private_b  → 172.16-31.x
#   private_c  → 192.168.x.x
#   any        → matches all above"
                        </pre>
                    </div>
                </div>

                // 11 — Routines
                <div class="wiki-section">
                    <div class="wiki-section-num">"11"</div>
                    <div class="wiki-section-content">
                        <h4 class="wiki-title">"Advanced Traffic Routines"</h4>
                        <p class="wiki-desc">"Match specific flow directions (Source → Destination)."</p>
                        <pre class="code-block">
"routine:
  from_ip: '192.168.1.100'
  to_ip: 'any'
  to_port: 80"
                        </pre>
                    </div>
                </div>

                // ── Divider ─────────────────────────────────────────────
                <div class="wiki-divider">
                    <span>"EXAMPLE"</span>
                </div>

                // Complex example
                <div class="wiki-section wiki-section-example">
                    <div class="wiki-section-num wiki-num-red">"🔥"</div>
                    <div class="wiki-section-content">
                        <h4 class="wiki-title wiki-title-red">"C2 Beacon Detection"</h4>
                        <p class="wiki-desc">"Detects Base64-encoded beacons targeting suspicious TLDs — a classic APT indicator."</p>
                        <pre class="code-block code-block-red">
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

            </div>

            // ── Inline styles ─────────────────────────────────────────────
            <style>
"
.wiki-root {
    display: flex;
    flex-direction: column;
    overflow: hidden;
    padding: 0;
    flex: 1;
}

.wiki-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 18px 24px;
    border-bottom: 1px solid rgba(255,255,255,0.06);
    background: linear-gradient(90deg, rgba(74,158,255,0.05), transparent);
    flex-shrink: 0;
}

.wiki-header-left {
    display: flex;
    align-items: center;
    gap: 14px;
}

.wiki-header-icon {
    font-size: 22px;
    line-height: 1;
    filter: drop-shadow(0 0 10px rgba(74,158,255,0.4));
}

.wiki-header-title {
    margin: 0;
    font-size: 15px;
    font-weight: 800;
    color: #f0f2f7;
    letter-spacing: -0.3px;
}

.wiki-header-sub {
    font-size: 11px;
    color: #4a5162;
    margin-top: 2px;
    font-family: 'JetBrains Mono', monospace;
}

.wiki-version-chip {
    font-size: 10px;
    font-weight: 700;
    color: #4a9eff;
    background: rgba(74,158,255,0.10);
    border: 1px solid rgba(74,158,255,0.18);
    border-radius: 999px;
    padding: 3px 10px;
    letter-spacing: 0.06em;
}

.wiki-body {
    flex: 1;
    overflow-y: auto;
    padding: 20px 24px 32px;
    background: #08090d;
    display: flex;
    flex-direction: column;
    gap: 0;
}

.wiki-section {
    display: flex;
    gap: 18px;
    padding: 20px 0;
    border-bottom: 1px solid rgba(255,255,255,0.04);
}

.wiki-section:last-child { border-bottom: none; }

.wiki-section-num {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    font-weight: 700;
    color: #2a3040;
    min-width: 24px;
    padding-top: 2px;
    letter-spacing: 0.04em;
    text-align: right;
    flex-shrink: 0;
}

.wiki-num-red { color: transparent; font-size: 16px; }

.wiki-section-content { flex: 1; min-width: 0; }

.wiki-title {
    font-size: 12px;
    font-weight: 800;
    color: #4a9eff;
    margin: 0 0 7px;
    text-transform: uppercase;
    letter-spacing: 0.1em;
}

.wiki-title-red { color: #f53a3a; }

.wiki-desc {
    font-size: 13px;
    color: #6e7c94;
    margin: 0 0 12px;
    line-height: 1.65;
}

.inline-code {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11.5px;
    color: #4a9eff;
    background: rgba(74,158,255,0.08);
    border: 1px solid rgba(74,158,255,0.14);
    border-radius: 4px;
    padding: 1px 5px;
}

.code-block {
    background: #050608;
    padding: 14px 16px;
    border-radius: 10px;
    border: 1px solid rgba(255,255,255,0.055);
    border-top-color: rgba(255,255,255,0.09);
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    color: #7eb8ff;
    overflow-x: auto;
    white-space: pre;
    line-height: 1.65;
    box-shadow: inset 0 2px 10px rgba(0,0,0,0.4), 0 1px 0 rgba(255,255,255,0.03);
    margin: 0;
    display: block;
}

.code-block-red {
    color: #f07070;
    border-color: rgba(245,58,58,0.12);
    border-top-color: rgba(245,58,58,0.22);
    background: rgba(8,4,4,1);
}

.wiki-divider {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 24px 0 8px;
    color: #2a3040;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.14em;
    text-transform: uppercase;
}

.wiki-divider::before,
.wiki-divider::after {
    content: '';
    flex: 1;
    height: 1px;
    background: rgba(255,255,255,0.04);
}

.wiki-section-example {
    margin-top: 4px;
    border: 1px solid rgba(245,58,58,0.10);
    border-radius: 12px;
    padding: 20px;
    background: rgba(245,58,58,0.025);
    border-bottom: 1px solid rgba(245,58,58,0.10);
}
"
            </style>
        </div>
    }
}
