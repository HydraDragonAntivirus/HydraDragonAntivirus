use leptos::*;

#[component]
pub fn RulesWiki() -> impl IntoView {
    view! {
        <div class="wiki-root">

            // ── Top Bar ──────────────────────────────────────────────
            <div class="wiki-topbar">
                <div class="wiki-topbar-left">
                    <div class="wiki-logo-mark">"📖"</div>
                    <div class="wiki-topbar-info">
                        <span class="wiki-topbar-title">"Rules Reference"</span>
                        <span class="wiki-topbar-meta">"SDK v0.1.0 · YAML · 11 primitives"</span>
                    </div>
                </div>
                <div class="wiki-topbar-pills">
                    <span class="wiki-pill wiki-pill-cyan">"YAML"</span>
                    <span class="wiki-pill wiki-pill-acid">"LIVE"</span>
                </div>
            </div>

            // ── Body ────────────────────────────────────────────────
            <div class="wiki-body">

                // Left index column
                <div class="wiki-index">
                    <div class="wiki-index-item">"01 · Structure"</div>
                    <div class="wiki-index-item">"02 · Protocol"</div>
                    <div class="wiki-index-item">"03 · Actions"</div>
                    <div class="wiki-index-item">"04 · IP Conditions"</div>
                    <div class="wiki-index-item">"05 · Ports"</div>
                    <div class="wiki-index-item">"06 · Domain / URL"</div>
                    <div class="wiki-index-item">"07 · Payload"</div>
                    <div class="wiki-index-item">"08 · Regex"</div>
                    <div class="wiki-index-item">"09 · File Types"</div>
                    <div class="wiki-index-item">"10 · Scope"</div>
                    <div class="wiki-index-item">"11 · Routines"</div>
                    <div class="wiki-index-divider"/>
                    <div class="wiki-index-item wiki-index-fire">"🔥 C2 Example"</div>
                </div>

                // Right entries column
                <div class="wiki-entries">

                    <div class="wiki-entry">
                        <div class="wiki-entry-header">
                            <span class="wiki-num">"01"</span>
                            <span class="wiki-tag">"STRUCTURE"</span>
                            <h4 class="wiki-title">"Structure & Metadata"</h4>
                        </div>
                        <p class="wiki-desc">"Every rule needs a unique name, description, and enabled flag. The engine validates strict YAML on load."</p>
                        <div class="wiki-code-wrap"><div class="wiki-code-bar"><span class="wiki-code-lang">"YAML"</span><div class="wiki-dots"><span/><span/><span/></div></div>
                        <pre class="wiki-code">
<div class="yl-line yl-toplevel"><span class="yl-ln">" 1"</span><span class="yl-txt">"- name: 'My Unique Rule Name'"</span></div>
<div class="yl-line yl-value"><span class="yl-ln">" 2"</span><span class="yl-txt">"  description: 'What this rule detects'"</span></div>
<div class="yl-line yl-value"><span class="yl-ln">" 3"</span><span class="yl-txt">"  enabled: true"</span></div>
<div class="yl-line yl-comment"><span class="yl-ln">" 4"</span><span class="yl-txt">"  # false = disabled, not deleted"</span></div>
<div class="yl-line yl-value"><span class="yl-ln">" 5"</span><span class="yl-txt">"  condition_logic: and"</span></div>
<div class="yl-line yl-comment"><span class="yl-ln">" 6"</span><span class="yl-txt">"  # 'and' (all must match) | 'or' (any match)"</span></div>
                        </pre></div>
                    </div>

                    <div class="wiki-entry">
                        <div class="wiki-entry-header">
                            <span class="wiki-num">"02"</span>
                            <span class="wiki-tag">"PROTOCOL"</span>
                            <h4 class="wiki-title">"Protocol Matching"</h4>
                        </div>
                        <p class="wiki-desc">"Target a specific network protocol. Omit or use 'any' to match all traffic."</p>
                        <div class="wiki-code-wrap"><div class="wiki-code-bar"><span class="wiki-code-lang">"YAML"</span><div class="wiki-dots"><span/><span/><span/></div></div>
                        <pre class="wiki-code">
<div class="yl-line yl-toplevel"><span class="yl-ln">" 1"</span><span class="yl-txt">"protocol: http"</span></div>
<div class="yl-line yl-comment"><span class="yl-ln">" 2"</span><span class="yl-txt">"# http · https · tcp · udp · icmp · arp · any"</span></div>
                        </pre></div>
                    </div>

                    <div class="wiki-entry">
                        <div class="wiki-entry-header">
                            <span class="wiki-num">"03"</span>
                            <span class="wiki-tag">"ACTIONS"</span>
                            <h4 class="wiki-title">"Actions"</h4>
                        </div>
                        <p class="wiki-desc">"Defines what happens when a rule fires. Only one action is allowed per rule."</p>
                        <div class="wiki-code-wrap"><div class="wiki-code-bar"><span class="wiki-code-lang">"YAML"</span><div class="wiki-dots"><span/><span/><span/></div></div>
                        <pre class="wiki-code">
<div class="yl-line yl-toplevel"><span class="yl-ln">" 1"</span><span class="yl-txt">"action: block"</span></div>
<div class="yl-line yl-comment"><span class="yl-ln">" 2"</span><span class="yl-txt">"# Drop packet silently"</span></div>
<div class="yl-line yl-toplevel"><span class="yl-ln">" 3"</span><span class="yl-txt">"action: allow"</span></div>
<div class="yl-line yl-comment"><span class="yl-ln">" 4"</span><span class="yl-txt">"# Whitelist — bypass all further checks"</span></div>
<div class="yl-line yl-toplevel"><span class="yl-ln">" 5"</span><span class="yl-txt">"action: ask"</span></div>
<div class="yl-line yl-comment"><span class="yl-ln">" 6"</span><span class="yl-txt">"# Prompt user with popup decision"</span></div>
<div class="yl-line yl-toplevel"><span class="yl-ln">" 7"</span><span class="yl-txt">"action: traffic_attack"</span></div>
<div class="yl-line yl-comment"><span class="yl-ln">" 8"</span><span class="yl-txt">"# Mark as HIGH SEVERITY threat"</span></div>
<div class="yl-line yl-toplevel"><span class="yl-ln">" 9"</span><span class="yl-txt">"action: change_packet"</span></div>
<div class="yl-line yl-comment"><span class="yl-ln">"10"</span><span class="yl-txt">"# Rewrite payload content (advanced)"</span></div>
<div class="yl-line yl-toplevel"><span class="yl-ln">"11"</span><span class="yl-txt">"action: solve_packet"</span></div>
<div class="yl-line yl-comment"><span class="yl-ln">"12"</span><span class="yl-txt">"# Auto-repair malformed packets"</span></div>
                        </pre></div>
                    </div>

                    <div class="wiki-entry">
                        <div class="wiki-entry-header">
                            <span class="wiki-num">"04"</span>
                            <span class="wiki-tag">"IP"</span>
                            <h4 class="wiki-title">"IP Address Conditions"</h4>
                        </div>
                        <p class="wiki-desc">"Match source or destination addresses using exact IPs or CIDR notation."</p>
                        <div class="wiki-code-wrap"><div class="wiki-code-bar"><span class="wiki-code-lang">"YAML"</span><div class="wiki-dots"><span/><span/><span/></div></div>
                        <pre class="wiki-code">
<div class="yl-line yl-toplevel"><span class="yl-ln">" 1"</span><span class="yl-txt">"conditions:"</span></div>
<div class="yl-line yl-key"><span class="yl-ln">" 2"</span><span class="yl-txt">"  - src_ip:"</span></div>
<div class="yl-line yl-value"><span class="yl-ln">" 3"</span><span class="yl-txt">"      addresses:   ['192.168.1.55', '10.0.0.1']"</span></div>
<div class="yl-line yl-value"><span class="yl-ln">" 4"</span><span class="yl-txt">"      cidr_ranges: ['172.16.0.0/12', '10.0.0.0/8']"</span></div>
<div class="yl-line yl-key"><span class="yl-ln">" 5"</span><span class="yl-txt">"  - dst_ip:"</span></div>
<div class="yl-line yl-value"><span class="yl-ln">" 6"</span><span class="yl-txt">"      addresses: ['8.8.8.8']"</span></div>
                        </pre></div>
                    </div>

                    <div class="wiki-entry">
                        <div class="wiki-entry-header">
                            <span class="wiki-num">"05"</span>
                            <span class="wiki-tag">"PORTS"</span>
                            <h4 class="wiki-title">"Port Matching"</h4>
                        </div>
                        <p class="wiki-desc">"Filter by specific ports or inclusive port ranges."</p>
                        <div class="wiki-code-wrap"><div class="wiki-code-bar"><span class="wiki-code-lang">"YAML"</span><div class="wiki-dots"><span/><span/><span/></div></div>
                        <pre class="wiki-code">
<div class="yl-line yl-toplevel"><span class="yl-ln">" 1"</span><span class="yl-txt">"conditions:"</span></div>
<div class="yl-line yl-key"><span class="yl-ln">" 2"</span><span class="yl-txt">"  - dst_port:"</span></div>
<div class="yl-line yl-value"><span class="yl-ln">" 3"</span><span class="yl-txt">"      ports:  [80, 443, 8080, 8443]"</span></div>
<div class="yl-line yl-value"><span class="yl-ln">" 4"</span><span class="yl-txt">"      ranges: [(1000, 2000), (30000, 65535)]"</span></div>
                        </pre></div>
                    </div>

                    <div class="wiki-entry">
                        <div class="wiki-entry-header">
                            <span class="wiki-num">"06"</span>
                            <span class="wiki-tag">"WEB"</span>
                            <h4 class="wiki-title">"Domain & URL Filtering"</h4>
                        </div>
                        <p class="wiki-desc">"Wildcard matching for web traffic. All comparisons are case-insensitive."</p>
                        <div class="wiki-code-wrap"><div class="wiki-code-bar"><span class="wiki-code-lang">"YAML"</span><div class="wiki-dots"><span/><span/><span/></div></div>
                        <pre class="wiki-code">
<div class="yl-line yl-toplevel"><span class="yl-ln">" 1"</span><span class="yl-txt">"conditions:"</span></div>
<div class="yl-line yl-key"><span class="yl-ln">" 2"</span><span class="yl-txt">"  - domain:"</span></div>
<div class="yl-line yl-value"><span class="yl-ln">" 3"</span><span class="yl-txt">"      domains: ['*.google.com', 'tracking.*']"</span></div>
<div class="yl-line yl-key"><span class="yl-ln">" 4"</span><span class="yl-txt">"  - url:"</span></div>
<div class="yl-line yl-value"><span class="yl-ln">" 5"</span><span class="yl-txt">"      patterns: ['*/login.php', '*?query=malicious*']"</span></div>
                        </pre></div>
                    </div>

                    <div class="wiki-entry">
                        <div class="wiki-entry-header">
                            <span class="wiki-num">"07"</span>
                            <span class="wiki-tag">"PAYLOAD"</span>
                            <h4 class="wiki-title">"Content Inspection & Encoding"</h4>
                        </div>
                        <p class="wiki-desc">"Deep payload scanning with multi-layer encoding support to surface obfuscated threats."</p>
                        <div class="wiki-code-wrap"><div class="wiki-code-bar"><span class="wiki-code-lang">"YAML"</span><div class="wiki-dots"><span/><span/><span/></div></div>
                        <pre class="wiki-code">
<div class="yl-line yl-comment"><span class="yl-ln">" 1"</span><span class="yl-txt">"# Declare the encoding layer first"</span></div>
<div class="yl-line yl-toplevel"><span class="yl-ln">" 2"</span><span class="yl-txt">"encoding: base64"</span></div>
<div class="yl-line yl-comment"><span class="yl-ln">" 3"</span><span class="yl-txt">"# plain · base64 · base58 · hex · reverse"</span></div>
<div class="yl-line yl-toplevel"><span class="yl-ln">" 4"</span><span class="yl-txt">"conditions:"</span></div>
<div class="yl-line yl-comment"><span class="yl-ln">" 5"</span><span class="yl-txt">"  # Searched AFTER the payload is decoded"</span></div>
<div class="yl-line yl-key"><span class="yl-ln">" 6"</span><span class="yl-txt">"  - content_match: 'powershell.exe -nop -w hidden'"</span></div>
                        </pre></div>
                    </div>

                    <div class="wiki-entry">
                        <div class="wiki-entry-header">
                            <span class="wiki-num">"08"</span>
                            <span class="wiki-tag">"REGEX"</span>
                            <h4 class="wiki-title">"Regex Matching"</h4>
                        </div>
                        <p class="wiki-desc">"Rust-compatible regular expressions for complex pattern detection."</p>
                        <div class="wiki-code-wrap"><div class="wiki-code-bar"><span class="wiki-code-lang">"YAML"</span><div class="wiki-dots"><span/><span/><span/></div></div>
                        <pre class="wiki-code">
<div class="yl-line yl-toplevel"><span class="yl-ln">" 1"</span><span class="yl-txt">"conditions:"</span></div>
<div class="yl-line yl-key"><span class="yl-ln">" 2"</span><span class="yl-txt">"  - regex:"</span></div>
<div class="yl-line yl-value"><span class="yl-ln">" 3"</span><span class="yl-txt">"      pattern:          '^POST.*\\/admin\\/.*'"</span></div>
<div class="yl-line yl-value"><span class="yl-ln">" 4"</span><span class="yl-txt">"      case_insensitive: true"</span></div>
                        </pre></div>
                    </div>

                    <div class="wiki-entry">
                        <div class="wiki-entry-header">
                            <span class="wiki-num">"09"</span>
                            <span class="wiki-tag">"FILES"</span>
                            <h4 class="wiki-title">"File Type Detection"</h4>
                        </div>
                        <p class="wiki-desc">"Identify files by magic bytes inside the stream — independent of extension."</p>
                        <div class="wiki-code-wrap"><div class="wiki-code-bar"><span class="wiki-code-lang">"YAML"</span><div class="wiki-dots"><span/><span/><span/></div></div>
                        <pre class="wiki-code">
<div class="yl-line yl-toplevel"><span class="yl-ln">" 1"</span><span class="yl-txt">"conditions:"</span></div>
<div class="yl-line yl-key"><span class="yl-ln">" 2"</span><span class="yl-txt">"  - file_type:"</span></div>
<div class="yl-line yl-value"><span class="yl-ln">" 3"</span><span class="yl-txt">"      file_types: ['exe', 'pdf', 'zip', 'png', 'docx']"</span></div>
                        </pre></div>
                    </div>

                    <div class="wiki-entry">
                        <div class="wiki-entry-header">
                            <span class="wiki-num">"10"</span>
                            <span class="wiki-tag">"SCOPE"</span>
                            <h4 class="wiki-title">"Localhost & Network Scope"</h4>
                        </div>
                        <p class="wiki-desc">"Narrow rules to specific RFC-1918 segments or loopback traffic."</p>
                        <div class="wiki-code-wrap"><div class="wiki-code-bar"><span class="wiki-code-lang">"YAML"</span><div class="wiki-dots"><span/><span/><span/></div></div>
                        <pre class="wiki-code">
<div class="yl-line yl-toplevel"><span class="yl-ln">" 1"</span><span class="yl-txt">"localhost_type: private_c"</span></div>
<div class="yl-line yl-comment"><span class="yl-ln">" 2"</span><span class="yl-txt">"# loopback  → 127.x.x.x"</span></div>
<div class="yl-line yl-comment"><span class="yl-ln">" 3"</span><span class="yl-txt">"# private_a → 10.x.x.x"</span></div>
<div class="yl-line yl-comment"><span class="yl-ln">" 4"</span><span class="yl-txt">"# private_b → 172.16–31.x.x"</span></div>
<div class="yl-line yl-comment"><span class="yl-ln">" 5"</span><span class="yl-txt">"# private_c → 192.168.x.x"</span></div>
<div class="yl-line yl-comment"><span class="yl-ln">" 6"</span><span class="yl-txt">"# any       → all of the above"</span></div>
                        </pre></div>
                    </div>

                    <div class="wiki-entry">
                        <div class="wiki-entry-header">
                            <span class="wiki-num">"11"</span>
                            <span class="wiki-tag">"ROUTINES"</span>
                            <h4 class="wiki-title">"Advanced Traffic Routines"</h4>
                        </div>
                        <p class="wiki-desc">"Define directional flow matching: Source → Destination."</p>
                        <div class="wiki-code-wrap"><div class="wiki-code-bar"><span class="wiki-code-lang">"YAML"</span><div class="wiki-dots"><span/><span/><span/></div></div>
                        <pre class="wiki-code">
<div class="yl-line yl-toplevel"><span class="yl-ln">" 1"</span><span class="yl-txt">"routine:"</span></div>
<div class="yl-line yl-value"><span class="yl-ln">" 2"</span><span class="yl-txt">"  from_ip: '192.168.1.100'"</span></div>
<div class="yl-line yl-value"><span class="yl-ln">" 3"</span><span class="yl-txt">"  to_ip:   'any'"</span></div>
<div class="yl-line yl-value"><span class="yl-ln">" 4"</span><span class="yl-txt">"  to_port: 80"</span></div>
                        </pre></div>
                    </div>

                    // ── Section break ─────────────────────────────────
                    <div class="wiki-break">
                        <div class="wiki-break-line"/>
                        <span class="wiki-break-label">"COMPLEX EXAMPLE"</span>
                        <div class="wiki-break-line"/>
                    </div>

                    // ── C2 Danger Entry ───────────────────────────────
                    <div class="wiki-entry wiki-entry-danger">
                        <div class="wiki-danger-ribbon"><span>"HIGH SEVERITY"</span></div>
                        <div class="wiki-entry-header">
                            <span class="wiki-num wiki-num-fire">"🔥"</span>
                            <span class="wiki-tag wiki-tag-red">"THREAT INTEL"</span>
                            <h4 class="wiki-title wiki-title-red">"APT28 · C2 Beacon Detection"</h4>
                        </div>
                        <p class="wiki-desc">
                            "Detects Base64-encoded beacons phoning home to suspicious TLDs — "
                            "a hallmark of APT infrastructure. Combines domain, payload, and port "
                            "conditions with " <code class="wiki-icode">"condition_logic: and"</code>
                            " for precision detection."
                        </p>
                        <div class="wiki-code-wrap wiki-code-danger-wrap">
                            <div class="wiki-code-bar wiki-code-bar-danger">
                                <span class="wiki-code-lang">"YAML"</span>
                                <span class="wiki-danger-pulse">"⚠ LIVE RULE"</span>
                                <div class="wiki-dots"><span/><span/><span/></div>
                            </div>
                            <pre class="wiki-code wiki-code-dark">
<div class="yl-line yl-toplevel"><span class="yl-ln">" 1"</span><span class="yl-txt">"- name: 'APT28 C2 Beacon Detection'"</span></div>
<div class="yl-line yl-value"><span class="yl-ln">" 2"</span><span class="yl-txt">"  description: 'Detects Base64 encoded beacons to suspicious TLDs'"</span></div>
<div class="yl-line yl-value"><span class="yl-ln">" 3"</span><span class="yl-txt">"  enabled: true"</span></div>
<div class="yl-line yl-toplevel"><span class="yl-ln">" 4"</span><span class="yl-txt">"  protocol: https"</span></div>
<div class="yl-line yl-toplevel"><span class="yl-ln">" 5"</span><span class="yl-txt">"  action: traffic_attack"</span></div>
<div class="yl-line yl-toplevel"><span class="yl-ln">" 6"</span><span class="yl-txt">"  condition_logic: and"</span></div>
<div class="yl-line yl-toplevel"><span class="yl-ln">" 7"</span><span class="yl-txt">"  encoding: base64"</span></div>
<div class="yl-line yl-toplevel"><span class="yl-ln">" 8"</span><span class="yl-txt">"  conditions:"</span></div>
<div class="yl-line yl-key"><span class="yl-ln">" 9"</span><span class="yl-txt">"    - domain:"</span></div>
<div class="yl-line yl-value"><span class="yl-ln">"10"</span><span class="yl-txt">"        domains: ['*.xyz', '*.top', '*.ru']"</span></div>
<div class="yl-line yl-key"><span class="yl-ln">"11"</span><span class="yl-txt">"    - content_match: 'cmd=whoami'"</span></div>
<div class="yl-line yl-key"><span class="yl-ln">"12"</span><span class="yl-txt">"    - dst_port:"</span></div>
<div class="yl-line yl-value"><span class="yl-ln">"13"</span><span class="yl-txt">"        ports: [443, 8443, 4443]"</span></div>
                            </pre>
                        </div>
                    </div>

                </div>
            </div>

            // ── Inline Styles ─────────────────────────────────────────
            <style>
"
.wiki-root {
    display: flex !important;
    flex-direction: column !important;
    overflow: hidden !important;
    padding: 0 !important;
    flex: 1;
}

.wiki-topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 22px;
    border-bottom: 1px solid rgba(255,255,255,0.05);
    background: linear-gradient(90deg, rgba(0,207,255,0.05), transparent 60%);
    flex-shrink: 0;
}

.wiki-topbar-left { display: flex; align-items: center; gap: 13px; }

.wiki-logo-mark {
    width: 44px; height: 44px;
    background: rgba(0,207,255,0.07);
    border: 1px solid rgba(0,207,255,0.16);
    border-radius: 9px;
    display: flex; align-items: center; justify-content: center;
    font-size: 22px; flex-shrink: 0;
}

.wiki-topbar-info { display: flex; flex-direction: column; gap: 2px; }

.wiki-topbar-title {
    font-family: 'Oxanium', sans-serif;
    font-size: 17px !important; font-weight: 800;
    color: #F4F6FF;
    letter-spacing: 0.08em; text-transform: uppercase;
}

.wiki-topbar-meta {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 12.5px !important; color: #4A5270;
    letter-spacing: 0.08em;
}

.wiki-topbar-pills { display: flex; gap: 7px; }

.wiki-pill {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 8.5px; font-weight: 700;
    letter-spacing: 0.14em; text-transform: uppercase;
    padding: 3px 9px; border-radius: 3px;
}

.wiki-pill-cyan {
    color: #00CFFF; background: rgba(0,207,255,0.07);
    border: 1px solid rgba(0,207,255,0.16);
}

.wiki-pill-acid {
    color: #0CF584; background: rgba(12,245,132,0.07);
    border: 1px solid rgba(12,245,132,0.16);
    animation: wiki-glow 2s ease-in-out infinite;
}

@keyframes wiki-glow {
    0%,100% { box-shadow: none; opacity: 0.8; }
    50%      { box-shadow: 0 0 10px rgba(12,245,132,0.3); opacity: 1; }
}

/* ── Body layout ── */
.wiki-body {
    flex: 1; display: flex; overflow: hidden;
    background: #040509;
}

/* ── Index column ── */
.wiki-index {
    width: 200px; flex-shrink: 0;
    border-right: 1px solid rgba(255,255,255,0.04);
    padding: 40px 0 18px !important; overflow-y: auto;
    background: rgba(3,4,9,0.7);
    display: flex; flex-direction: column; gap: 1px;
}

.wiki-index-item {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 12px; font-weight: 500;
    color: #3A4260;
    padding: 8px 18px; cursor: pointer;
    transition: color 0.12s, background 0.12s;
    letter-spacing: 0.03em;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}

.wiki-index-item:hover { color: #6B7591; background: rgba(255,255,255,0.025); }
.wiki-index-fire { color: rgba(255,38,38,0.35); }
.wiki-index-fire:hover { color: rgba(255,38,38,0.65); background: rgba(255,38,38,0.04); }
.wiki-index-divider { height: 1px; background: rgba(255,255,255,0.04); margin: 10px 14px; }

/* ── Entries column ── */
.wiki-entries {
    flex: 1; overflow-y: auto; padding: 16px 26px 40px;
    overscroll-behavior: contain;
}

/* ── Entry ── */
.wiki-entry {
    padding: 20px 0 26px;
    border-bottom: 1px solid rgba(255,255,255,0.035);
    position: relative;
}
.wiki-entry:last-child { border-bottom: none; }

.wiki-entry-header {
    display: flex; align-items: center; gap: 9px; margin-bottom: 8px;
}

.wiki-num {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 9.5px; font-weight: 700; color: #1E2540;
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.05);
    border-radius: 4px; width: 28px; height: 20px;
    display: flex; align-items: center; justify-content: center;
    letter-spacing: 0.06em; flex-shrink: 0;
}

.wiki-num-fire {
    font-size: 14px;
    border-color: rgba(255,38,38,0.18);
    background: rgba(255,38,38,0.05);
    color: transparent; width: 28px; height: 20px;
}

.wiki-tag {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 8.5px; font-weight: 700;
    letter-spacing: 0.14em; text-transform: uppercase;
    color: rgba(0,207,255,0.55);
    background: rgba(0,207,255,0.055);
    border: 1px solid rgba(0,207,255,0.10);
    border-radius: 3px; padding: 2px 7px; flex-shrink: 0;
}

.wiki-tag-red {
    color: rgba(255,38,38,0.6);
    background: rgba(255,38,38,0.06);
    border-color: rgba(255,38,38,0.12);
}

.wiki-title {
    font-family: 'Oxanium', sans-serif;
    font-size: 14px; font-weight: 700;
    color: #8899BB; margin: 0; letter-spacing: 0.02em;
}
.wiki-title-red { color: #FF6868; }

.wiki-desc {
    font-size: 12px; color: #3D4A68; margin: 0 0 13px;
    line-height: 1.7; max-width: 640px;
}

.wiki-icode {
    font-family: 'IBM Plex Mono', monospace; font-size: 11px;
    color: #00CFFF; background: rgba(0,207,255,0.07);
    border: 1px solid rgba(0,207,255,0.12);
    border-radius: 3px; padding: 1px 5px;
}

/* ── Code wrap ── */
.wiki-code-wrap {
    border: 1px solid rgba(255,255,255,0.05);
    border-radius: 9px; overflow: hidden; background: #02030A;
}

.wiki-code-danger-wrap {
    border-color: rgba(255,38,38,0.13);
    box-shadow: 0 0 28px rgba(255,38,38,0.04);
}

.wiki-code-bar {
    display: flex; align-items: center; justify-content: space-between;
    padding: 7px 14px;
    background: rgba(255,255,255,0.022);
    border-bottom: 1px solid rgba(255,255,255,0.04);
}

.wiki-code-bar-danger {
    background: rgba(255,38,38,0.045);
    border-bottom-color: rgba(255,38,38,0.07);
}

.wiki-code-lang {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 8.5px; font-weight: 700;
    color: #1E2540; letter-spacing: 0.16em; text-transform: uppercase;
}

.wiki-danger-pulse {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 8.5px; font-weight: 700;
    color: rgba(255,38,38,0.55); letter-spacing: 0.12em;
    animation: wiki-glow 2s ease-in-out infinite;
}

.wiki-dots { display: flex; gap: 5px; align-items: center; }
.wiki-dots span {
    width: 7px; height: 7px; border-radius: 50%;
    background: rgba(255,255,255,0.07);
}
.wiki-dots span:nth-child(1) { background: rgba(255,38,38,0.30); }
.wiki-dots span:nth-child(2) { background: rgba(255,186,8,0.25); }
.wiki-dots span:nth-child(3) { background: rgba(12,245,132,0.25); }

.wiki-code {
    margin: 0; padding: 10px 0; overflow-x: auto;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 11.5px; line-height: 1;
    background: transparent;
}

.wiki-code-dark { background: rgba(5,1,1,1); }

/* ── Syntax lines ── */
.yl-line {
    display: flex; align-items: baseline;
    padding: 2.5px 0; transition: background 0.1s ease;
}
.yl-line:hover { background: rgba(255,255,255,0.022); }

.yl-ln {
    font-size: 10px; color: #1A2040;
    min-width: 36px; padding: 0 12px 0 12px;
    text-align: right; user-select: none; flex-shrink: 0;
    border-right: 1px solid rgba(255,255,255,0.025);
}

.yl-txt { padding-left: 14px; white-space: pre; letter-spacing: 0.01em; }

.yl-comment .yl-txt { color: #253048; font-style: italic; }
.yl-comment .yl-ln  { color: #131A2A; }
.yl-toplevel .yl-txt { color: #7eb8ff; }
.yl-toplevel .yl-ln  { color: #1A2A50; }
.yl-key .yl-txt { color: rgba(12,245,132,0.8); }
.yl-key .yl-ln  { color: #0C2020; }
.yl-value .yl-txt { color: #7880A8; }
.yl-value .yl-ln  { color: #161D38; }

/* ── Section break ── */
.wiki-break {
    display: flex; align-items: center; gap: 14px;
    padding: 28px 0 4px;
}
.wiki-break-line {
    flex: 1; height: 1px;
    background: linear-gradient(90deg, transparent, rgba(255,38,38,0.18), transparent);
}
.wiki-break-label {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 8.5px; font-weight: 700;
    color: rgba(255,38,38,0.35); letter-spacing: 0.20em;
    text-transform: uppercase; white-space: nowrap;
}

/* ── Danger entry ── */
.wiki-entry-danger {
    background: rgba(255,38,38,0.016) !important;
    border: 1px solid rgba(255,38,38,0.10) !important;
    border-radius: 11px !important;
    padding: 20px 20px 24px !important;
    margin-top: 6px;
    overflow: hidden;
}

.wiki-entry-danger::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; height: 1px;
    background: linear-gradient(90deg, transparent, rgba(255,38,38,0.45), transparent);
}

.wiki-danger-ribbon {
    position: absolute;
    top: 26px; right: -40px;
    width: 170px;
    background: var(--red, #FF2626);
    padding: 5px 0;
    transform: rotate(45deg);
    font-family: 'IBM Plex Mono', monospace;
    font-size: 9px; font-weight: 800;
    color: #fff; letter-spacing: 0.12em; text-transform: uppercase;
    pointer-events: none;
    box-shadow: 0 2px 16px rgba(255,38,38,0.4);
    text-align: center;
}
"
            </style>
        </div>
    }
}
