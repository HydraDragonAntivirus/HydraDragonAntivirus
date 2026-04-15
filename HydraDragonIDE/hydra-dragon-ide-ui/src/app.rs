// src/app.rs — HydraDragonIDE full Yew UI

use serde_json::json;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;
use crate::invoke::invoke;
use crate::types::*;

const DEFAULT_YARA: &str = r#"rule MZ_Header {
    meta:
        description = "Detects MZ executable header"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0
}

rule Suspicious_XOR_Loop {
    meta:
        description = "Generic XOR loop pattern (x86)"
    strings:
        $xor = { 30 ?? [0-4] (E2 | 75 | 74) }
    condition:
        any of them
}
"#;

const ROWS_PER_PAGE: usize = 512;
const DISASM_INSNS:  usize = 200;

// ─── helpers ─────────────────────────────────────────────────────────────────

fn load_hex_page(offset: u64, hp: UseStateHandle<Option<HexPage>>, st: UseStateHandle<String>) {
    spawn_local(async move {
        match invoke::<_, HexPage>("get_hex_page",
            &json!({"offset": offset, "num_rows": ROWS_PER_PAGE})).await
        {
            Ok(p)  => hp.set(Some(p)),
            Err(e) => st.set(format!("Hex error: {e}")),
        }
    });
}

// ─── component ───────────────────────────────────────────────────────────────
#[function_component]
pub fn App() -> Html {
    let file_info       = use_state(|| None::<FileInfo>);
    let hex_page        = use_state(|| None::<HexPage>);
    let hex_offset      = use_state(|| 0u64);
    let disasm_rows     = use_state(Vec::<DisasmRow>::new);
    let disasm_arch     = use_state(|| "x86_64".to_string());
    let disasm_base     = use_state(|| 0x00400000u64);
    let yara_rules_src  = use_state(|| DEFAULT_YARA.to_string());
    let yara_hits       = use_state(Vec::<YaraHit>::new);
    let bottom_tab      = use_state(|| BottomTab::YaraRules);
    let xor_key_hex     = use_state(|| "FF".to_string());
    let xor_result_hex  = use_state(String::new);
    let xor_candidates  = use_state(Vec::<XorCandidate>::new);
    let b64_input       = use_state(String::new);
    let b64_output      = use_state(String::new);
    let status          = use_state(|| "Ready. Open a file to begin analysis.".to_string());
    let selected_byte   = use_state(|| None::<u64>);
    let jump_offset     = use_state(|| "0".to_string());
    let entropy_sum     = use_state(|| None::<EntropySummary>);
    let extracted_strs  = use_state(Vec::<ExtractedString>::new);
    let str_filter      = use_state(String::new);
    let str_min_len     = use_state(|| 4usize);
    let parsed_headers  = use_state(|| None::<ParsedHeaders>);
    let pe_sub_tab      = use_state(|| "fields"); // "fields" | "sections" | "imports" | "exports"

    // ── open file ──────────────────────────────────────────────────────────
    let on_open_file = {
        let file_info=file_info.clone(); let hex_page=hex_page.clone();
        let hex_offset=hex_offset.clone(); let yara_hits=yara_hits.clone();
        let status=status.clone(); let entropy_sum=entropy_sum.clone();
        let extracted_strs=extracted_strs.clone(); let parsed_headers=parsed_headers.clone();
        Callback::from(move |_: MouseEvent| {
            let file_info=file_info.clone(); let hex_page=hex_page.clone();
            let hex_offset=hex_offset.clone(); let yara_hits=yara_hits.clone();
            let status=status.clone(); let entropy_sum=entropy_sum.clone();
            let extracted_strs=extracted_strs.clone(); let parsed_headers=parsed_headers.clone();
            spawn_local(async move {
                status.set("Opening file…".into());
                match invoke::<_, Option<FileInfo>>("open_file", &json!({})).await {
                    Ok(Some(info)) => {
                        let nm = info.path.split(['/','\\']).last().unwrap_or("?").to_string();
                        let sz = info.size;
                        file_info.set(Some(info));
                        yara_hits.set(vec![]);
                        hex_offset.set(0);
                        entropy_sum.set(None);
                        extracted_strs.set(vec![]);
                        parsed_headers.set(None);
                        status.set(format!("Loaded: {nm}  ({sz} bytes)"));
                        load_hex_page(0, hex_page, status);
                    }
                    Ok(None)  => status.set("Open cancelled.".into()),
                    Err(e)    => status.set(format!("Error: {e}")),
                }
            });
        })
    };

    // ── hex navigation ─────────────────────────────────────────────────────
    let on_prev_page = {
        let hex_offset=hex_offset.clone(); let hex_page=hex_page.clone(); let status=status.clone();
        Callback::from(move |_: MouseEvent| {
            let new_off = hex_offset.saturating_sub(ROWS_PER_PAGE as u64 * 16);
            hex_offset.set(new_off);
            load_hex_page(new_off, hex_page.clone(), status.clone());
        })
    };
    let on_next_page = {
        let hex_offset=hex_offset.clone(); let hex_page=hex_page.clone();
        let status=status.clone(); let file_info=file_info.clone();
        Callback::from(move |_: MouseEvent| {
            if let Some(info) = file_info.as_ref() {
                let pb  = ROWS_PER_PAGE as u64 * 16;
                let mx  = (info.size as u64).saturating_sub(pb);
                let off = (*hex_offset + pb).min(mx);
                hex_offset.set(off);
                load_hex_page(off, hex_page.clone(), status.clone());
            }
        })
    };
    let on_jump = {
        let jump_offset=jump_offset.clone(); let hex_offset=hex_offset.clone();
        let hex_page=hex_page.clone(); let status=status.clone();
        Callback::from(move |_: MouseEvent| {
            let raw = jump_offset.trim().to_lowercase();
            let parsed = if raw.starts_with("0x") {
                u64::from_str_radix(&raw[2..], 16)
            } else { raw.parse::<u64>() };
            match parsed {
                Ok(off) => { hex_offset.set(off); load_hex_page(off, hex_page.clone(), status.clone()); }
                Err(_)  => status.set(format!("Invalid offset: '{raw}'")),
            }
        })
    };

    // ── disasm ─────────────────────────────────────────────────────────────
    let on_disasm = {
        let disasm_rows=disasm_rows.clone(); let disasm_arch=disasm_arch.clone();
        let disasm_base=disasm_base.clone(); let selected=selected_byte.clone();
        let hex_offset=hex_offset.clone(); let status=status.clone();
        Callback::from(move |_: MouseEvent| {
            let disasm_rows=disasm_rows.clone(); let status=status.clone();
            let arch = (*disasm_arch).clone(); let base_addr = *disasm_base;
            let offset = selected.as_ref().copied().unwrap_or(*hex_offset);
            spawn_local(async move {
                status.set(format!("Disassembling at 0x{offset:X}…"));
                match invoke::<_, Vec<DisasmRow>>("disassemble_at",
                    &json!({"offset":offset,"arch":arch,"base_addr":base_addr,"num_insns":DISASM_INSNS})).await
                {
                    Ok(rows) => { let n=rows.len(); disasm_rows.set(rows); status.set(format!("Disassembled {n} instructions.")); }
                    Err(e)   => status.set(format!("Disasm error: {e}")),
                }
            });
        })
    };

    // ── YARA scan ──────────────────────────────────────────────────────────
    let on_yara_scan = {
        let yara_hits=yara_hits.clone(); let yara_rules_src=yara_rules_src.clone();
        let hex_page=hex_page.clone(); let hex_offset=hex_offset.clone();
        let status=status.clone(); let bottom_tab=bottom_tab.clone();
        Callback::from(move |_: MouseEvent| {
            let yara_hits=yara_hits.clone(); let hex_page=hex_page.clone();
            let status=status.clone(); let bottom_tab=bottom_tab.clone();
            let rules=(*yara_rules_src).clone(); let cur=*hex_offset;
            spawn_local(async move {
                status.set("Running YARA-X scan…".into());
                match invoke::<_, Vec<YaraHit>>("scan_yara", &json!({"rules_source":rules})).await {
                    Ok(hits) => {
                        let n=hits.len(); yara_hits.set(hits);
                        status.set(format!("YARA: {n} matches.")); bottom_tab.set(BottomTab::YaraResults);
                        load_hex_page(cur, hex_page, status);
                    }
                    Err(e) => status.set(format!("YARA error: {e}")),
                }
            });
        })
    };

    // ── entropy ────────────────────────────────────────────────────────────
    let on_entropy = {
        let entropy_sum=entropy_sum.clone(); let status=status.clone(); let bottom_tab=bottom_tab.clone();
        Callback::from(move |_: MouseEvent| {
            let entropy_sum=entropy_sum.clone(); let status=status.clone(); let bottom_tab=bottom_tab.clone();
            spawn_local(async move {
                status.set("Computing entropy…".into());
                match invoke::<_, EntropySummary>("compute_entropy", &json!({"block_size":256})).await {
                    Ok(s)  => { entropy_sum.set(Some(s)); status.set("Entropy done.".into()); bottom_tab.set(BottomTab::Entropy); }
                    Err(e) => status.set(format!("Entropy error: {e}")),
                }
            });
        })
    };

    // ── strings ────────────────────────────────────────────────────────────
    let on_extract_strings = {
        let extracted_strs=extracted_strs.clone(); let status=status.clone();
        let bottom_tab=bottom_tab.clone(); let str_min_len=str_min_len.clone();
        Callback::from(move |_: MouseEvent| {
            let extracted_strs=extracted_strs.clone(); let status=status.clone();
            let bottom_tab=bottom_tab.clone(); let min=*str_min_len;
            spawn_local(async move {
                status.set(format!("Extracting strings (min {min})…"));
                match invoke::<_, Vec<ExtractedString>>("extract_strings", &json!({"min_len":min})).await {
                    Ok(ss) => { let n=ss.len(); extracted_strs.set(ss); status.set(format!("Strings: {n} found.")); bottom_tab.set(BottomTab::Strings); }
                    Err(e) => status.set(format!("Strings error: {e}")),
                }
            });
        })
    };

    // ── PE headers ─────────────────────────────────────────────────────────
    let on_parse_headers = {
        let parsed_headers=parsed_headers.clone(); let status=status.clone(); let bottom_tab=bottom_tab.clone();
        Callback::from(move |_: MouseEvent| {
            let parsed_headers=parsed_headers.clone(); let status=status.clone(); let bottom_tab=bottom_tab.clone();
            spawn_local(async move {
                status.set("Parsing headers…".into());
                match invoke::<_, ParsedHeaders>("parse_headers", &json!({})).await {
                    Ok(h)  => { parsed_headers.set(Some(h)); status.set("Headers parsed.".into()); bottom_tab.set(BottomTab::PeHeaders); }
                    Err(e) => status.set(format!("Header error: {e}")),
                }
            });
        })
    };

    // ── XOR ────────────────────────────────────────────────────────────────
    let on_xor_brute = {
        let xor_candidates=xor_candidates.clone(); let status=status.clone();
        Callback::from(move |_: MouseEvent| {
            let xor_candidates=xor_candidates.clone(); let status=status.clone();
            spawn_local(async move {
                status.set("XOR brute-force…".into());
                match invoke::<_, Vec<XorCandidate>>("xor_brute_force", &json!({"sample_size":4096})).await {
                    Ok(c)  => { xor_candidates.set(c); status.set("XOR brute-force done.".into()); }
                    Err(e) => status.set(format!("XOR error: {e}")),
                }
            });
        })
    };
    let on_xor_decode = {
        let key=xor_key_hex.clone(); let result=xor_result_hex.clone();
        let selected=selected_byte.clone(); let hex_offset=hex_offset.clone(); let status=status.clone();
        Callback::from(move |_: MouseEvent| {
            let key=(*key).clone(); let result=result.clone(); let status=status.clone();
            let offset=selected.as_ref().copied().unwrap_or(*hex_offset);
            spawn_local(async move {
                match invoke::<_, String>("xor_decode_region",
                    &json!({"offset":offset,"length":256,"key_hex":key})).await
                {
                    Ok(h)  => result.set(h),
                    Err(e) => status.set(format!("XOR decode error: {e}")),
                }
            });
        })
    };

    // ── Base64 ─────────────────────────────────────────────────────────────
    let on_b64_decode = {
        let input=b64_input.clone(); let output=b64_output.clone(); let status=status.clone();
        Callback::from(move |_: MouseEvent| {
            let inp=(*input).clone(); let output=output.clone(); let status=status.clone();
            spawn_local(async move {
                match invoke::<_, String>("base64_decode_str", &json!({"input":inp})).await {
                    Ok(h)  => output.set(h),
                    Err(e) => status.set(format!("B64 decode error: {e}")),
                }
            });
        })
    };
    let on_b64_encode = {
        let selected=selected_byte.clone(); let hex_offset=hex_offset.clone();
        let output=b64_output.clone(); let status=status.clone();
        Callback::from(move |_: MouseEvent| {
            let output=output.clone(); let status=status.clone();
            let offset=selected.as_ref().copied().unwrap_or(*hex_offset);
            spawn_local(async move {
                match invoke::<_, String>("base64_encode_region",
                    &json!({"offset":offset,"length":256})).await
                {
                    Ok(b)  => output.set(b),
                    Err(e) => status.set(format!("B64 encode error: {e}")),
                }
            });
        })
    };

    // ── display helpers ────────────────────────────────────────────────────
    let file_name = file_info.as_ref()
        .and_then(|fi| fi.path.split(['/','\\']).last().map(|s| s.to_string()))
        .unwrap_or_else(|| "No file loaded".into());

    let str_filtered: Vec<_> = if str_filter.is_empty() {
        extracted_strs.iter().collect()
    } else {
        let f = str_filter.to_lowercase();
        extracted_strs.iter().filter(|s| s.value.to_lowercase().contains(&f)).collect()
    };

    // ─────────────────────────── RENDER ───────────────────────────────────
    html! {
    <div class="app">

    // ── TOPBAR ─────────────────────────────────────────────────────────────
    <header class="topbar">
        <span class="logo"><span class="logo-h">{"⬡"}</span>{" HydraDragonIDE"}</span>

        <div class="topbar-actions">
            <button class="btn-primary"  onclick={on_open_file}>{"⬆ Open"}</button>
            <button class="btn-accent"   onclick={on_yara_scan.clone()}>{"⚡ YARA"}</button>
            <button class="btn-ghost"    onclick={on_disasm}   >{"⚙ Disasm"}</button>
            <button class="btn-ghost"    onclick={on_entropy}  >{"📊 Entropy"}</button>
            <button class="btn-ghost"    onclick={on_extract_strings}>{"🔤 Strings"}</button>
            <button class="btn-ghost"    onclick={on_parse_headers} >{"🗂 Headers"}</button>
        </div>

        <div class="topbar-meta">
            <span class="file-label">{ file_name }</span>
            if let Some(fi) = file_info.as_ref() {
                <span class="file-meta">{
                    format!(" {}B  sha256:{}", fi.size, &fi.sha256[..8])
                }</span>
            }
        </div>

        <div class="topbar-right">
            <label class="meta-label">{"arch:"}</label>
            <select class="sel" onchange={{
                let arch=disasm_arch.clone();
                Callback::from(move |e: Event| {
                    use wasm_bindgen::JsCast;
                    if let Some(s) = e.target_dyn_into::<web_sys::HtmlSelectElement>() { arch.set(s.value()); }
                })
            }}>
                { for ["x86_64","x86_32","arm64","arm"].iter().map(|a| html!{
                    <option value={*a} selected={(*disasm_arch)==*a}>{a}</option>
                })}
            </select>
        </div>
    </header>

    // ── MAIN SPLIT ─────────────────────────────────────────────────────────
    <main class="main-split">

        // HEX PANEL
        <section class="panel hex-panel">
            <div class="panel-title">
                {"HEX VIEW"}
                <div class="hex-nav">
                    <input class="inp-jump" type="text" value={(*jump_offset).clone()}
                        placeholder="offset (hex/dec)"
                        oninput={{
                            let jo=jump_offset.clone();
                            Callback::from(move |e: InputEvent| {
                                use wasm_bindgen::JsCast;
                                if let Some(el)=e.target_dyn_into::<web_sys::HtmlInputElement>() { jo.set(el.value()); }
                            })
                        }}
                    />
                    <button class="btn-xs" onclick={on_jump}>{"Go"}</button>
                    <button class="btn-xs" onclick={on_prev_page}>{"◀"}</button>
                    <button class="btn-xs" onclick={on_next_page}>{"▶"}</button>
                    if let Some(pg)=hex_page.as_ref() {
                        <span class="hex-info">{format!("0x{:08X} / 0x{:08X}", *hex_offset, pg.total_bytes)}</span>
                    }
                </div>
            </div>
            <div class="hex-viewport">
                <div class="hex-header">
                    <span class="hex-hdr-addr">{"Offset  "}</span>
                    <span class="hex-hdr-bytes">{(0..16u8).map(|i| format!("{i:02X}")).collect::<Vec<_>>().join(" ")}</span>
                    <span class="hex-hdr-ascii">{"  ASCII"}</span>
                </div>
                { render_hex_rows(&hex_page, &selected_byte) }
            </div>
        </section>

        // DISASM PANEL
        <section class="panel disasm-panel">
            <div class="panel-title">{"DISASSEMBLY"}</div>
            <div class="disasm-viewport">
                if disasm_rows.is_empty() {
                    <div class="placeholder">{"Select a byte → click ⚙ Disasm"}</div>
                } else {
                    <table class="disasm-table">
                        <colgroup>
                            <col style="width:11ch"/><col style="width:22ch"/>
                            <col style="width:9ch"/><col/>
                        </colgroup>
                        { for disasm_rows.iter().map(|row| {
                            let cls = if row.mnemonic.starts_with("call") { "disasm-row call" }
                                      else if row.mnemonic.starts_with('j') { "disasm-row jmp" }
                                      else if row.mnemonic=="ret"||row.mnemonic=="retn" { "disasm-row ret" }
                                      else { "disasm-row" };
                            html!{<tr class={cls}>
                                <td class="addr">{format!("{:08X}", row.address)}</td>
                                <td class="bytes-col">{&row.bytes_hex}</td>
                                <td class="mnem">{&row.mnemonic}</td>
                                <td class="ops">{&row.operands}</td>
                            </tr>}
                        })}
                    </table>
                }
            </div>
        </section>
    </main>

    // ── BOTTOM TABS ─────────────────────────────────────────────────────────
    <footer class="bottom-area">
        <div class="tab-bar">
            { render_tab(&bottom_tab, BottomTab::YaraRules,   "⚡ YARA Rules") }
            { render_tab(&bottom_tab, BottomTab::YaraResults, "📋 Matches") }
            { render_tab(&bottom_tab, BottomTab::XorDecoder,  "🔑 XOR") }
            { render_tab(&bottom_tab, BottomTab::Base64,      "📦 Base64") }
            { render_tab(&bottom_tab, BottomTab::Strings,     "🔤 Strings") }
            { render_tab(&bottom_tab, BottomTab::Entropy,     "📊 Entropy") }
            { render_tab(&bottom_tab, BottomTab::PeHeaders,   "🗂 Headers") }
        </div>

        <div class="tab-content">
        { match *bottom_tab {

            // ── YARA rules editor ──────────────────────────────────────────
            BottomTab::YaraRules => html!{
                <div class="yara-editor-wrap">
                    <textarea class="code-editor" value={(*yara_rules_src).clone()}
                        oninput={{
                            let yr=yara_rules_src.clone();
                            Callback::from(move |e: InputEvent| {
                                use wasm_bindgen::JsCast;
                                if let Some(el)=e.target_dyn_into::<web_sys::HtmlTextAreaElement>() { yr.set(el.value()); }
                            })
                        }}
                    />
                    <div class="editor-actions">
                        <button class="btn-accent" onclick={on_yara_scan}>{"⚡ Run YARA Scan"}</button>
                    </div>
                </div>
            },

            // ── YARA results ───────────────────────────────────────────────
            BottomTab::YaraResults => html!{
                <div class="results-list">
                if yara_hits.is_empty() {
                    <div class="placeholder">{"No YARA matches yet."}</div>
                } else {
                    <table class="hit-table">
                        <thead><tr>
                            <th>{"Rule"}</th><th>{"Pattern"}</th>
                            <th>{"Offset"}</th><th>{"Length"}</th><th>{"Namespace"}</th>
                        </tr></thead>
                        <tbody>
                        { for yara_hits.iter().map(|hit| html!{<tr class="hit-row">
                            <td class="hit-rule">{&hit.rule_name}</td>
                            <td class="hit-pat">{&hit.pattern_name}</td>
                            <td class="hit-off">{format!("0x{:08X}", hit.offset)}</td>
                            <td class="hit-len">{hit.length}</td>
                            <td class="hit-ns">{&hit.namespace}</td>
                        </tr>})}
                        </tbody>
                    </table>
                }
                </div>
            },

            // ── XOR decoder ────────────────────────────────────────────────
            BottomTab::XorDecoder => html!{
                <div class="decoder-wrap">
                    <div class="decoder-controls">
                        <label class="meta-label">{"Key (hex):"}</label>
                        <input class="inp-key" type="text" value={(*xor_key_hex).clone()}
                            placeholder="e.g. FF or DEADBEEF"
                            oninput={{
                                let k=xor_key_hex.clone();
                                Callback::from(move |e: InputEvent| {
                                    use wasm_bindgen::JsCast;
                                    if let Some(el)=e.target_dyn_into::<web_sys::HtmlInputElement>() { k.set(el.value()); }
                                })
                            }}
                        />
                        <button class="btn-primary" onclick={on_xor_decode}>{"Decode 256B at cursor"}</button>
                        <button class="btn-ghost"   onclick={on_xor_brute} >{"Brute-force 1-byte key"}</button>
                    </div>
                    <div class="decoder-output">
                        <div class="decoded-hex">
                            <div class="output-label">{"Decoded (hex):"}</div>
                            <pre class="hex-pre">{(*xor_result_hex).clone()}</pre>
                        </div>
                        if !xor_candidates.is_empty() {
                            <div class="candidates">
                                <div class="output-label">{"Top XOR candidates:"}</div>
                                <table class="cand-table">
                                    <thead><tr><th>{"Key"}</th><th>{"ASCII%"}</th><th>{"Preview"}</th></tr></thead>
                                    <tbody>
                                    { for xor_candidates.iter().take(10).map(|c| html!{<tr>
                                        <td class="addr">{format!("0x{:02X}", c.key)}</td>
                                        <td>{format!("{:.0}%", c.ascii_score*100.0)}</td>
                                        <td class="cand-preview">{&c.preview}</td>
                                    </tr>})}
                                    </tbody>
                                </table>
                            </div>
                        }
                    </div>
                </div>
            },

            // ── Base64 ─────────────────────────────────────────────────────
            BottomTab::Base64 => html!{
                <div class="decoder-wrap">
                    <div class="decoder-controls">
                        <button class="btn-primary" onclick={on_b64_encode}>{"Encode 256B at cursor → Base64"}</button>
                        <button class="btn-ghost"   onclick={on_b64_decode}>{"Decode input → Hex"}</button>
                    </div>
                    <div class="decoder-output b64-output">
                        <div class="b64-col">
                            <div class="output-label">{"Input (Base64):"}</div>
                            <textarea class="b64-text" value={(*b64_input).clone()} placeholder="Paste Base64 here…"
                                oninput={{
                                    let bi=b64_input.clone();
                                    Callback::from(move |e: InputEvent| {
                                        use wasm_bindgen::JsCast;
                                        if let Some(el)=e.target_dyn_into::<web_sys::HtmlTextAreaElement>() { bi.set(el.value()); }
                                    })
                                }}
                            />
                        </div>
                        <div class="b64-col">
                            <div class="output-label">{"Output:"}</div>
                            <textarea class="b64-text" readonly=true value={(*b64_output).clone()}/>
                        </div>
                    </div>
                </div>
            },

            // ── Strings ────────────────────────────────────────────────────
            BottomTab::Strings => html!{
                <div class="decoder-wrap">
                    <div class="decoder-controls">
                        <label class="meta-label">{"Min length:"}</label>
                        <input class="inp-key" type="number" value={(*str_min_len).to_string()}
                            style="width:6ch;"
                            oninput={{
                                let sml=str_min_len.clone();
                                Callback::from(move |e: InputEvent| {
                                    use wasm_bindgen::JsCast;
                                    if let Some(el)=e.target_dyn_into::<web_sys::HtmlInputElement>() {
                                        if let Ok(v)=el.value().parse::<usize>() { sml.set(v); }
                                    }
                                })
                            }}
                        />
                        <button class="btn-primary" onclick={on_extract_strings}>{"🔤 Extract Strings"}</button>
                        <label class="meta-label" style="margin-left:12px;">{"Filter:"}</label>
                        <input class="inp-jump" type="text" value={(*str_filter).clone()} placeholder="search strings…"
                            oninput={{
                                let sf=str_filter.clone();
                                Callback::from(move |e: InputEvent| {
                                    use wasm_bindgen::JsCast;
                                    if let Some(el)=e.target_dyn_into::<web_sys::HtmlInputElement>() { sf.set(el.value()); }
                                })
                            }}
                        />
                        <span class="meta-label">{format!("  {} strings", str_filtered.len())}</span>
                    </div>
                    <div class="results-list">
                    if extracted_strs.is_empty() {
                        <div class="placeholder">{"Click 🔤 Extract Strings to begin."}</div>
                    } else {
                        <table class="hit-table">
                            <thead><tr>
                                <th>{"Offset"}</th><th>{"Kind"}</th>
                                <th>{"Len"}</th><th>{"Value"}</th>
                            </tr></thead>
                            <tbody>
                            { for str_filtered.iter().take(5000).map(|s| html!{<tr>
                                <td class="hit-off">{format!("0x{:08X}", s.offset)}</td>
                                <td class="hit-ns">{&s.kind}</td>
                                <td class="hit-len">{s.length}</td>
                                <td class="str-val">{&s.value}</td>
                            </tr>})}
                            </tbody>
                        </table>
                    }
                    </div>
                </div>
            },

            // ── Entropy ────────────────────────────────────────────────────
            BottomTab::Entropy => html!{
                <div class="decoder-wrap">
                    <div class="decoder-controls">
                        <button class="btn-primary" onclick={on_entropy}>{"📊 Compute Entropy (256B blocks)"}</button>
                        if let Some(s)=entropy_sum.as_ref() {
                            <span class="meta-label">{
                                format!("  min {:.2}  max {:.2}  mean {:.2}  ({} blocks)",
                                    s.min, s.max, s.mean, s.blocks.len())
                            }</span>
                        }
                    </div>
                    if let Some(sum)=entropy_sum.as_ref() {
                        <div class="entropy-wrap">
                            // heat-map bar
                            <div class="entropy-bar" title="Entropy heat-map (left=low offset, right=high)">
                            { for sum.blocks.iter().map(|b| {
                                let tip = format!("0x{:08X}  {:.2}  {}", b.offset, b.entropy, b.class);
                                html!{<span class="ebar-cell" style={format!("background:{}", b.colour)} title={tip}/>}
                            })}
                            </div>
                            // legend
                            <div class="entropy-legend">
                                { for [("#1e2a38","Zeroed <1.0"),("#166534","Plaintext 1–4.5"),
                                       ("#4fc3f7","Code 4.5–6.5"),("#fb923c","Compressed 6.5–7.2"),
                                       ("#f87171","Encrypted >7.2")]
                                    .iter().map(|(col,lbl)| html!{
                                        <span class="legend-item">
                                            <span class="legend-dot" style={format!("background:{col}")}/>
                                            {lbl}
                                        </span>
                                    })
                                }
                            </div>
                            // table of high-entropy regions (> 7.0)
                            <div class="entropy-table-wrap">
                                <div class="output-label">{"High-entropy regions (> 7.0) — likely packed/encrypted:"}</div>
                                <table class="hit-table">
                                    <thead><tr><th>{"Offset"}</th><th>{"Entropy"}</th><th>{"Class"}</th></tr></thead>
                                    <tbody>
                                    { for sum.blocks.iter().filter(|b| b.entropy > 7.0).map(|b| html!{<tr>
                                        <td class="hit-off">{format!("0x{:08X}", b.offset)}</td>
                                        <td class="hit-rule">{format!("{:.3}", b.entropy)}</td>
                                        <td class="hit-ns">{&b.class}</td>
                                    </tr>})}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    } else {
                        <div class="placeholder">{"Click 📊 Compute Entropy to analyse the loaded file."}</div>
                    }
                </div>
            },

            // ── PE / ELF headers ───────────────────────────────────────────
            BottomTab::PeHeaders => html!{
                <div class="decoder-wrap">
                    <div class="decoder-controls">
                        <button class="btn-primary" onclick={on_parse_headers}>{"🗂 Parse Headers"}</button>
                        if let Some(h)=parsed_headers.as_ref() {
                            <span class="meta-label" style="margin-left:8px;">{
                                format!("Format: {}  |  {} sections  |  {} imports  |  {} exports",
                                    h.format, h.sections.len(), h.imports.len(), h.exports.len())
                            }</span>
                            // sub-tabs
                            <div class="sub-tabs" style="margin-left:auto;">
                                { for [("fields","Fields"),("sections","Sections"),("imports","Imports"),("exports","Exports")]
                                    .iter().map(|(id,lbl)| {
                                        let pts=pe_sub_tab.clone(); let id_str=id.to_string();
                                        let active=(*pe_sub_tab)==id_str;
                                        let cls=if active {"tab active"} else {"tab"};
                                        html!{<button class={cls} onclick={{
                                            let pts=pts.clone(); let i=id_str.clone();
                                            Callback::from(move |_: MouseEvent| pts.set(i.clone()))
                                        }}>{lbl}</button>}
                                    })
                                }
                            </div>
                        }
                    </div>
                    if let Some(headers)=parsed_headers.as_ref() {
                        <div class="results-list">
                        { match pe_sub_tab.as_str() {
                            "sections" => html!{
                                <table class="hit-table">
                                    <thead><tr>
                                        <th>{"Name"}</th><th>{"VAddr"}</th><th>{"VSize"}</th>
                                        <th>{"RawOff"}</th><th>{"RawSz"}</th>
                                        <th>{"Entropy"}</th><th>{"Flags"}</th>
                                    </tr></thead>
                                    <tbody>
                                    { for headers.sections.iter().map(|s| {
                                        let hi_ent = s.entropy > 7.0;
                                        html!{<tr>
                                            <td class="hit-rule">{&s.name}</td>
                                            <td class="hit-off">{&s.virt_addr}</td>
                                            <td class="hit-len">{&s.virt_size}</td>
                                            <td class="hit-off">{&s.raw_offset}</td>
                                            <td class="hit-len">{&s.raw_size}</td>
                                            <td class={if hi_ent {"hit-rule"} else {"hit-ns"}}>{s.entropy}</td>
                                            <td class="hit-ns">{&s.flags}</td>
                                        </tr>}
                                    })}
                                    </tbody>
                                </table>
                            },
                            "imports" => html!{
                                <table class="hit-table">
                                    <thead><tr><th>{"DLL"}</th><th>{"Function"}</th><th>{"Ordinal"}</th></tr></thead>
                                    <tbody>
                                    { for headers.imports.iter().map(|i| html!{<tr>
                                        <td class="hit-ns">{&i.dll}</td>
                                        <td class="hit-rule">{&i.function}</td>
                                        <td class="hit-len">{i.ordinal.map(|o| o.to_string()).unwrap_or_default()}</td>
                                    </tr>})}
                                    </tbody>
                                </table>
                            },
                            "exports" => html!{
                                <table class="hit-table">
                                    <thead><tr><th>{"Ordinal"}</th><th>{"Name"}</th><th>{"Offset"}</th></tr></thead>
                                    <tbody>
                                    { for headers.exports.iter().map(|e| html!{<tr>
                                        <td class="hit-len">{e.ordinal}</td>
                                        <td class="hit-rule">{e.name.clone().unwrap_or_else(|| "(no name)".into())}</td>
                                        <td class="hit-off">{&e.offset}</td>
                                    </tr>})}
                                    </tbody>
                                </table>
                            },
                            _ => html!{ // fields
                                <table class="hit-table">
                                    <thead><tr><th>{"Field"}</th><th>{"Value"}</th></tr></thead>
                                    <tbody>
                                    { for headers.fields.iter().map(|f| html!{<tr>
                                        <td class="hit-ns">{&f.name}</td>
                                        <td class="hit-rule">{&f.value}</td>
                                    </tr>})}
                                    </tbody>
                                </table>
                            },
                        }}
                        </div>
                    } else {
                        <div class="placeholder">{"Click 🗂 Parse Headers to inspect PE/ELF structure."}</div>
                    }
                </div>
            },
        }}
        </div>
    </footer>

    // ── STATUS BAR ─────────────────────────────────────────────────────────
    <div class="statusbar">
        <span class="status-dot">{"●"}</span>
        { (*status).clone() }
        if let Some(off) = *selected_byte {
            <span class="status-sel">{format!("  │  0x{off:08X}")}</span>
        }
    </div>

    </div>
    }
}

// ─── sub-render helpers ───────────────────────────────────────────────────────

fn render_hex_rows(hp: &UseStateHandle<Option<HexPage>>, sel: &UseStateHandle<Option<u64>>) -> Html {
    let Some(page) = hp.as_ref() else {
        return html!{<div class="placeholder">{"No file loaded — click ⬆ Open"}</div>};
    };
    html!{<div class="hex-rows">{ for page.rows.iter().map(|row| render_hex_row(row, sel)) }</div>}
}

fn render_hex_row(row: &HexRow, sel: &UseStateHandle<Option<u64>>) -> Html {
    let ascii: String = row.bytes.iter()
        .map(|&b| if b>=0x20 && b<0x7F { b as char } else { '.' })
        .collect();

    html!{
        <div class="hex-row">
            <span class="hex-addr">{format!("{:08X}", row.offset)}</span>
            <span class="hex-sep">{"│"}</span>
            <span class="hex-bytes">
            { for row.bytes.iter().enumerate().map(|(i,&byte)| {
                let boff = row.offset + i as u64;
                let is_sel = *sel.as_ref() == Some(boff);
                let has_hit= row.hit_rules.get(i).and_then(|r| r.as_ref()).is_some();
                let cls = match (is_sel, has_hit) {
                    (true,  true)  => "byte sel hit",
                    (true,  false) => "byte sel",
                    (false, true)  => "byte hit",
                    (false, false) => "byte",
                };
                let gap = if i==8 { html!{<span class="byte-gap">{" "}</span>} } else { html!{} };
                let sh = sel.clone();
                let cb = Callback::from(move |_: MouseEvent| sh.set(Some(boff)));
                html!{<>
                    {gap}
                    <span class={cls} onclick={cb} title={format!("0x{boff:08X} = {byte}")}>
                        {format!("{:02X}", byte)}
                    </span>
                </>}
            })}
            </span>
            <span class="hex-sep">{"│"}</span>
            <span class="hex-ascii">{ascii}</span>
        </div>
    }
}

fn render_tab(cur: &UseStateHandle<BottomTab>, tab: BottomTab, lbl: &'static str) -> Html {
    let active = *cur.as_ref() == tab;
    let cls    = if active { "tab active" } else { "tab" };
    let cur    = cur.clone();
    let cb     = Callback::from(move |_: MouseEvent| cur.set(tab.clone()));
    html!{<button class={cls} onclick={cb}>{lbl}</button>}
}
