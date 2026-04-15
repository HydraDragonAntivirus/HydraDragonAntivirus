use serde::{Deserialize, Serialize};
use serde_json::json;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileInfo {
    pub path: String,
    pub size: usize,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HexRow {
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub hit_rules: Vec<Option<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HexPage {
    pub rows: Vec<HexRow>,
    pub total_rows: usize,
    pub total_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DisasmRow {
    pub address: u64,
    pub bytes_hex: String,
    pub mnemonic: String,
    pub operands: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct YaraHit {
    pub rule_name: String,
    pub namespace: String,
    pub pattern_name: String,
    pub offset: usize,
    pub length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct XorCandidate {
    pub key: u8,
    pub ascii_score: f32,
    pub preview: String,
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(catch, js_namespace = ["window", "__TAURI__", "core"])]
    async fn invoke(cmd: &str, args: JsValue) -> Result<JsValue, JsValue>;
}

async fn tauri_invoke<T, R>(cmd: &str, args: &T) -> Result<R, String>
where
    T: Serialize,
    for<'de> R: Deserialize<'de>,
{
    let args_js = serde_wasm_bindgen::to_value(args).map_err(|e| e.to_string())?;
    let res_js = invoke(cmd, args_js)
        .await
        .map_err(|e| e.as_string().unwrap_or_else(|| format!("{e:?}")))?;
    serde_wasm_bindgen::from_value(res_js).map_err(|e| e.to_string())
}

fn format_size(size: usize) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];

    let mut value = size as f64;
    let mut unit_index = 0usize;
    while value >= 1024.0 && unit_index < UNITS.len() - 1 {
        value /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", size, UNITS[unit_index])
    } else {
        format!("{value:.2} {}", UNITS[unit_index])
    }
}

fn parse_offset_input(input: &str) -> Option<u64> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).ok();
    }

    if trimmed
        .chars()
        .any(|c| c.is_ascii_hexdigit() && c.is_ascii_alphabetic())
    {
        return u64::from_str_radix(trimmed, 16).ok();
    }

    trimmed
        .parse::<u64>()
        .ok()
        .or_else(|| u64::from_str_radix(trimmed, 16).ok())
}

fn selected_byte_details(hex_page: Option<&HexPage>, selected_byte: Option<u64>) -> Option<(u8, Option<String>)> {
    let selected = selected_byte?;
    let page = hex_page?;

    for row in &page.rows {
        let row_start = row.offset;
        let row_end = row.offset + row.bytes.len() as u64;
        if (row_start..row_end).contains(&selected) {
            let index = (selected - row_start) as usize;
            return Some((row.bytes[index], row.hit_rules[index].clone()));
        }
    }

    None
}

#[derive(Properties, PartialEq)]
pub struct HexViewProps {
    pub hex_page: Option<HexPage>,
    pub selected_byte: Option<u64>,
    pub on_byte_click: Callback<u64>,
}

#[function_component]
fn HexView(props: &HexViewProps) -> Html {
    html! {
        <div class="table-wrap editor-table-wrap">
            <table class="hex-table">
                <thead>
                    <tr>
                        <th>{"Offset"}</th>
                        { for (0..16).map(|i| html! { <th>{format!("{i:02X}")}</th> }) }
                        <th>{"ASCII"}</th>
                    </tr>
                </thead>
                <tbody>
                    {
                        if let Some(page) = &props.hex_page {
                            html! {
                                { for page.rows.iter().map(|row| {
                                    html! {
                                        <tr>
                                            <td class="hex-offset">{format!("0x{:08X}", row.offset)}</td>
                                            {
                                                for row.bytes.iter().enumerate().map(|(index, byte)| {
                                                    let offset = row.offset + index as u64;
                                                    let is_selected = Some(offset) == props.selected_byte;
                                                    let is_hit = row
                                                        .hit_rules
                                                        .get(index)
                                                        .and_then(|rule| rule.as_deref())
                                                        .is_some();
                                                    let class_name = classes!(
                                                        "hex-byte",
                                                        is_selected.then_some("is-selected"),
                                                        is_hit.then_some("is-hit"),
                                                    );
                                                    let title = row
                                                        .hit_rules
                                                        .get(index)
                                                        .and_then(|rule| rule.as_ref())
                                                        .cloned()
                                                        .unwrap_or_default();

                                                    html! {
                                                        <td
                                                            class={class_name}
                                                            title={title}
                                                            onclick={{
                                                                let on_byte_click = props.on_byte_click.clone();
                                                                Callback::from(move |_| on_byte_click.emit(offset))
                                                            }}
                                                        >
                                                            {format!("{byte:02X}")}
                                                        </td>
                                                    }
                                                })
                                            }
                                            <td class="ascii-cell">
                                                {
                                                    for row.bytes.iter().map(|byte| {
                                                        let chr = if (0x20..=0x7e).contains(byte) {
                                                            *byte as char
                                                        } else {
                                                            '.'
                                                        };
                                                        html! { <span>{chr}</span> }
                                                    })
                                                }
                                            </td>
                                        </tr>
                                    }
                                }) }
                            }
                        } else {
                            Html::default()
                        }
                    }
                </tbody>
            </table>
        </div>
    }
}

#[derive(Properties, PartialEq)]
pub struct DisasmPanelProps {
    pub rows: Vec<DisasmRow>,
    pub has_file: bool,
    pub target_offset: u64,
}

#[function_component]
fn DisasmPanel(props: &DisasmPanelProps) -> Html {
    let _ = props.target_offset;

    html! {
        <div class="table-wrap">
            <table class="disasm-table">
                <thead>
                    <tr>
                        <th>{"Address"}</th>
                        <th>{"Bytes"}</th>
                        <th>{"Mnemonic"}</th>
                        <th>{"Operands"}</th>
                    </tr>
                </thead>
                <tbody>
                    {
                        if props.has_file {
                            html! {
                                { for props.rows.iter().map(|row| {
                                    html! {
                                        <tr>
                                            <td class="mono-accent">{format!("0x{:08X}", row.address)}</td>
                                            <td class="mono-dim">{&row.bytes_hex}</td>
                                            <td class="mono-strong">{&row.mnemonic}</td>
                                            <td class="mono-dim">{&row.operands}</td>
                                        </tr>
                                    }
                                }) }
                            }
                        } else {
                            Html::default()
                        }
                    }
                </tbody>
            </table>
        </div>
    }
}

#[function_component]
pub fn App() -> Html {
    const ROWS_PER_PAGE: usize = 512;
    const PAGE_BYTES: u64 = (ROWS_PER_PAGE as u64) * 16;
    const DEFAULT_YARA: &str = r#"rule HydraDragon_MZ_Header {
    meta:
        author = "HydraDragonIDE"
        description = "Starter rule for quick binary pivots"

    strings:
        $mz = { 4D 5A }

    condition:
        $mz at 0
}"#;

    let file_info = use_state(|| None::<FileInfo>);
    let hex_page = use_state(|| None::<HexPage>);
    let hex_offset = use_state(|| 0u64);
    let disasm_rows = use_state(Vec::<DisasmRow>::new);
    let yara_rules_src = use_state(|| DEFAULT_YARA.to_string());
    let yara_hits = use_state(Vec::<YaraHit>::new);
    let xor_key_hex = use_state(|| "FF".to_string());
    let xor_result_hex = use_state(String::new);
    let xor_candidates = use_state(Vec::<XorCandidate>::new);
    let b64_input = use_state(String::new);
    let b64_output = use_state(String::new);
    let status = use_state(|| "Ready.".to_string());
    let selected_byte = use_state(|| None::<u64>);
    let jump_input = use_state(|| "0x00000000".to_string());

    let load_hex = {
        let hex_page = hex_page.clone();
        let hex_offset = hex_offset.clone();
        let jump_input = jump_input.clone();
        let status = status.clone();

        Callback::from(move |offset: u64| {
            let hex_page = hex_page.clone();
            let hex_offset = hex_offset.clone();
            let jump_input = jump_input.clone();
            let status = status.clone();

            spawn_local(async move {
                match tauri_invoke::<_, HexPage>(
                    "get_hex_page",
                    &json!({ "offset": offset, "num_rows": ROWS_PER_PAGE }),
                )
                .await
                {
                    Ok(page) => {
                        hex_offset.set(offset);
                        jump_input.set(format!("0x{offset:08X}"));
                        hex_page.set(Some(page));
                    }
                    Err(error) => status.set(format!("Hex view error: {error}")),
                }
            });
        })
    };

    let request_disasm = {
        let disasm_rows = disasm_rows.clone();
        let status = status.clone();

        Callback::from(move |target: u64| {
            let disasm_rows = disasm_rows.clone();
            let status = status.clone();

            spawn_local(async move {
                match tauri_invoke::<_, Vec<DisasmRow>>(
                    "disassemble_at",
                    &json!({
                        "offset": target,
                        "arch": "x86_64",
                        "base_addr": 0x400000u64,
                        "num_insns": 100usize
                    }),
                )
                .await
                {
                    Ok(rows) => disasm_rows.set(rows),
                    Err(error) => status.set(format!("Disassembly error: {error}")),
                }
            });
        })
    };

    let on_open_file = {
        let file_info = file_info.clone();
        let selected_byte = selected_byte.clone();
        let disasm_rows = disasm_rows.clone();
        let yara_hits = yara_hits.clone();
        let xor_result_hex = xor_result_hex.clone();
        let xor_candidates = xor_candidates.clone();
        let b64_input = b64_input.clone();
        let b64_output = b64_output.clone();
        let load_hex = load_hex.clone();
        let request_disasm = request_disasm.clone();
        let jump_input = jump_input.clone();
        let status = status.clone();

        Callback::from(move |_| {
            let file_info = file_info.clone();
            let selected_byte = selected_byte.clone();
            let disasm_rows = disasm_rows.clone();
            let yara_hits = yara_hits.clone();
            let xor_result_hex = xor_result_hex.clone();
            let xor_candidates = xor_candidates.clone();
            let b64_input = b64_input.clone();
            let b64_output = b64_output.clone();
            let load_hex = load_hex.clone();
            let request_disasm = request_disasm.clone();
            let jump_input = jump_input.clone();
            let status = status.clone();

            spawn_local(async move {
                match tauri_invoke::<_, Option<FileInfo>>("open_file", &json!({})).await {
                    Ok(Some(info)) => {
                        status.set(format!("Loaded {}", info.path));
                        file_info.set(Some(info));
                        selected_byte.set(None);
                        disasm_rows.set(Vec::new());
                        yara_hits.set(Vec::new());
                        xor_result_hex.set(String::new());
                        xor_candidates.set(Vec::new());
                        b64_input.set(String::new());
                        b64_output.set(String::new());
                        jump_input.set("0x00000000".to_string());
                        load_hex.emit(0);
                        request_disasm.emit(0);
                    }
                    Ok(None) => status.set("Open file cancelled.".to_string()),
                    Err(error) => status.set(format!("Open file error: {error}")),
                }
            });
        })
    };

    let on_scan = {
        let yara_hits = yara_hits.clone();
        let yara_rules_src = yara_rules_src.clone();
        let status = status.clone();
        let load_hex = load_hex.clone();
        let hex_offset = hex_offset.clone();

        Callback::from(move |_| {
            let yara_hits = yara_hits.clone();
            let status = status.clone();
            let load_hex = load_hex.clone();
            let hex_offset = hex_offset.clone();
            let rules = (*yara_rules_src).clone();

            spawn_local(async move {
                status.set("Running YARA scan...".to_string());
                match tauri_invoke::<_, Vec<YaraHit>>(
                    "scan_yara",
                    &json!({ "rules_source": rules }),
                )
                .await
                {
                    Ok(hits) => {
                        let hit_count = hits.len();
                        yara_hits.set(hits);
                        status.set(format!("YARA scan completed with {hit_count} hit(s)."));
                        load_hex.emit(*hex_offset);
                    }
                    Err(error) => status.set(format!("YARA error: {error}")),
                }
            });
        })
    };

    let on_run_disasm = {
        let request_disasm = request_disasm.clone();
        let selected_byte = selected_byte.clone();
        let hex_offset = hex_offset.clone();

        Callback::from(move |_| {
            let target = (*selected_byte).unwrap_or(*hex_offset);
            request_disasm.emit(target);
        })
    };

    let on_xor_decode = {
        let xor_key_hex = xor_key_hex.clone();
        let xor_result_hex = xor_result_hex.clone();
        let selected_byte = selected_byte.clone();
        let hex_offset = hex_offset.clone();
        let status = status.clone();

        Callback::from(move |_| {
            let xor_key_hex = xor_key_hex.clone();
            let xor_result_hex = xor_result_hex.clone();
            let status = status.clone();
            let target = (*selected_byte).unwrap_or(*hex_offset);

            spawn_local(async move {
                match tauri_invoke::<_, String>(
                    "xor_decode_region",
                    &json!({
                        "offset": target,
                        "length": 256usize,
                        "key_hex": (*xor_key_hex).clone()
                    }),
                )
                .await
                {
                    Ok(output) => xor_result_hex.set(output),
                    Err(error) => status.set(format!("XOR decode error: {error}")),
                }
            });
        })
    };

    let on_xor_brute = {
        let xor_candidates = xor_candidates.clone();
        let status = status.clone();

        Callback::from(move |_| {
            let xor_candidates = xor_candidates.clone();
            let status = status.clone();

            spawn_local(async move {
                match tauri_invoke::<_, Vec<XorCandidate>>(
                    "xor_brute_force",
                    &json!({ "sample_size": 1024usize }),
                )
                .await
                {
                    Ok(candidates) => xor_candidates.set(candidates),
                    Err(error) => status.set(format!("XOR brute force error: {error}")),
                }
            });
        })
    };

    let on_b64_encode = {
        let b64_output = b64_output.clone();
        let selected_byte = selected_byte.clone();
        let hex_offset = hex_offset.clone();
        let status = status.clone();

        Callback::from(move |_| {
            let b64_output = b64_output.clone();
            let status = status.clone();
            let target = (*selected_byte).unwrap_or(*hex_offset);

            spawn_local(async move {
                match tauri_invoke::<_, String>(
                    "base64_encode_region",
                    &json!({ "offset": target, "length": 64usize }),
                )
                .await
                {
                    Ok(encoded) => b64_output.set(encoded),
                    Err(error) => status.set(format!("Base64 encode error: {error}")),
                }
            });
        })
    };

    let on_b64_decode = {
        let b64_input = b64_input.clone();
        let b64_output = b64_output.clone();
        let status = status.clone();

        Callback::from(move |_| {
            let b64_output = b64_output.clone();
            let status = status.clone();
            let input = (*b64_input).clone();

            spawn_local(async move {
                match tauri_invoke::<_, String>("base64_decode_str", &json!({ "input": input })).await {
                    Ok(decoded) => b64_output.set(decoded),
                    Err(error) => status.set(format!("Base64 decode error: {error}")),
                }
            });
        })
    };

    let on_select_byte = {
        let selected_byte = selected_byte.clone();
        let status = status.clone();

        Callback::from(move |offset: u64| {
            selected_byte.set(Some(offset));
            status.set(format!("Selected offset 0x{offset:08X}."));
        })
    };

    let on_prev_page = {
        let load_hex = load_hex.clone();
        let hex_offset = hex_offset.clone();

        Callback::from(move |_| {
            let new_offset = hex_offset.saturating_sub(PAGE_BYTES);
            load_hex.emit(new_offset);
        })
    };

    let on_next_page = {
        let load_hex = load_hex.clone();
        let hex_offset = hex_offset.clone();

        Callback::from(move |_| {
            load_hex.emit(*hex_offset + PAGE_BYTES);
        })
    };

    let on_jump_to_offset = {
        let jump_input = jump_input.clone();
        let load_hex = load_hex.clone();
        let status = status.clone();

        Callback::from(move |_| {
            if let Some(offset) = parse_offset_input((*jump_input).as_str()) {
                load_hex.emit(offset);
            } else {
                status.set(format!("Invalid offset: {}", (*jump_input).clone()));
            }
        })
    };

    let has_file = (*file_info).is_some();
    let active_offset = (*selected_byte).unwrap_or(*hex_offset);
    let selection_details = selected_byte_details((*hex_page).as_ref(), *selected_byte);
    let (selected_hex, selected_ascii, selected_rule) = if let Some((byte, hit_rule)) = selection_details {
        let ascii = if (0x20..=0x7e).contains(&byte) {
            (byte as char).to_string()
        } else {
            ".".to_string()
        };
        (
            format!("{byte:02X}"),
            ascii,
            hit_rule.unwrap_or_else(|| "-".to_string()),
        )
    } else {
        ("--".to_string(), "--".to_string(), "-".to_string())
    };

    let file_path = (*file_info)
        .as_ref()
        .map(|info| info.path.clone())
        .unwrap_or_else(|| "No file".to_string());
    let file_size = (*file_info)
        .as_ref()
        .map(|info| format_size(info.size))
        .unwrap_or_else(|| "0 B".to_string());
    let file_sha256 = (*file_info)
        .as_ref()
        .map(|info| info.sha256.clone())
        .unwrap_or_else(|| "-".to_string());

    html! {
        <div class="app-shell">
            <header class="topbar">
                <div class="brand-block">
                    <div class="eyebrow">{"HydraDragon"}</div>
                    <h1>{"HydraDragonIDE"}</h1>
                    <p>{"Single-screen binary editor workspace with analysis tools kept in the same flow."}</p>
                </div>
            </header>

            <main class="workspace workspace-fixed">
                <section class="workbench workbench-fixed">
                    <div class="workbench-toolbar">
                        <div class="toolbar-group">
                            <button class="btn btn-primary" onclick={on_open_file}>{"Open File"}</button>
                            <button class="btn" onclick={on_scan.clone()} disabled={!has_file}>{"Run YARA"}</button>
                            <button class="btn" onclick={on_run_disasm.clone()} disabled={!has_file}>{"Disassemble"}</button>
                            <button class="btn" onclick={on_prev_page.clone()} disabled={!has_file || *hex_offset == 0}>{"Page -"}</button>
                            <button class="btn" onclick={on_next_page.clone()} disabled={!has_file}>{"Page +"}</button>
                        </div>

                        <div class="toolbar-group">
                            <label class="field-inline" for="offset-jump">{"Offset"}</label>
                            <input
                                id="offset-jump"
                                class="text-input offset-input"
                                value={(*jump_input).clone()}
                                oninput={{
                                    let jump_input = jump_input.clone();
                                    Callback::from(move |event: InputEvent| {
                                        if let Some(input) = event.target_dyn_into::<web_sys::HtmlInputElement>() {
                                            jump_input.set(input.value());
                                        }
                                    })
                                }}
                            />
                            <button class="btn" onclick={on_jump_to_offset} disabled={!has_file}>{"Jump"}</button>
                        </div>
                    </div>

                    <div class="meta-strip meta-strip-compact">
                        <div class="meta-item meta-item-wide">
                            <span class="summary-label">{"File"}</span>
                            <code>{file_path}</code>
                        </div>
                        <div class="meta-item">
                            <span class="summary-label">{"Size"}</span>
                            <strong>{file_size}</strong>
                        </div>
                        <div class="meta-item">
                            <span class="summary-label">{"Offset"}</span>
                            <strong>{format!("0x{:08X}", active_offset)}</strong>
                        </div>
                        <div class="meta-item">
                            <span class="summary-label">{"Byte"}</span>
                            <strong>{selected_hex}</strong>
                        </div>
                        <div class="meta-item">
                            <span class="summary-label">{"ASCII"}</span>
                            <strong>{selected_ascii}</strong>
                        </div>
                        <div class="meta-item">
                            <span class="summary-label">{"Hits"}</span>
                            <strong>{yara_hits.len()}</strong>
                        </div>
                        <div class="meta-item meta-item-wide">
                            <span class="summary-label">{"Rule"}</span>
                            <code>{selected_rule}</code>
                        </div>
                        <div class="meta-item meta-item-wide">
                            <span class="summary-label">{"SHA-256"}</span>
                            <code>{file_sha256}</code>
                        </div>
                    </div>

                    <div class="viewport-layout">
                        <div class="viewport-editor">
                            <div class="workbench-head">
                                <div>
                                    <h2>{"Editor"}</h2>
                                    <p>{"Hex editor stays visible all the time."}</p>
                                </div>
                                <div class="section-actions">
                                    <span class="chip">{format!("Page offset 0x{:08X}", *hex_offset)}</span>
                                </div>
                            </div>
                            <HexView
                                hex_page={(*hex_page).clone()}
                                selected_byte={*selected_byte}
                                on_byte_click={on_select_byte}
                            />
                        </div>

                        <div class="viewport-disasm">
                            <div class="workbench-head">
                                <div>
                                    <h2>{"Disassembly"}</h2>
                                    <p>{"Selection or current offset."}</p>
                                </div>
                                <div class="section-actions">
                                    <span class="chip">{format!("{}", disasm_rows.len())}</span>
                                    <button class="btn btn-small" onclick={on_run_disasm.clone()} disabled={!has_file}>{"Refresh"}</button>
                                </div>
                            </div>
                            <DisasmPanel
                                rows={(*disasm_rows).clone()}
                                has_file={has_file}
                                target_offset={active_offset}
                            />
                        </div>
                    </div>

                    <div class="tool-grid">
                        <div class="tool-panel tool-panel-yara">
                            <div class="workbench-head">
                                <div>
                                    <h2>{"YARA"}</h2>
                                    <p>{"Rules and matches."}</p>
                                </div>
                                <div class="section-actions">
                                    <button class="btn btn-small" onclick={on_scan} disabled={!has_file}>{"Scan"}</button>
                                </div>
                            </div>

                            <textarea
                                id="yara-rules"
                                class="text-editor text-editor-tight"
                                value={(*yara_rules_src).clone()}
                                oninput={{
                                    let yara_rules_src = yara_rules_src.clone();
                                    Callback::from(move |event: InputEvent| {
                                        if let Some(input) = event.target_dyn_into::<web_sys::HtmlTextAreaElement>() {
                                            yara_rules_src.set(input.value());
                                        }
                                    })
                                }}
                            />

                            <div class="table-wrap tool-fill">
                                <table class="result-table">
                                    <thead>
                                        <tr>
                                            <th>{"Rule"}</th>
                                            <th>{"Offset"}</th>
                                            <th>{"Length"}</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        { for yara_hits.iter().map(|hit| {
                                            html! {
                                                <tr>
                                                    <td>{&hit.rule_name}</td>
                                                    <td class="mono-accent">{format!("0x{:X}", hit.offset)}</td>
                                                    <td>{hit.length}</td>
                                                </tr>
                                            }
                                        }) }
                                    </tbody>
                                </table>
                            </div>
                        </div>

                        <div class="tool-panel">
                            <div class="workbench-head">
                                <div>
                                    <h2>{"XOR"}</h2>
                                    <p>{"Decode and brute force."}</p>
                                </div>
                            </div>

                            <div class="control-row">
                                <label class="field-inline" for="xor-key">{"Key"}</label>
                                <input
                                    id="xor-key"
                                    class="text-input"
                                    value={(*xor_key_hex).clone()}
                                    oninput={{
                                        let xor_key_hex = xor_key_hex.clone();
                                        Callback::from(move |event: InputEvent| {
                                            if let Some(input) = event.target_dyn_into::<web_sys::HtmlInputElement>() {
                                                xor_key_hex.set(input.value());
                                            }
                                        })
                                    }}
                                />
                                <button class="btn btn-small" onclick={on_xor_decode} disabled={!has_file}>{"Decode"}</button>
                                <button class="btn btn-small" onclick={on_xor_brute} disabled={!has_file}>{"Brute"}</button>
                            </div>

                            <pre class="output-block tool-output">{(*xor_result_hex).clone()}</pre>

                            <div class="table-wrap tool-fill">
                                <table class="result-table">
                                    <thead>
                                        <tr>
                                            <th>{"Key"}</th>
                                            <th>{"Score"}</th>
                                            <th>{"Preview"}</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        { for xor_candidates.iter().map(|candidate| {
                                            html! {
                                                <tr>
                                                    <td class="mono-accent">{format!("0x{:02X}", candidate.key)}</td>
                                                    <td>{format!("{:.1}%", candidate.ascii_score * 100.0)}</td>
                                                    <td class="mono-dim">{&candidate.preview}</td>
                                                </tr>
                                            }
                                        }) }
                                    </tbody>
                                </table>
                            </div>
                        </div>

                        <div class="tool-panel">
                            <div class="workbench-head">
                                <div>
                                    <h2>{"Base64"}</h2>
                                    <p>{"Encode and decode."}</p>
                                </div>
                                <div class="section-actions">
                                    <button class="btn btn-small" onclick={on_b64_encode} disabled={!has_file}>{"Encode"}</button>
                                    <button class="btn btn-small" onclick={on_b64_decode}>{"Decode"}</button>
                                </div>
                            </div>

                            <textarea
                                id="b64-input"
                                class="text-editor text-editor-tight"
                                value={(*b64_input).clone()}
                                oninput={{
                                    let b64_input = b64_input.clone();
                                    Callback::from(move |event: InputEvent| {
                                        if let Some(input) = event.target_dyn_into::<web_sys::HtmlTextAreaElement>() {
                                            b64_input.set(input.value());
                                        }
                                    })
                                }}
                            />

                            <textarea
                                id="b64-output"
                                class="text-editor text-editor-tight tool-fill"
                                readonly=true
                                value={(*b64_output).clone()}
                            />
                        </div>
                    </div>
                </section>
            </main>

            <footer class="statusbar">
                <span class="status-dot"></span>
                <span>{(*status).clone()}</span>
                <span class="status-chip">{format!("Active offset 0x{:08X}", active_offset)}</span>
            </footer>
        </div>
    }
}
