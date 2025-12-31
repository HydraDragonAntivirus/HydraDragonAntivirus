use js_sys::Reflect;
use leptos::*;
// Assuming imports work.
use serde::{Deserialize, Serialize};
use std::time::Duration;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

mod wiki;
use wiki::RulesWiki;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "core"])]
    async fn invoke(cmd: &str, args: JsValue) -> JsValue;

    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "event"])]
    async fn listen(event: &str, handler: &Closure<dyn FnMut(JsValue)>) -> JsValue;

    // For window control in alert mode
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "window"])]
    async fn getCurrentWindow() -> JsValue;
}

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum LogLevel {
    Info,
    Success,
    Warning,
    Error,
    #[serde(other)]
    Other,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: String,
    pub timestamp: u64,
    pub level: LogLevel,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingApp {
    pub process_id: u32,
    pub name: String,
    pub path: String,
    pub dst_ip: String,
    pub dst_port: u16,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RawPacket {
    pub id: String,
    pub timestamp: u64,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub length: usize,
    pub payload_hex: String,
    pub payload_preview: String,
    pub summary: String,
    // Process Correlation
    pub process_id: u32,
    pub process_name: String,
    pub process_path: String,
    // SDK/Rule Context
    pub action: String,
    pub rule: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ResolveArgs {
    name: String,
    decision: String,
}

#[derive(Copy, Clone, PartialEq)]
enum AppView {
    Dashboard,
    Rules,
    Logs,
    PacketReader,
    Settings,
    Exclusions,
}

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    Raw(u8),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum AppDecision {
    Allow,
    Block,
    Pending,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FirewallRule {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    #[serde(default)]
    pub block: bool,
    #[serde(default)]
    pub protocol: Option<Protocol>,
    #[serde(default)]
    pub remote_ips: Vec<String>,
    #[serde(default)]
    pub remote_ports: Vec<u16>,
    #[serde(default)]
    pub app_name: Option<String>,
    #[serde(default)]
    pub hostname_pattern: Option<String>,
    #[serde(default)]
    pub url_pattern: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RuleActionView {
    TrafficAttack,
    Block,
    Allow,
    Ask,
    ChangePacket,
    SolvePacket,
    InjectDll,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SdkRuleView {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub enabled: bool,
    pub action: RuleActionView,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct FirewallSettings {
    #[serde(default)]
    pub website_path: String,
    #[serde(default)]
    pub rules: Vec<FirewallRule>,
}

#[component]
pub fn App() -> impl IntoView {
    let (logs, set_logs) = create_signal(Vec::<LogEntry>::new());
    let (blocked_count, set_blocked_count) = create_signal(0);
    let (threats_count, set_threats_count) = create_signal(0);
    let (allowed_count, set_allowed_count) = create_signal(0);
    let (total_count, set_total_count) = create_signal(0);

    // Navigation State
    let (current_view, set_current_view) = create_signal(AppView::Dashboard);
    let (raw_packets, set_raw_packets) = create_signal(Vec::<RawPacket>::new());
    let (selected_packet, set_selected_packet) = create_signal(Option::<RawPacket>::None);
    let (sdk_rules, set_sdk_rules) = create_signal(Vec::<SdkRuleView>::new());
    
    // Editor State
    let (show_editor, set_show_editor) = create_signal(false);
    let (rules_raw_content, set_rules_raw_content) = create_signal(String::new());
    let (validation_result, set_validation_result) = create_signal(String::from("Ready to validate.")); // Validation status

    let fetch_sdk_rules = move || {
        spawn_local(async move {
            let args = js_sys::Object::new();
            let val = invoke("get_sdk_rules", args.into()).await;
            let rules: Vec<SdkRuleView> = serde_wasm_bindgen::from_value(val).unwrap_or_default();
            set_sdk_rules.set(rules);
        });
    };

    let fetch_rules_raw = move || {
        spawn_local(async move {
             let args = js_sys::Object::new();
             let val = invoke("get_rules_content", args.into()).await;
             if let Some(s) = val.as_string() {
                 set_rules_raw_content.set(s);
             }
        });
    };

    let save_rules_raw = move || {
        let content = rules_raw_content.get();
        spawn_local(async move {
            let args = js_sys::Object::new();
            js_sys::Reflect::set(&args, &"content".into(), &content.into()).unwrap();
            
            // Allow failure (result)
            match invoke("save_rules_content", args.into()).await.as_string() {
                 _ => {
                     // Reload rules list
                     fetch_sdk_rules();
                     set_show_editor.set(false);
                 }
            }
        });
    };

    let validate_rules_raw = move || {
        let content = rules_raw_content.get();
        set_validation_result.set("Validating...".to_string());
        spawn_local(async move {
            let args = js_sys::Object::new();
            js_sys::Reflect::set(&args, &"content".into(), &content.into()).unwrap();
            
            match invoke("validate_rules_content", args.into()).await.as_string() {
                Some(msg) => set_validation_result.set(msg),
                None => set_validation_result.set("Unknown validation error".to_string()),
            }
        });
    };




    let (app_decisions, set_app_decisions) = create_signal(std::collections::HashMap::<String, AppDecision>::new());

    let fetch_app_decisions = move || {
        spawn_local(async move {
            let res = invoke("get_app_decisions", JsValue::NULL).await;
            if let Ok(decisions) = serde_wasm_bindgen::from_value::<std::collections::HashMap<String, AppDecision>>(res) {
                set_app_decisions.set(decisions);
            }
        });
    };

    create_effect(move |_| {
        match current_view.get() {
            AppView::Rules => {
                fetch_sdk_rules();
                fetch_rules_raw();
            }
            AppView::Exclusions => {
                fetch_app_decisions();
            }
            _ => {}
        }
    });

    // Rule Modal State & Validation
    let (show_rule_modal, set_show_rule_modal) = create_signal(false);
    let (new_rule_name, set_new_rule_name) = create_signal(String::new());
    let (new_rule_desc, set_new_rule_desc) = create_signal(String::new());
    let (new_rule_ips, set_new_rule_ips) = create_signal(String::new());
    let (new_rule_ports, set_new_rule_ports) = create_signal(String::new());
    let (new_rule_protocol, set_new_rule_protocol) = create_signal("Any".to_string());
    let (new_rule_block, set_new_rule_block) = create_signal(true);



    let remove_decision_action = move |name: String| {
        spawn_local(async move {
            let args = serde_wasm_bindgen::to_value(&serde_json::json!({ "name_lower": name })).unwrap();
            let _ = invoke("remove_app_decision", args).await;
            fetch_app_decisions(); // Refresh list
        });
    };
    let (validation_error, set_validation_error) = create_signal(Option::<String>::None);
    let (console_output, set_console_output) = create_signal(Vec::<String>::new());
    let (is_compiling, set_is_compiling) = create_signal(false);
    let (active_tab, set_active_tab) = create_signal("rule".to_string());

    let (pending_app, set_pending_app) = create_signal(Option::<PendingApp>::None);
    let (saved_status, set_saved_status) = create_signal(false);
    let (engine_status, set_engine_status) = create_signal("Initializing Engine...".to_string());
    let (engine_active, set_engine_active) = create_signal(false);

    // Graph State
    let (graph_data, set_graph_data) =
        create_signal(vec![180, 160, 170, 150, 140, 130, 110, 120, 100]);
    let _graph_points = move || {
        graph_data
            .get()
            .iter()
            .enumerate()
            .map(|(i, &v)| format!("{},{}", i * 50, v))
            .collect::<Vec<_>>()
            .join(" ")
    };


    // Update Graph Data periodically (Unified UI)
    create_effect(move |_| {
        use std::time::Duration;
        set_interval(
            move || {
                let current_activity = (total_count.get() % 100) as u32;
                let val = 180 - (current_activity.min(150));
                set_graph_data.update(|v| {
                    v.push(val);
                    if v.len() > 10 {
                        v.remove(0);
                    }
                });
            },
            Duration::from_millis(2000),
        );
    });


    let (settings, set_settings) = create_signal(FirewallSettings {
        website_path: "website".to_string(),
        rules: vec![],
    });

    // Setup Event Listener
    create_effect(move |_| {
        let closure = Closure::wrap(Box::new(move |event: JsValue| {
            match serde_wasm_bindgen::from_value::<serde_json::Value>(event.clone()) {
                Ok(payload) => {
                    if let Some(payload_obj) = payload.get("payload") {
                        match serde_json::from_value::<LogEntry>(payload_obj.clone()) {
                            Ok(entry) => {
                                set_logs.update(|l: &mut Vec<LogEntry>| {
                                    l.push(entry.clone());
                                    if l.len() > 200 {
                                        l.remove(0);
                                    }
                                });

                                set_total_count.update(|n| *n += 1);

                                // Update engine status based on log messages
                                if entry.message.contains("Starting")
                                    || entry.message.contains("Loading")
                                {
                                    set_engine_status.set(entry.message.clone());
                                }
                                if entry.message.contains("ACTIVE")
                                    || entry.message.contains("Engine")
                                {
                                    set_engine_status.set(entry.message.clone());
                                    if entry.message.contains("ACTIVE") {
                                        set_engine_active.set(true);
                                    }
                                }
                                if entry.message.contains("WebFilter Loaded") {
                                    set_engine_status.set("🟢 Monitoring Active".to_string());
                                    set_engine_active.set(true);
                                }
                                if entry.message.contains("WinDivert")
                                    && !entry.message.contains("Failed")
                                {
                                    set_engine_active.set(true);
                                }
                                if entry.message.contains("Failed")
                                    || entry.message.contains("Error")
                                {
                                    set_engine_status.set(format!("⚠️ {}", entry.message));
                                }

                                match entry.level {
                                    LogLevel::Warning | LogLevel::Error => {
                                        if entry.message.contains("Blocking")
                                            || entry.message.contains("BLOCKED")
                                        {
                                            set_blocked_count.update(|n| *n += 1);
                                        }
                                        if entry.message.contains("Malicious")
                                            || entry.message.contains("Threat")
                                        {
                                            set_threats_count.update(|n| *n += 1);
                                        }
                                    }
                                    LogLevel::Success => {
                                        set_allowed_count.update(|n| *n += 1);
                                    }
                                    _ => {}
                                }
                            }
                            Err(_) => {}
                        }
                    }
                }
                Err(_) => {}
            }
        }) as Box<dyn FnMut(JsValue)>);

        spawn_local(async move {
            let _ = listen("log", &closure).await;
            closure.forget();
        });

        // Ask Decision Listener - Now enabled for all windows
        let ask_closure = Closure::wrap(Box::new(move |event: JsValue| {
            if let Ok(payload) = serde_wasm_bindgen::from_value::<serde_json::Value>(event) {
                if let Some(payload_obj) = payload.get("payload") {
                    if let Ok(app) = serde_json::from_value::<PendingApp>(payload_obj.clone()) {
                        set_pending_app.set(Some(app));
                    }
                }
            }
        }) as Box<dyn FnMut(JsValue)>);

        spawn_local(async move {
            let _ = listen("ask_app_decision", &ask_closure).await;
            ask_closure.forget();
        });

        // Raw Packet Listener
        let raw_closure = Closure::wrap(Box::new(move |event: JsValue| {
            if let Ok(payload) = serde_wasm_bindgen::from_value::<serde_json::Value>(event) {
                if let Some(payload_obj) = payload.get("payload") {
                    if let Ok(pkt) = serde_json::from_value::<RawPacket>(payload_obj.clone()) {
                        set_raw_packets.update(|p| {
                            p.push(pkt);
                            if p.len() > 100 {
                                p.remove(0);
                            }
                        });
                    }
                }
            }
        }) as Box<dyn FnMut(JsValue)>);

        spawn_local(async move {
            let _ = listen("raw_packet", &raw_closure).await;
            raw_closure.forget();
        });
    });

    // Load Settings
    create_effect(move |_| {
        spawn_local(async move {
            let args = serde_wasm_bindgen::to_value(&()).unwrap();
            let res = invoke("get_settings", args).await;
            if let Ok(s) = serde_wasm_bindgen::from_value::<FirewallSettings>(res) {
                set_settings.set(s);
            }
        });
    });

    let save_settings_action = move || {
        spawn_local(async move {
            let s = settings.get();
            let args = serde_wasm_bindgen::to_value(&s).unwrap();
            let _ = invoke("save_settings", args).await;
            set_saved_status.set(true);
            set_timeout(
                move || set_saved_status.set(false),
                std::time::Duration::from_secs(2),
            );
        });
    };

    let toggle_rule = move |index: usize| {
        set_settings.update(|s| {
            if let Some(rule) = s.rules.get_mut(index) {
                rule.enabled = !rule.enabled;
            }
        });
        save_settings_action();
    };

    let update_path = move |path: String| {
        set_settings.update(|s| s.website_path = path);
    };

    let resolve_decision = move |name: String, decision: String| {
        spawn_local(async move {
            let args = ResolveArgs { name, decision };
            let args_js = serde_wasm_bindgen::to_value(&args).unwrap();
            let _ = invoke("resolve_app_decision", args_js).await;
            set_pending_app.set(None);
        });
    };

    // Mock Rule Generation Logic REMOVED per user request (YAML only)
    let add_rule_action = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
    };


    view! {
        <div class="app-container">
            <aside>
                <div class="logo-area">
                    <div class="logo-icon"></div>
                    <span class="logo-text">"HYDRADRAGON"</span>
                </div>
                <nav>
                    <a href="#" class={move || if current_view.get() == AppView::Dashboard { "nav-item active" } else { "nav-item" }}
                       on:click=move |ev| { ev.prevent_default(); set_current_view.set(AppView::Dashboard); }>
                       "Dashboard"
                    </a>
                    <a href="#" class={move || if current_view.get() == AppView::Rules { "nav-item active" } else { "nav-item" }}
                       on:click=move |ev| { ev.prevent_default(); set_current_view.set(AppView::Rules); }>
                       "Protection Rules"
                    </a>
                    <a href="#" class={move || if current_view.get() == AppView::Logs { "nav-item active" } else { "nav-item" }}
                       on:click=move |ev| { ev.prevent_default(); set_current_view.set(AppView::Logs); }>
                       "Network Activity"
                    </a>
                    <a href="#" class={move || if current_view.get() == AppView::PacketReader { "nav-item active" } else { "nav-item" }}
                       on:click=move |ev| { ev.prevent_default(); set_current_view.set(AppView::PacketReader); }>
                       "Packet Reader"
                    </a>
                    <a href="#" class={move || if current_view.get() == AppView::Exclusions { "nav-item active" } else { "nav-item" }}
                       on:click=move |ev| { ev.prevent_default(); set_current_view.set(AppView::Exclusions); }>
                       "Exclusions"
                    </a>
                    <a href="#" class={move || if current_view.get() == AppView::Settings { "nav-item active" } else { "nav-item" }}
                       on:click=move |ev| { ev.prevent_default(); set_current_view.set(AppView::Settings); }>
                       "Settings"
                    </a>
                </nav>
            </aside>

            <main>
                <header style="display: flex; justify-content: space-between; align-items: center">
                    <h2 style="margin: 0; font-weight: 800; font-size: 28px">
                        {move || match current_view.get() {
                            AppView::Dashboard => "Security Overview",
                            AppView::Rules => "Protection Rules",
                            AppView::Logs => "Network Activity",
                            AppView::PacketReader => "Packet Inspection",
                            AppView::Exclusions => "Exclusions Management",
                            AppView::Settings => "System Settings",
                        }}
                    </h2>
                    <span style={move || if engine_active.get() { "color: var(--accent-green); font-weight: 600; font-size: 14px" } else { "color: var(--accent-yellow); font-weight: 600; font-size: 14px" }}>
                        {move || if engine_active.get() { "● SYSTEM SECURE" } else { "○ INITIALIZING..." }}
                    </span>
                </header>

                {move || match current_view.get() {
                    AppView::Dashboard => view! {
                        <div class="dashboard-grid">
                            <div class="dash-col-main">
                                <div class="glass-card status-card">
                                    <div class="status-header">
                                        <div>
                                            <h3>"System Status"</h3>
                                            <span class="status-badge secure">"SECURE"</span>
                                        </div>
                                        <div class="pulse-indicator"></div>
                                    </div>
                                    <div class="traffic-graph-container">
                                        <svg width="100%" height="150" viewBox="0 0 600 150" class="traffic-svg">
                                            <defs>
                                                <linearGradient id="grad1" x1="0%" y1="0%" x2="0%" y2="100%">
                                                    <stop offset="0%" style="stop-color:var(--accent-blue);stop-opacity:0.5" />
                                                    <stop offset="100%" style="stop-color:var(--accent-blue);stop-opacity:0" />
                                                </linearGradient>
                                            </defs>
                                            <path d="M0,150 L0,100 Q50,50 100,80 T200,60 T300,100 T400,40 T500,80 T600,60 V150 Z"
                                                  fill="url(#grad1)" stroke="var(--accent-blue)" stroke-width="2" />
                                        </svg>
                                        <div class="graph-overlay">
                                            <div class="traffic-stat">
                                                <span class="label">"REAL-TIME ACTIVITY"</span>
                                                <span class="value" style="color:var(--accent-blue)">
                                                    {move || format!("{:.1} PPS", (total_count.get() % 50) as f32 + 5.0)}
                                                </span>
                                            </div>
                                            <div class="traffic-stat">
                                                <span class="label">"THREAT LEVEL"</span>
                                                <span class="value" style="color:var(--accent-yellow)">
                                                    {move || if threats_count.get() > 0 { "ELEVATED" } else { "LOW" }}
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                <div class="glass-card logs-section">
                                    <div class="section-header">
                                        <h3 style="margin: 0; font-size: 16px; font-weight: 700">"Real-time Intelligence"</h3>
                                        <span style={move || if engine_active.get() { "font-size: 12px; color: var(--accent-green)" } else { "font-size: 12px; color: var(--text-muted)" }}>
                                            {move || engine_status.get()}
                                        </span>
                                    </div>
                                    <div class="logs-viewport">
                                        <For
                                            each=move || logs.get()
                                            key=|log| log.id.clone()
                                            children=move |log| {
                                                let level_class = match log.level {
                                                    LogLevel::Info => "lvl-info",
                                                    LogLevel::Success => "lvl-success",
                                                    LogLevel::Warning => "lvl-warning",
                                                    LogLevel::Error => "lvl-error",
                                                    _ => "lvl-info",
                                                };
                                                view! {
                                                    <div class={format!("log-row {}", level_class)}>
                                                        <span class="log-time">"[" {log.timestamp % 100000} "]"</span>
                                                        <span class="log-msg">{log.message}</span>
                                                    </div>
                                                }
                                            }
                                        />
                                    </div>
                                </div>
                            </div>

                            <div class="dash-col-side">
                                 <div class="glass-card stat-item-compact">
                                    <h4>"Total Traffic"</h4>
                                    <div class="stat-value">{move || total_count.get()}</div>
                                </div>
                                <div class="glass-card stat-item-compact">
                                    <h4>"Blocked"</h4>
                                    <div class="stat-value" style="color: var(--accent-red)">{move || blocked_count.get()}</div>
                                </div>
                                <div class="glass-card stat-item-compact" style="border-left: 3px solid var(--accent-yellow)">
                                    <h4>"Threats"</h4>
                                    <div class="stat-value" style="color: var(--accent-yellow)">{move || threats_count.get()}</div>
                                </div>
                                 <div class="glass-card stat-item-compact">
                                    <h4>"Safe Requests"</h4>
                                    <div class="stat-value" style="color: var(--accent-green)">{move || allowed_count.get()}</div>
                                </div>
                            </div>
                        </div>
                    }.into_view(),

                    AppView::Rules => view! {
                        <div style="height: calc(100vh - 120px); display: flex; flex-direction: column; gap: 15px">
                            // Toolbar
                            <div style="display: flex; justify-content: flex-end; gap: 10px">
                                <button 
                                    class="btn-primary" 
                                    style={move || if show_editor.get() { "background: var(--bg-panel); border: 1px solid var(--glass-border)" } else { "" }}
                                    on:click=move |_| set_show_editor.set(!show_editor.get())
                                >
                                    {move || if show_editor.get() { "Cancel / View" } else { "Edit YAML" }}
                                </button>
                                {move || if show_editor.get() {
                                    view! {
                                        <div style="display: flex; gap: 10px; align-items: center">
                                            <span style="font-size: 11px; color: var(--text-muted); margin-right: 10px">{move || validation_result.get()}</span>
                                            <button class="btn-secondary" on:click=move |_| validate_rules_raw()>
                                                "Validate Syntax"
                                            </button>
                                            <button class="btn-primary" on:click=move |_| save_rules_raw()>
                                                "Save Changes"
                                            </button>
                                        </div>
                                    }.into_view()
                                } else {
                                    view! {}.into_view()
                                }}
                            </div>

                            {move || if show_editor.get() {
                                view! {
                                    <div class="glass-card" style="flex: 1; display: flex; flex-direction: column; padding: 0; overflow: hidden">
                                        <textarea
                                            style="flex: 1; width: 100%; height: 100%; background: transparent; border: none; padding: 20px; font-family: 'Fira Code', monospace; color: #e0e0e0; resize: none; outline: none; font-size: 13px; line-height: 1.5"
                                            prop:value=move || rules_raw_content.get()
                                            on:input=move |ev| set_rules_raw_content.set(event_target_value(&ev))
                                        ></textarea>
                                    </div>
                                }.into_view()
                            } else {
                                view! {
                                    <div class="dashboard-grid rules-wiki-mode" style="display: grid; grid-template-columns: 350px 1fr; gap: 20px; flex: 1; min-height: 0">
                                        // LEFT PANE: Active Rules List
                                        <div class="glass-card" style="display: flex; flex-direction: column; overflow: hidden; padding: 0">
                                            <div class="section-header" style="padding: 15px 20px; border-bottom: 1px solid rgba(255,255,255,0.05)">
                                                <div>
                                                    <h3 style="margin: 0; font-size: 14px">"Active Rules"</h3>
                                                    <span style="font-size: 11px; color: var(--text-muted)">"From rules.yaml"</span>
                                                </div>
                                                <div style="font-size: 11px; background: rgba(255,255,255,0.1); padding: 2px 6px; border-radius: 4px; color: var(--accent-green); font-weight: 700">
                                                    {move || sdk_rules.get().len()}
                                                </div>
                                            </div>
                                            <div style="flex: 1; overflow-y: auto; padding: 10px">
                                                <For
                                                    each=move || sdk_rules.get().into_iter().enumerate()
                                                    key=|(_, rule)| rule.name.clone()
                                                    children=move |(idx, rule)| {
                                                        view! {
                                                            <div class="rule-item-compact" style="padding: 10px; margin-bottom: 8px; background: rgba(255,255,255,0.02); border-radius: 6px; border: 1px solid rgba(255,255,255,0.03)">
                                                                 <div style="font-weight: 600; font-size: 13px; margin-bottom: 2px">{rule.name}</div>
                                                                 <div style="font-size: 11px; color: var(--text-muted); display: flex; justify-content: space-between">
                                                                     <span style="text-transform: uppercase; font-size: 10px; padding: 2px 6px; background: rgba(255,255,255,0.05); border-radius: 4px">{format!("{:?}", rule.action)}</span>
                                                                     <span style={if rule.enabled { "color: var(--accent-green)" } else { "color: var(--text-muted)" }}>{if rule.enabled { "Active" } else { "Disabled" }}</span>
                                                                 </div>
                                                            </div>
                                                        }
                                                    }
                                                />
                                            </div>
                                        </div>

                                        // RIGHT PANE: Wiki
                                        <RulesWiki />
                                    </div>
                                }.into_view()
                            }}
                        </div>
                    }.into_view(),

                    AppView::Logs => view! {
                         <div class="dashboard-grid" style="flex-direction: column">
                            // Stats Banner
                            <div style="display: flex; gap: 15px; margin-bottom: 10px">
                                <div style="flex: 1; background: rgba(62,148,255,0.1); padding: 15px 20px; border-radius: 10px; border-left: 3px solid var(--accent-blue)">
                                    <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px">"Total Events"</div>
                                    <div style="font-size: 24px; font-weight: 700; color: var(--accent-blue); margin-top: 5px">{move || total_count.get()}</div>
                                </div>
                                <div style="flex: 1; background: rgba(0,255,136,0.1); padding: 15px 20px; border-radius: 10px; border-left: 3px solid var(--accent-green)">
                                    <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px">"Allowed"</div>
                                    <div style="font-size: 24px; font-weight: 700; color: var(--accent-green); margin-top: 5px">{move || allowed_count.get()}</div>
                                </div>
                                <div style="flex: 1; background: rgba(255,62,62,0.1); padding: 15px 20px; border-radius: 10px; border-left: 3px solid var(--accent-red)">
                                    <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px">"Blocked"</div>
                                    <div style="font-size: 24px; font-weight: 700; color: var(--accent-red); margin-top: 5px">{move || blocked_count.get()}</div>
                                </div>
                                <div style="flex: 1; background: rgba(255,204,0,0.1); padding: 15px 20px; border-radius: 10px; border-left: 3px solid var(--accent-yellow)">
                                    <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px">"Threats"</div>
                                    <div style="font-size: 24px; font-weight: 700; color: var(--accent-yellow); margin-top: 5px">{move || threats_count.get()}</div>
                                </div>
                            </div>

                            // Logs Card
                            <div class="glass-card logs-section" style="width: 100%; flex: 1">
                                <div class="section-header" style="margin-bottom: 15px">
                                    <div>
                                        <h3 style="margin: 0; font-size: 16px; font-weight: 700">"📜 Full Network Event Log"</h3>
                                        <span style="font-size: 12px; color: var(--text-muted)">{move || format!("Showing {} events", logs.get().len())}</span>
                                    </div>
                                    <button class="btn-primary" style="padding: 6px 15px; font-size: 12px; background: rgba(255,255,255,0.1); box-shadow: none"
                                            on:click=move |_| set_logs.set(vec![])>
                                        "🗑️ CLEAR"
                                    </button>
                                </div>
                                <div class="logs-viewport" style="height: calc(100vh - 380px); min-height: 400px">
                                    <For
                                        each=move || logs.get()
                                        key=|log| log.id.clone()
                                        children=move |log| {
                                            let level_class = match log.level {
                                                LogLevel::Info => "lvl-info",
                                                LogLevel::Success => "lvl-success",
                                                LogLevel::Warning => "lvl-warning",
                                                LogLevel::Error => "lvl-error",
                                                _ => "lvl-info",
                                            };
                                            let level_icon = match log.level {
                                                LogLevel::Info => "ℹ️",
                                                LogLevel::Success => "✅",
                                                LogLevel::Warning => "⚠️",
                                                LogLevel::Error => "❌",
                                                _ => "📝",
                                            };
                                            view! {
                                                <div class={format!("log-row {}", level_class)} style="align-items: center">
                                                    <span style="font-size: 14px; margin-right: 8px">{level_icon}</span>
                                                    <span class="log-time">"[" {log.timestamp % 100000} "]"</span>
                                                    <span class="log-msg">{log.message}</span>
                                                </div>
                                            }
                                        }
                                    />
                                    // Empty State
                                    {move || {
                                        if logs.get().is_empty() {
                                            view! {
                                                <div style="text-align: center; padding: 80px 20px; color: var(--text-muted)">
                                                    <div style="font-size: 48px; margin-bottom: 15px; opacity: 0.3">"📋"</div>
                                                    <div style="font-size: 16px; font-weight: 600">"No Events Yet"</div>
                                                    <div style="font-size: 13px; margin-top: 5px">"Network activity will appear here in real-time"</div>
                                                </div>
                                            }.into_view()
                                        } else {
                                            view! { <div></div> }.into_view()
                                        }
                                    }}
                                </div>
                            </div>
                        </div>
                    }.into_view(),

                    AppView::PacketReader => view! {
                        <div class="dashboard-grid" style="flex-direction: column; height: calc(100vh - 120px)">
                            <div class="glass-card" style="width: 100%; flex: 1; display: flex; flex-direction: column; overflow: hidden; padding: 0">
                                <div class="section-header" style="padding: 15px 20px; border-bottom: 1px solid rgba(255,255,255,0.05)">
                                    <div>
                                        <h3 style="margin: 0">"🔍 Real-time Packet Inspection"</h3>
                                        <span style="font-size: 11px; color: var(--text-muted)">"Wireshark-mode enabled; live capturing from WinDivert"</span>
                                    </div>
                                    <div style="display: flex; gap: 10px">
                                        <button class="btn-primary" style="padding: 6px 15px; font-size: 11px; background: rgba(255,62,62,0.1); color: var(--accent-red); border-color: var(--accent-red)"
                                                on:click=move |_| set_raw_packets.set(vec![])>
                                            "STOP & CLEAR"
                                        </button>
                                    </div>
                                </div>

                                <div style="display: flex; flex: 1; overflow: hidden">
                                    // Packet List
                                    <div style="flex: 1; border-right: 1px solid rgba(255,255,255,0.05); overflow-y: auto">
                                        <table style="width: 100%; border-collapse: collapse; font-family: 'Fira Code', monospace; font-size: 12px">
                                            <thead style="position: sticky; top: 0; background: #1a1a1a; z-index: 10">
                                                <tr style="text-align: left; color: var(--text-muted); border-bottom: 1px solid #333">
                                                    <th style="padding: 10px">"Time"</th>
                                                    <th style="padding: 10px">"Application"</th>
                                                    <th style="padding: 10px">"Action"</th>
                                                    <th style="padding: 10px">"Rule"</th>
                                                    <th style="padding: 10px">"Protocol"</th>
                                                    <th style="padding: 10px">"Source"</th>
                                                    <th style="padding: 10px">"Destination"</th>
                                                    <th style="padding: 10px">"Length"</th>
                                                    <th style="padding: 10px">"Info"</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <For
                                                    each=move || raw_packets.get().into_iter().rev()
                                                    key=|pkt| pkt.id.clone()
                                                    children=move |pkt| {
                                                        let p = pkt.clone();
                                                        let sel_id = p.id.clone();
                                                        let is_selected = move || selected_packet.get().map(|s| s.id == sel_id).unwrap_or(false);
                                                        let proto = pkt.protocol;

                                                        view! {
                                                            <tr style=move || format!("border-bottom: 1px solid rgba(255,255,255,0.02); cursor: pointer; {}", if is_selected() { "background: rgba(62,148,255,0.15)" } else { "" })
                                                                on:click=move |_| set_selected_packet.set(Some(p.clone()))>
                                                                <td style="padding: 8px 10px">{pkt.timestamp % 100000}</td>
                                                                <td style="padding: 8px 10px">
                                                                    <div style="font-weight: 500; color: var(--text-bright)">{pkt.process_name.clone()}</div>
                                                                    <div style="font-size: 10px; color: var(--text-muted)">{format!("PID: {}", pkt.process_id)}</div>
                                                                </td>
                                                                <td style="padding: 8px 10px">
                                                                    {
                                                                        let action_style = pkt.action.clone();
                                                                        view! {
                                                                            <span style=move || format!("color: {}", if action_style == "Allow" { "var(--success)" } else { "var(--danger)" })>
                                                                                {pkt.action.clone()}
                                                                            </span>
                                                                        }
                                                                    }
                                                                </td>
                                                                <td style="padding: 8px 10px; font-size: 11px; color: var(--text-muted)">
                                                                    {if pkt.rule.is_empty() { "-".to_string() } else { pkt.rule.clone() }}
                                                                </td>
                                                                <td style="padding: 8px 10px">
                                                                    <span style=move || format!("color: {}", match proto { Protocol::TCP => "var(--accent-blue)", Protocol::UDP => "var(--accent-green)", _ => "var(--accent-yellow)" })>
                                                                        {match proto { Protocol::TCP => "TCP", Protocol::UDP => "UDP", Protocol::ICMP => "ICMP", _ => "RAW" }}
                                                                    </span>
                                                                </td>
                                                                <td style="padding: 8px 10px">{format!("{}:{}", pkt.src_ip, pkt.src_port)}</td>
                                                                <td style="padding: 8px 10px">{format!("{}:{}", pkt.dst_ip, pkt.dst_port)}</td>
                                                                <td style="padding: 8px 10px">{pkt.length}</td>
                                                                <td style="padding: 8px 10px; color: var(--text-muted); font-size: 11px">{pkt.payload_preview.clone()}</td>
                                                            </tr>
                                                        }
                                                    }
                                                />
                                            </tbody>
                                        </table>
                                    </div>

                                    // Detail View
                                    <div style="width: 400px; padding: 15px; background: rgba(0,0,0,0.1); overflow-y: auto; font-family: 'Fira Code', monospace">
                                        {move || match selected_packet.get() {
                                            Some(pkt) => view! {
                                                <div style="font-size: 12px">
                                                    <h4 style="margin: 0 0 15px 0; color: var(--accent-blue)">"Packet Details"</h4>
                                                    <div style="display: flex; flex-direction: column; gap: 8px">
                                                        <div style="color: #6a9955">"// Frame Metadata"</div>
                                                        <div><span style="color: var(--text-muted)">"Timestamp: "</span> {pkt.timestamp}</div>
                                                        <div><span style="color: var(--text-muted)">"Length:    "</span> {pkt.length} " bytes"</div>

                                                        <div style="margin-top: 10px; color: #6a9955">"// Process Trace"</div>
                                                        <div><span style="color: var(--text-muted)">"Process:   "</span> <span style="color: var(--accent-blue)">{pkt.process_name.clone()}</span></div>
                                                        <div><span style="color: var(--text-muted)">"PID:       "</span> {pkt.process_id}</div>
                                                        <div style="font-size: 11px; word-break: break-all"><span style="color: var(--text-muted)">"Path:      "</span> {pkt.process_path.clone()}</div>

                                                        <div style="margin-top: 10px; color: #6a9955">"// Network Layer"</div>
                                                        <div><span style="color: var(--text-muted)">"Source:    "</span> {pkt.src_ip.clone()}</div>
                                                        <div><span style="color: var(--text-muted)">"Dest:      "</span> {pkt.dst_ip.clone()}</div>

                                                        <div style="margin-top: 10px; color: #6a9955">"// Transport Layer"</div>
                                                        <div><span style="color: var(--text-muted)">"Protocol:  "</span> {match pkt.protocol { Protocol::TCP => "TCP", Protocol::UDP => "UDP", _ => "OTHER" }}</div>
                                                        <div><span style="color: var(--text-muted)">"Src Port:  "</span> {pkt.src_port}</div>
                                                        <div><span style="color: var(--text-muted)">"Dst Port:  "</span> {pkt.dst_port}</div>

                                                        <div style="margin-top: 20px; border-top: 1px solid #333; padding-top: 15px">
                                                            <div style="color: var(--accent-yellow); margin-bottom: 10px">"Hex Dump"</div>
                                                            <div style="background: rgba(0,0,0,0.3); padding: 10px; border-radius: 4px; line-height: 1.4; word-break: break-all; font-size: 11px; color: #aaa">
                                                                {pkt.payload_hex.clone()}
                                                            </div>
                                                        </div>
                                                    </div>
                                                </div>
                                            }.into_view(),
                                            None => view! {
                                                <div style="height: 100%; display: flex; align-items: center; justify-content: center; color: var(--text-muted); text-align: center; font-size: 13px">
                                                    "Select a packet to view its raw data and headers"
                                                </div>
                                            }.into_view()
                                        }}
                                    </div>
                                </div>
                            </div>
                        </div>
                    }.into_view(),

                    AppView::Exclusions => view! {
                        <div class="dashboard-grid" style="flex-direction: column; height: calc(100vh - 120px)">
                            <div class="glass-card" style="width: 100%; flex: 1; display: flex; flex-direction: column; overflow: hidden">
                                <div class="section-header">
                                    <h3 style="margin: 0">"✅ Allowed Applications"</h3>
                                    <span style="font-size: 12px; color: var(--text-muted)">"manage applications with custom network permissions"</span>
                                </div>
                                <div style="margin-top: 20px; overflow-y: auto; flex: 1">
                                    <div class="exclusions-list">
                                        {move || app_decisions.get().into_iter().map(|(name, decision): (String, AppDecision)| {
                                            let n = name.clone();
                                            let n2 = name.clone();
                                            view! {
                                                <div class="exclusion-item">
                                                    <div style="display: flex; flex-direction: column; gap: 4px">
                                                        <span style="font-weight: 700; color: var(--accent-yellow); font-family: 'Fira Code', monospace">{n}</span>
                                                        <span style="font-size: 11px; color: var(--text-muted)">{format!("{:?}", decision)}</span>
                                                    </div>
                                                    <button class="btn-primary" 
                                                            style="background: rgba(255,62,62,0.1); color: var(--accent-red); border-color: var(--accent-red); padding: 5px 15px; font-size: 11px"
                                                            on:click=move |_| remove_decision_action(n2.clone())>
                                                        "REMOVE"
                                                    </button>
                                                </div>
                                            }
                                        }).collect_view()}
                                        {move || if app_decisions.get().is_empty() {
                                            view! { <div style="text-align: center; color: var(--text-muted); padding: 40px">"No exclusions found."</div> }.into_view()
                                        } else {
                                            view! { }.into_view()
                                        }}
                                    </div>
                                </div>
                            </div>
                        </div>
                    }.into_view(),

                    AppView::Settings => view! {
                         <div class="dashboard-grid" style="flex-direction: column">
                            // General Settings Card
                            <div class="glass-card" style="width: 100%">
                                <div class="section-header">
                                    <h3 style="margin: 0">"⚙️ General Settings"</h3>
                                    <span style="font-size: 12px; color: var(--text-muted)">"configure core firewall behavior"</span>
                                </div>
                                <div class="input-group" style="margin-top: 20px">
                                    <label>"THREAT INTELLIGENCE DATABASE PATH"</label>
                                    <input type="text"
                                           placeholder="e.g., website or C:\\path\\to\\intel"
                                           prop:value=move || settings.get().website_path
                                           on:input=move |ev| update_path(event_target_value(&ev))
                                    />
                                </div>
                            </div>

                            // Save Button
                            <div style="display: flex; justify-content: flex-end; gap: 15px">
                                <button class="btn-primary"
                                        style={move || if saved_status.get() { "padding: 12px 30px; background: var(--accent-green)" } else { "padding: 12px 30px" }}
                                        on:click=move |_| save_settings_action()>
                                    {move || if saved_status.get() { "✓ SETTINGS SAVED!" } else { "💾 SAVE ALL SETTINGS" }}
                                </button>
                            </div>
                        </div>
                    }.into_view(),
                }}
            </main>

            <div class={move || if show_rule_modal.get() { "modal-overlay open" } else { "modal-overlay" }}
                 style={move || if !show_rule_modal.get() { "pointer-events: none" } else { "pointer-events: auto" }}>
                <div class="glass-modal" style="width: 850px; max-width: 95vw; background: #1e1e1e; border: 1px solid #333; box-shadow: 0 10px 40px rgba(0,0,0,0.6); padding: 0; overflow: hidden; display: flex; flex-direction: column; border-radius: 8px">

                    <div style="background: #252526; padding: 10px 15px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #333">
                         <div style="display: flex; gap: 10px; align-items: center">
                            <div style="display: flex; gap: 6px">
                                <span style="height: 12px; width: 12px; background: #ff5f56; border-radius: 50%"></span>
                                <span style="height: 12px; width: 12px; background: #ffbd2e; border-radius: 50%"></span>
                                <span style="height: 12px; width: 12px; background: #27c93f; border-radius: 50%"></span>
                            </div>
                            <span style="color: #888; font-family: 'Segoe UI', sans-serif; font-size: 12px; margin-left: 15px; border-left: 1px solid #444; padding-left: 15px">"HydraDragon Advanced SDK v0.1.0"</span>
                         </div>
                         <button style="background:none; border:none; color: #888; cursor: pointer; font-size: 18px" on:click=move |_| set_show_rule_modal.set(false)>"✕"</button>
                    </div>

                    <div style="background: #2d2d2d; display: flex; border-bottom: 1px solid #111">
                        <div style=move || format!("padding: 8px 20px; font-size: 11px; display: flex; align-items: center; gap: 8px; cursor: pointer; {}",
                             if active_tab.get() == "rule" { "background: #1e1e1e; border-top: 1px solid #007acc; color: #fff;" } else { "color: #888;" })
                             on:click=move |_| set_active_tab.set("rule".to_string())>
                            <span style="color: #ce9178">"RS"</span>
                            "rule_definition.rs"
                        </div>
                        <div style=move || format!("padding: 8px 20px; font-size: 11px; display: flex; align-items: center; gap: 8px; cursor: pointer; {}",
                             if active_tab.get() == "engine" { "background: #1e1e1e; border-top: 1px solid #007acc; color: #fff;" } else { "color: #888;" })
                             on:click=move |_| set_active_tab.set("engine".to_string())>
                            <span style="color: #ce9178">"RS"</span>
                            "engine_core.rs"
                        </div>
                    </div>

                    <div style="display: flex; flex: 1; min-height: 450px; background: #1e1e1e">
                        <div style="width: 45px; background: #1e1e1e; border-right: 1px solid #333; color: #858585; font-family: 'Consolas', 'Courier New', monospace; font-size: 13px; padding-top: 15px; text-align: right; padding-right: 12px; display: flex; flex-direction: column; gap: 6px; user-select: none; line-height: 1.5">
                            {(1..=18).map(|n| view! { <span>{n}</span> }).collect_view()}
                        </div>

                        <div style="flex: 1; padding: 15px; font-family: 'Consolas', 'Courier New', monospace; font-size: 13px; color: #d4d4d4; overflow-y: auto; line-height: 1.5">
                            <Show when=move || active_tab.get() == "rule" fallback=move || view! {
                                <div style="color: #6a9955; font-style: italic">
                                    "// HydraDragon Engine Core - v0.1.0" <br/>
                                    "// Internal Packet Processing Pipeline" <br/><br/>
                                    <span style="color: #c586c0">"pub fn"</span><span style="color: #dcdcaa">" process_packet"</span>"(data: &[u8]) {" <br/>
                                    <span style="margin-left: 20px">"let decision = rule_engine.evaluate(data);"</span> <br/>
                                    <span style="margin-left: 20px">"let telemetry = Telemetry::new(decision);"</span> <br/>
                                    <span style="margin-left: 20px; color: #569cd6">"if"</span>" decision.is_blocked() {" <br/>
                                    <span style="margin-left: 40px">"UI::emit(\"blocked_connection\", telemetry);"</span> <br/>
                                    <span style="margin-left: 20px">"}"</span> <br/>
                                    "}"
                                </div>
                            }>
                            <form on:submit=add_rule_action>
                                <div style="display: flex; flex-direction: column; gap: 4px">
                                    <div><span style="color: #c586c0">"use"</span> " hydradragon_sdk::prelude::*;"</div>
                                    <div style="margin-bottom: 15px"></div>

                                    <div style="color: #569cd6">"#[rule_entry]"</div>
                                    <div style="color: #569cd6">"pub fn"<span style="color: #dcdcaa">" define_rule"</span>"() -> "<span style="color: #4ec9b0">"Rule"</span>" {"</div>

                                    <div style="margin-left: 20px">
                                        <span style="color: #4ec9b0">"RuleBuilder"</span>"::"<span style="color: #dcdcaa">"new"</span>"()"
                                    </div>

                                    <div style="margin-left: 40px; display: flex; align-items: center; gap: 8px">
                                        <span>"."</span><span style="color: #dcdcaa">"name"</span><span>"("</span>
                                        <input type="text" required placeholder="\"Enter rule name...\""
                                               style="background: rgba(206, 145, 120, 0.05); border: none; border-bottom: 1px solid #444; color: #ce9178; font-family: inherit; width: 280px; outline: none; padding: 2px 4px"
                                               on:input=move |ev| set_new_rule_name.set(event_target_value(&ev))
                                               prop:value=new_rule_name
                                        />
                                        <span>")"</span>
                                    </div>

                                    <div style="margin-left: 40px; display: flex; align-items: center; gap: 8px">
                                        <span>"."</span><span style="color: #dcdcaa">"description"</span><span>"("</span>
                                        <input type="text" required placeholder="\"Describe this rule...\""
                                               style="background: rgba(206, 145, 120, 0.05); border: none; border-bottom: 1px solid #444; color: #ce9178; font-family: inherit; width: 350px; outline: none; padding: 2px 4px"
                                               on:input=move |ev| set_new_rule_desc.set(event_target_value(&ev))
                                               prop:value=new_rule_desc
                                        />
                                        <span>")"</span>
                                    </div>

                                    <div style="margin-left: 40px; display: flex; align-items: center; gap: 8px">
                                        <span>"."</span><span style="color: #dcdcaa">"protocol"</span><span>"("</span>
                                        <select style="background: #252526; border: 1px solid #444; color: #4ec9b0; font-family: inherit; border-radius: 2px; padding: 1px 4px; outline: none"
                                                on:change=move |ev| set_new_rule_protocol.set(event_target_value(&ev))>
                                            <option value="Any">"Protocol::Any"</option>
                                            <option value="TCP">"Protocol::TCP"</option>
                                            <option value="UDP">"Protocol::UDP"</option>
                                            <option value="ICMP">"Protocol::ICMP"</option>
                                        </select>
                                        <span>")"</span>
                                    </div>

                                    <div style="margin-left: 40px; display: flex; align-items: center; gap: 8px">
                                        <span>"."</span><span style="color: #dcdcaa">"action"</span><span>"("</span>
                                        <select style="background: #252526; border: 1px solid #444; color: #b5cea8; font-family: inherit; border-radius: 2px; padding: 1px 4px; outline: none"
                                                on:change=move |ev| set_new_rule_block.set(event_target_value(&ev) == "Block")>
                                            <option value="Block">"Action::Block"</option>
                                            <option value="Allow">"Action::Allow"</option>
                                        </select>
                                        <span>")"</span>
                                    </div>

                                    <div style="margin-left: 40px; display: flex; align-items: center; gap: 8px">
                                        <span>"."</span><span style="color: #dcdcaa">"target_ips"</span><span>"( "</span><span style="color: #569cd6">"vec!"</span>"["
                                        <input type="text" placeholder="\"192.168.1.*\", \"*\""
                                               style="background: rgba(156, 220, 254, 0.05); border: none; border-bottom: 1px solid #444; color: #9cdcfe; font-family: inherit; width: 300px; outline: none; padding: 2px 4px"
                                               on:input=move |ev| {
                                                    set_new_rule_ips.set(event_target_value(&ev));
                                                    set_validation_error.set(None);
                                               }
                                               prop:value=new_rule_ips
                                        />
                                        "] )"
                                    </div>

                                    <div style="margin-left: 40px; display: flex; align-items: center; gap: 8px">
                                        <span>"."</span><span style="color: #dcdcaa">"target_ports"</span><span>"( "</span><span style="color: #569cd6">"vec!"</span>"["
                                        <input type="text" placeholder="80, 443"
                                               style="background: rgba(181, 206, 168, 0.05); border: none; border-bottom: 1px solid #444; color: #b5cea8; font-family: inherit; width: 180px; outline: none; padding: 2px 4px"
                                               on:input=move |ev| {
                                                   set_new_rule_ports.set(event_target_value(&ev));
                                                   set_validation_error.set(None);
                                               }
                                               prop:value=new_rule_ports
                                        />
                                        "] )"
                                    </div>

                                    <div style="margin-left: 20px">
                                        <span>"."</span><span style="color: #dcdcaa">"build"</span><span>"()"</span>
                                    </div>
                                    <div>"}"</div>
                                </div>

                                <div style="margin-top: 30px; display: flex; gap: 15px">
                                     <button type="submit"
                                             class={move || if is_compiling.get() { "btn-primary disabled" } else { "btn-primary" }}
                                             disabled={move || is_compiling.get()}
                                             style="background: #007acc; border: none; color: white; padding: 8px 25px; font-family: inherit; cursor: pointer; border-radius: 2px; font-weight: bold; font-size: 12px; display: flex; align-items: center; gap: 10px; transition: background 0.2s">
                                         {move || if is_compiling.get() {
                                             view! { <span style="display:inline-block" class="spin">"🌀"</span> }
                                         } else {
                                             view! { <span>"🚀"</span> }
                                         }}
                                         {move || if is_compiling.get() { "COMPILING..." } else { "BUILD & DEPLOY" }}
                                     </button>
                                </div>
                            </form>
                            </Show>
                        </div>
                    </div>

                    <div style="height: 140px; background: #1e1e1e; border-top: 4px solid #333; display: flex; flex-direction: column">
                        <div style="background: #252526; padding: 4px 15px; font-size: 10px; color: #aaa; text-transform: uppercase; letter-spacing: 1px; display: flex; gap: 20px; border-bottom: 1px solid #333">
                            <span style="color: #fff; border-bottom: 1px solid #007acc; padding-bottom: 2px">"Output"</span>
                            "Debug Console"
                            "Problems"
                            "Terminal"
                        </div>
                        <div style="flex: 1; padding: 10px; font-family: 'Consolas', 'Courier New', monospace; font-size: 12px; overflow-y: auto; background: #0c0c0c">
                             {move || console_output.get().into_iter().map(|line| {
                                 let l = line.clone();
                                 let first = l.get(0..1).unwrap_or("").to_string();
                                 let rest = l.get(1..).unwrap_or("").to_string();
                                 view! {
                                     <div style="color: #d4d4d4; margin-bottom: 3px; display: flex; gap: 8px">
                                        <span style="color: #4ec9b0; opacity: 0.8">{first}</span>
                                        <span>{rest}</span>
                                     </div>
                                 }
                             }).collect_view()}
                             {move || validation_error.get().map(|err| view! {
                                 <div style="color: #f44747; margin-top: 8px; font-weight: bold; background: rgba(244, 71, 71, 0.1); padding: 5px; border-left: 3px solid #f44747">
                                    "ERROR [SDK-001]: " {err}
                                 </div>
                             })}
                        </div>
                    </div>

                    <div style="background: #007acc; color: #fff; padding: 2px 15px; display: flex; justify-content: space-between; align-items: center; font-size: 11px">
                         <div style="display: flex; gap: 15px; align-items: center">
                            <span style="display: flex; gap: 4px; align-items: center">"⊗ 0" "△ 0"</span>
                            "ready"
                         </div>
                         <div style="display: flex; gap: 15px; align-items: center">
                            "Spaces: 4"
                            "UTF-8"
                            "Rust"
                         </div>
                    </div>
                </div>
            </div>

            {move || pending_app.get().map(|app| {
                let name_for_block = app.name.clone();
                let name_for_allow = app.name.clone();
                let display_reason = app.reason.clone().unwrap_or_else(|| "Unknown application activity detected.".to_string());
                
                view! {
                    <div class="hydra-toast">
                         <div class="hydra-toast-header">
                             <div class="hydra-toast-brand">
                                 <div class="dragon-icon"></div>
                                 "HYDRADRAGON FIREWALL"
                             </div>
                             <div style="cursor: pointer; opacity: 0.6" on:click=move |_| set_pending_app.set(None)>"✕"</div>
                         </div>
                         
                         <div class="hydra-toast-content">
                             <div class="hydra-toast-title">
                                 "Network Prompt"
                                 <span>"Action Required"</span>
                             </div>
                             <p class="hydra-toast-desc">
                                 {display_reason}
                             </p>
                             
                             <div class="hydra-toast-details">
                                 <div class="hydra-toast-detail-row">
                                     <span class="hydra-toast-label">"Process:"</span>
                                     <span class="hydra-toast-value">{app.name.clone()}</span>
                                 </div>
                                 <div class="hydra-toast-detail-row">
                                     <span class="hydra-toast-label">"Remote:"</span>
                                     <span class="hydra-toast-value">{format!("{}:{}", app.dst_ip, app.dst_port)}</span>
                                 </div>
                                 <div class="hydra-toast-detail-row">
                                     <span class="hydra-toast-label">"File:"</span>
                                     <span class="hydra-toast-value" style="font-size: 10px">{app.path.clone()}</span>
                                 </div>
                             </div>

                             <div class="hydra-toast-footer">
                                 <button class="btn-hydra-alt" on:click=move |_| {
                                     set_current_view.set(AppView::Exclusions);
                                     set_pending_app.set(None);
                                 }>
                                     "Exclusions"
                                 </button>
                                 <button class="btn-hydra-alt" on:click=move |_| resolve_decision(name_for_allow.clone(), "allow".to_string())>
                                     "Allow"
                                 </button>
                                 <button class="btn-hydra-main" on:click=move |_| resolve_decision(name_for_block.clone(), "block".to_string())>
                                     "Block"
                                 </button>
                             </div>
                         </div>
                    </div>
                }
            })}

        </div>
    }
}

pub fn main() {
    console_error_panic_hook::set_once();
    mount_to_body(|| view! { <App/> })
}
