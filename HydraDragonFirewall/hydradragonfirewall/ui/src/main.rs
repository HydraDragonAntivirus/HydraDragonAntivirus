use js_sys::Reflect;
use leptos::*;
// Assuming imports work.
use serde::{Deserialize, Serialize};
use std::time::Duration;
use wasm_bindgen::prelude::*;

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

    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "window"])]
    async fn closeWindow() -> JsValue;
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
    pub protocol: Protocol,
    pub hostname: Option<String>,
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
    pub hostname: Option<String>,
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
    AllowOnce,
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
    let (_threats_count, set_threats_count) = create_signal(0);
    let (_allowed_count, set_allowed_count) = create_signal(0);
    let (total_count, set_total_count) = create_signal(0);

    // Navigation State
    let (current_view, set_current_view) = create_signal(AppView::Dashboard);
    let (raw_packets, set_raw_packets) = create_signal(Vec::<RawPacket>::new());
    let (selected_packet, set_selected_packet) = create_signal(Option::<RawPacket>::None);
    let (_sdk_rules, set_sdk_rules) = create_signal(Vec::<SdkRuleView>::new());
    
    let (pending_app, set_pending_app) = create_signal(Option::<PendingApp>::None);
    let (app_decisions, set_app_decisions) = create_signal(std::collections::HashMap::<String, AppDecision>::new());

    // Window Mode Detection
    let (is_alert, set_is_alert) = create_signal({
        if let Some(win) = web_sys::window() {
            if let Ok(search) = win.location().search() {
                search.contains("mode=alert")
            } else {
                false
            }
        } else {
            false
        }
    });
    
    spawn_local(async move {
        // If in alert mode, try to fetch the active alert immediately
        if let Some(win) = web_sys::window() {
            if let Ok(search) = win.location().search() {
                 if search.contains("mode=alert") {
                     let res = invoke("get_active_alert", JsValue::NULL).await;
                     if let Ok(app_opt) = serde_wasm_bindgen::from_value::<Option<PendingApp>>(res) {
                         if let Some(app) = app_opt {
                             set_pending_app.set(Some(app));
                         }
                     }
                 }
            }
        };
        
        // Fallback or secondary confirmation via Label
        let win = getCurrentWindow().await;
        if !win.is_undefined() && !win.is_null() {
             if let Ok(label) = Reflect::get(&win, &"label".into()) {
                 if let Some(l) = label.as_string() {
                     if l == "firewall-alert" {
                         set_is_alert.set(true);
                     }
                 }
             }
        }
    });

    let _resolve_decision = move |name: String, decision: String| {
        let name_lower = name.clone();
        spawn_local(async move {
            let args = serde_wasm_bindgen::to_value(&ResolveArgs {
                name: name_lower,
                decision,
            })
            .unwrap();
            let _ = invoke("resolve_app_decision", args).await;
            
            // If in alert window, close it after decision
            let _ = invoke("close_window", JsValue::NULL).await;
            
            set_pending_app.set(None);
        });
    };
    
    let (show_editor, set_show_editor) = create_signal(false);
    let (rules_raw_content, set_rules_raw_content) = create_signal(String::new());
    let (_validation_result, set_validation_result) = create_signal(String::from("Ready to validate."));

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
             if let Ok(s) = serde_wasm_bindgen::from_value::<String>(val) {
                 set_rules_raw_content.set(s);
             }
        });
    };

    let fetch_app_decisions = move || {
        spawn_local(async move {
            let res = invoke("get_app_decisions", JsValue::NULL).await;
            if let Ok(decisions) = serde_wasm_bindgen::from_value::<std::collections::HashMap<String, AppDecision>>(res) {
                set_app_decisions.set(decisions);
            }
        });
    };

    let save_rules_raw = move || {
        let content = rules_raw_content.get();
        spawn_local(async move {
            let args = js_sys::Object::new();
            js_sys::Reflect::set(&args, &"content".into(), &content.into()).unwrap();
            let _ = invoke("save_rules_content", args.into()).await;
            fetch_sdk_rules();
            set_show_editor.set(false);
        });
    };

    let validate_rules_raw = move || {
        let content = rules_raw_content.get();
        set_validation_result.set("Validating...".to_string());
        spawn_local(async move {
            let args = js_sys::Object::new();
            js_sys::Reflect::set(&args, &"content".into(), &content.into()).unwrap();
            let res = invoke("validate_rules_content", args.into()).await;
            if let Some(msg) = res.as_string() {
                set_validation_result.set(msg);
            }
        });
    };

    let remove_decision_action = move |name: String| {
        spawn_local(async move {
            let args = serde_wasm_bindgen::to_value(&serde_json::json!({ "name": name })).unwrap();
            let _ = invoke("remove_app_decision", args).await;
            fetch_app_decisions();
        });
    };

    let clear_all_decisions = move || {
        spawn_local(async move {
            let _ = invoke("clear_app_decisions", JsValue::NULL).await;
            fetch_app_decisions();
        });
    };

    let (_show_rule_modal, _set_show_rule_modal) = create_signal(false);
    let (_new_rule_name, _set_new_rule_name) = create_signal(String::new());
    let (_new_rule_desc, _set_new_rule_desc) = create_signal(String::new());
    let (_new_rule_ips, _set_new_rule_ips) = create_signal(String::new());
    let (_new_rule_ports, _set_new_rule_ports) = create_signal(String::new());
    let (_new_rule_protocol, _set_new_rule_protocol) = create_signal("Any".to_string());
    let (_new_rule_block, _set_new_rule_block) = create_signal(true);
    let (_validation_error, _set_validation_error) = create_signal(Option::<String>::None);
    let (_console_output, _set_console_output) = create_signal(Vec::<String>::new());
    let (_is_compiling, _set_is_compiling) = create_signal(false);
    let (_active_tab, _set_active_tab) = create_signal("rule".to_string());
    let (saved_status, set_saved_status) = create_signal(false);
    let (engine_status, set_engine_status) = create_signal("Initializing Engine...".to_string());
    let (engine_active, set_engine_active) = create_signal(false);
    let (_graph_data, set_graph_data) = create_signal(vec![180, 160, 170, 150, 140, 130, 110, 120, 100]);
    let (settings, set_settings) = create_signal(FirewallSettings::default());

    create_effect(move |_| {
        match current_view.get() {
            AppView::Rules => { fetch_sdk_rules(); fetch_rules_raw(); }
            AppView::Exclusions => { fetch_app_decisions(); }
            _ => {}
        }
    });

    create_effect(move |_| {
        set_interval(move || {
                let current_activity = (total_count.get() % 100) as u32;
                let val = 180 - (current_activity.min(150));
                set_graph_data.update(|v| { v.push(val); if v.len() > 10 { v.remove(0); } });
            }, Duration::from_millis(2000));
    });

    create_effect(move |_| {
        let closure = Closure::wrap(Box::new(move |event: JsValue| {
            if let Ok(payload) = serde_wasm_bindgen::from_value::<serde_json::Value>(event) {
                if let Some(payload_obj) = payload.get("payload") {
                    if let Ok(entry) = serde_json::from_value::<LogEntry>(payload_obj.clone()) {
                        set_logs.update(|l| { l.push(entry.clone()); if l.len() > 200 { l.remove(0); } });
                        set_total_count.update(|n| *n += 1);
                        if entry.message.contains("ACTIVE") || entry.message.contains("Engine") {
                            set_engine_status.set(entry.message.clone());
                            if entry.message.contains("ACTIVE") { set_engine_active.set(true); }
                        }
                        match entry.level {
                            LogLevel::Warning | LogLevel::Error => {
                                if entry.message.contains("Blocking") { set_blocked_count.update(|n| *n += 1); }
                                if entry.message.contains("Malicious") { set_threats_count.update(|n| *n += 1); }
                            }
                            LogLevel::Success => { set_allowed_count.update(|n| *n += 1); }
                            _ => {}
                        }
                    }
                }
            }
        }) as Box<dyn FnMut(JsValue)>);
        spawn_local(async move { let _ = listen("log", &closure).await; closure.forget(); });

        let ask_closure = Closure::wrap(Box::new(move |event: JsValue| {
            if let Ok(payload) = serde_wasm_bindgen::from_value::<serde_json::Value>(event) {
                if let Some(payload_obj) = payload.get("payload") {
                    if let Ok(app) = serde_json::from_value::<PendingApp>(payload_obj.clone()) {
                        set_pending_app.set(Some(app));
                    }
                }
            }
        }) as Box<dyn FnMut(JsValue)>);
        spawn_local(async move { let _ = listen("ask_app_decision", &ask_closure).await; ask_closure.forget(); });

        let raw_closure = Closure::wrap(Box::new(move |event: JsValue| {
            if let Ok(payload) = serde_wasm_bindgen::from_value::<serde_json::Value>(event) {
                if let Some(payload_obj) = payload.get("payload") {
                    if let Ok(pkt) = serde_json::from_value::<RawPacket>(payload_obj.clone()) {
                        set_raw_packets.update(|p| { p.push(pkt); if p.len() > 100 { p.remove(0); } });
                    }
                }
            }
        }) as Box<dyn FnMut(JsValue)>);
        spawn_local(async move { let _ = listen("raw_packet", &raw_closure).await; raw_closure.forget(); });
    });

    let save_settings_action = move || {
        spawn_local(async move {
            let s = settings.get();
            let args = serde_wasm_bindgen::to_value(&s).unwrap();
            let _ = invoke("save_settings", args).await;
            set_saved_status.set(true);
            set_timeout(move || set_saved_status.set(false), Duration::from_secs(2));
        });
    };

    let update_path = move |path: String| { set_settings.update(|s| s.website_path = path); };

    view! {
        {move || if is_alert.get() {
            view! { <AlertWindow pending_app=pending_app /> }.into_view()
        } else {
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
                                                <div class="graph-overlay" style="position: absolute; top: 20px; right: 20px; text-align: right">
                                                    <div class="traffic-stat">
                                                        <span class="label">"REAL-TIME ACTIVITY"</span>
                                                        <span class="value" style="color:var(--accent-blue)">
                                                            {move || format!("{:.1} PPS", (total_count.get() % 50) as f32 + 5.0)}
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
                                                    each={move || logs.get()}
                                                    key={|log_item| log_item.id.clone()}
                                                    children={move |log_item| {
                                                        let ts = log_item.timestamp % 100000;
                                                        let msg = log_item.message.clone();
                                                        let level_class = match log_item.level {
                                                            LogLevel::Info => "lvl-info",
                                                            LogLevel::Success => "lvl-success",
                                                            LogLevel::Warning => "lvl-warning",
                                                            LogLevel::Error => "lvl-error",
                                                            _ => "lvl-info",
                                                        };
                                                        view! {
                                                            <div class={format!("log-row {}", level_class)}>
                                                                <span class="log-time">"[" {ts} "]"</span>
                                                                <span class="log-msg">{msg}</span>
                                                            </div>
                                                        }
                                                    }}
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
                                    </div>
                                </div>
                            }.into_view(),

                            AppView::Rules => view! {
                                <div style="height: calc(100vh - 120px); display: flex; flex-direction: column; gap: 15px">
                                    <div style="display: flex; justify-content: flex-end; gap: 10px">
                                        <button class="btn-primary" on:click=move |_| set_show_editor.set(!show_editor.get())>
                                            {move || if show_editor.get() { "Cancel" } else { "Edit YAML" }}
                                        </button>
                                        {move || if show_editor.get() {
                                            view! {
                                                <div style="display: flex; gap: 10px">
                                                    <button class="btn-secondary" on:click=move |_| validate_rules_raw()> "Validate" </button>
                                                    <button class="btn-primary" on:click=move |_| save_rules_raw()> "Save" </button>
                                                </div>
                                            }.into_view()
                                        } else { view! {}.into_view() }}
                                    </div>
                                    {move || if show_editor.get() {
                                        view! {
                                            <textarea class="glass-card" style="flex: 1; padding: 20px; font-family: monospace"
                                                prop:value=move || rules_raw_content.get()
                                                on:input=move |ev| set_rules_raw_content.set(event_target_value(&ev)) />
                                        }.into_view()
                                    } else {
                                        view! { <RulesWiki /> }.into_view()
                                    }}
                                </div>
                            }.into_view(),

                            AppView::Exclusions => view! {
                                <div class="dashboard-grid">
                                    <div class="glass-card" style="width: 100%">
                                        <div class="section-header">
                                            <h3>"Allowed Applications"</h3>
                                            <button class="btn-primary" style="background: var(--accent-red)" on:click=move |_| clear_all_decisions()> "REMOVE ALL" </button>
                                        </div>
                                        <div class="exclusions-list">
                                            {move || app_decisions.get().into_iter().map(|(name, decision)| {
                                                let n = name.clone();
                                                view! {
                                                    <div class="exclusion-item" style="display: flex; justify-content: space-between; padding: 10px; border-bottom: 1px solid #333">
                                                        <span>{n.clone()} " (" {format!("{:?}", decision)} ")"</span>
                                                        <button on:click=move |_| remove_decision_action(n.clone())> "Remove" </button>
                                                    </div>
                                                }
                                            }).collect_view()}
                                        </div>
                                    </div>
                                </div>
                            }.into_view(),

                            AppView::Logs => view! {
                                <div class="glass-card logs-section" style="height: calc(100vh - 120px)">
                                    <div class="section-header">
                                        <h3 style="margin: 0; font-size: 16px; font-weight: 700">"Network Activity Log"</h3>
                                        <button class="btn-primary" style="padding: 5px 15px; font-size: 11px" on:click=move |_| set_logs.set(Vec::new())> "Clear Logs" </button>
                                    </div>
                                    <div class="logs-viewport">
                                        <For
                                            each={move || logs.get().into_iter().rev().collect::<Vec<_>>()}
                                            key={|log_entry| log_entry.id.clone()}
                                            children={move |log_entry| {
                                                let ts = log_entry.timestamp % 100000;
                                                let msg = log_entry.message.clone();
                                                let level_class = match log_entry.level {
                                                    LogLevel::Info => "lvl-info",
                                                    LogLevel::Success => "lvl-success",
                                                    LogLevel::Warning => "lvl-warning",
                                                    LogLevel::Error => "lvl-error",
                                                    _ => "lvl-info",
                                                };
                                                view! {
                                                    <div class={format!("log-row {}", level_class)}>
                                                        <span class="log-time">"[" {ts} "]"</span>
                                                        <span class="log-msg">{msg}</span>
                                                    </div>
                                                }
                                            }}
                                        />
                                    </div>
                                </div>
                            }.into_view(),

                            AppView::PacketReader => view! {
                                <div class="dashboard-grid" style="height: calc(100vh - 120px)">
                                    <div class="glass-card dash-col-main" style="flex: 2; overflow-y: auto">
                                        <div class="section-header">
                                            <h3>"Live Packet Stream"</h3>
                                            <button class="btn-primary" style="padding: 5px 15px; font-size: 11px" on:click=move |_| set_raw_packets.set(Vec::new())> "Clear" </button>
                                        </div>
                                        <div class="logs-viewport">
                                            <For
                                                each={move || raw_packets.get().into_iter().rev().collect::<Vec<_>>()}
                                                key={|p_item| p_item.id.clone()}
                                                children={move |p_item| {
                                                    let p_selected = p_item.clone();
                                                    let p_summary = p_item.summary.clone();
                                                    let p_src = p_item.src_ip.clone();
                                                    let p_dst = p_item.dst_ip.clone();
                                                    let p_src_port = p_item.src_port;
                                                    let p_dst_port = p_item.dst_port;
                                                    view! {
                                                        <div class="log-row lvl-info" style="cursor: pointer" on:click=move |_| set_selected_packet.set(Some(p_selected.clone()))>
                                                            <span class="log-time">{format!("{}:{} -> {}:{}", p_src, p_src_port, p_dst, p_dst_port)}</span>
                                                            <span class="log-msg">{p_summary}</span>
                                                        </div>
                                                    }
                                                }}
                                            />
                                        </div>
                                    </div>
                                    <div class="glass-card dash-col-side" style="flex: 1">
                                        <h3>"Packet Inspection"</h3>
                                        {move || match selected_packet.get() {
                                            Some(p) => view! {
                                                <div style="font-size: 12px; display: flex; flex-direction: column; gap: 10px">
                                                    <div><strong>"Time:"</strong> {p.timestamp}</div>
                                                    <div><strong>"Direction:"</strong> {format!("{:?} -> {:?}", p.src_ip, p.dst_ip)}</div>
                                                    <div><strong>"Process:"</strong> {p.process_name} " (" {p.process_id} ")"</div>
                                                    <div style="margin-top: 10px"><strong>"Payload (Hex):"</strong></div>
                                                    <div style="background: #000; padding: 10px; border-radius: 4px; font-family: monospace; word-break: break-all">
                                                        {p.payload_hex}
                                                    </div>
                                                </div>
                                            }.into_view(),
                                            None => view! { <div style="color: var(--text-muted)">"Select a packet to inspect"</div> }.into_view(),
                                        }}
                                    </div>
                                </div>
                            }.into_view(),

                            AppView::Settings => view! {
                                <div class="dashboard-grid">
                                    <div class="glass-card" style="width: 100%">
                                        <h3>"System Settings"</h3>
                                        <div class="input-group">
                                            <label>"Custom Filter Path"</label>
                                            <input type="text" prop:value=move || settings.get().website_path on:input=move |ev| update_path(event_target_value(&ev)) />
                                        </div>
                                        <button class="btn-primary" on:click=move |_| save_settings_action()> "Save Changes" </button>
                                        {move || if saved_status.get() { view! { <span style="margin-left: 10px; color: var(--accent-green)">"Saved!"</span> }.into_view() } else { view! {}.into_view() }}
                                    </div>
                                </div>
                            }.into_view(),
                        }}
                    </main>
                </div>
            }.into_view()
        }}
    }
}

pub fn main() {
    console_error_panic_hook::set_once();
    mount_to_body(|| view! { <App/> })
}

#[component]
fn AlertWindow(
    pending_app: ReadSignal<Option<PendingApp>>,
) -> impl IntoView {
    let resolve_decision_internal = move |name: String, decision: String| {
        spawn_local(async move {
            let args = serde_wasm_bindgen::to_value(&ResolveArgs { name, decision }).unwrap();
            let _ = invoke("resolve_app_decision", args).await;
            
            // Close via backend command for reliability
            let _ = invoke("close_window", JsValue::NULL).await;
        });
    };

    view! {
        <div class="alert-window-root">
             <div class="alert-window-header">
                 <div class="alert-window-brand"> <div class="dragon-icon"></div> "HYDRADRAGON" </div>
                 <div class="alert-window-tag">"THREAT INTERCEPTED"</div>
             </div>
             <div class="alert-window-body">
                 {move || pending_app.get().map(|app| {
                     let n1 = app.name.clone(); let n2 = app.name.clone(); let n3 = app.name.clone();
                     let res1 = resolve_decision_internal.clone(); let res2 = resolve_decision_internal.clone(); let res3 = resolve_decision_internal.clone();
                     view! {
                         <div class="alert-content-grid" style="margin-top: 0">
                             <div class="alert-info-container">
                                  <h2 class="alert-title" style="margin-bottom: 5px">
                                      {if let Some(ref h) = app.hostname { format!("{} wants connection", h) } else { app.name.clone() }}
                                  </h2>
                                  <div class="alert-desc" style="margin-bottom: 8px">
                                      {if app.hostname.is_some() { app.name.clone() } else { "System intercept".to_string() }} " is attempting network access."
                                  </div>
                                  <div class="alert-details-box" style="font-size: 11px">
                                      <div class="detail-row"> <span class="detail-label" style="width: 80px">"Target:"</span> <span class="detail-value">{format!("{}:{}", app.dst_ip, app.dst_port)}</span> </div>
                                      <div class="detail-row"> <span class="detail-label" style="width: 80px">"Path:"</span> <span class="detail-value" style="font-size: 10px; opacity: 0.6">{app.path.clone()}</span> </div>
                                  </div>
                             </div>
                         </div>
                         <div class="alert-footer-actions" style="margin-top: 10px; padding-top: 10px">
                             <button class="alert-btn block" on:click=move |_| res3(n3.clone(), "block".to_string())> "BLOCK" </button>
                             <button class="alert-btn session" on:click=move |_| res1(n1.clone(), "allow_once".to_string())> "ONCE" </button>
                             <button class="alert-btn always" on:click=move |_| res2(n2.clone(), "allow_always".to_string())> "TRUST" </button>
                         </div>
                     }
                 })}
             </div>
        </div>
    }
}
