use js_sys::Reflect;
use leptos::*;
use leptos::{event_target_checked, event_target_value};
// Assuming imports work.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub alert_source: Option<String>,
    #[serde(default)]
    pub alert_kind: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub decision_key: Option<String>,
    #[serde(default)]
    pub full_url: Option<String>,
    #[serde(default)]
    pub http_method: Option<String>,
    #[serde(default)]
    pub http_path: Option<String>,
    #[serde(default)]
    pub http_user_agent: Option<String>,
    #[serde(default)]
    pub http_content_type: Option<String>,
    #[serde(default)]
    pub http_referer: Option<String>,
    #[serde(default)]
    pub http_request_body: Option<String>,
    #[serde(default)]
    pub http_response_body: Option<String>,
    #[serde(default)]
    pub payload_sample: Option<String>,
    #[serde(default)]
    pub detected_file_type: Option<String>,
    #[serde(default)]
    pub packet_json: Option<String>,
    #[serde(default = "default_queue_position")]
    pub queue_position: usize,
    #[serde(default = "default_queue_total")]
    pub queue_total: usize,
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
pub struct ProxyHttpEvent {
    pub id: String,
    pub timestamp: u64,
    pub method: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub full_url: String,
    pub status: u16,
    pub user_agent: Option<String>,
    pub content_type: Option<String>,
    pub referer: Option<String>,
    pub response_content_type: Option<String>,
    pub response_content_length: Option<String>,
    pub request_body: Option<String>,
    pub request_body_truncated: bool,
    #[serde(default)]
    pub response_body: Option<String>,
    #[serde(default)]
    pub response_body_truncated: bool,
}

/// A body changer rule managed through the GUI.
/// Serialised into rules.yaml as an SDK rule with action change_request_body
/// or change_response_body.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct BodyChangerRule {
    pub id: String,           // client-side UUID for keying
    pub name: String,
    pub enabled: bool,
    /// "request" or "response"
    pub target: String,
    /// URL substring to match (goes into url matcher)
    pub url_pattern: String,
    /// HTTP method to match, empty = any
    pub method_pattern: String,
    /// The replacement body text
    pub replacement: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EngineRuntimeStatus {
    pub active: bool,
    pub status: String,
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
    HttpInspector,
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TlsInspectionMode {
    MetadataOnly,
    TlsProxy,
}

impl Default for TlsInspectionMode {
    fn default() -> Self {
        Self::TlsProxy
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TlsProxyConfig {
    #[serde(default)]
    pub mode: TlsInspectionMode,
    #[serde(default)]
    pub listen_host: String,
    #[serde(default)]
    pub listen_port: u16,
    #[serde(default)]
    pub block_quic_udp_443: bool,
    #[serde(default)]
    pub auto_start: bool,
}

impl Default for TlsProxyConfig {
    fn default() -> Self {
        Self {
            mode: TlsInspectionMode::TlsProxy,
            listen_host: "127.0.0.1".to_string(),
            listen_port: 8877,
            block_quic_udp_443: true,
            auto_start: true,
        }
    }
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
    #[serde(default)]
    pub file_types: Vec<String>,
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
    ChangeRequestBody,
    ChangeResponseBody,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SdkRuleView {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub enabled: bool,
    pub action: RuleActionView,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub encoding: String,
    #[serde(default)]
    pub condition_logic: String,
    #[serde(default)]
    pub change_request_body: Option<String>,
    #[serde(default)]
    pub change_response_body: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FirewallSettings {
    #[serde(default)]
    pub app_decisions: HashMap<String, AppDecision>,
    #[serde(default)]
    pub website_path: String,
    #[serde(default)]
    pub rules: Vec<FirewallRule>,
    #[serde(default)]
    pub late_blocking_mode: bool,
    #[serde(default)]
    pub headless_mode: bool,
    #[serde(default)]
    pub log_mode: bool,
    #[serde(default)]
    pub no_alert_mode: bool,
    #[serde(default = "default_true")]
    pub save_all_logs: bool,
    #[serde(default = "default_true")]
    pub prune_old_logs: bool,
    #[serde(default = "default_max_visible_logs")]
    pub max_visible_logs: usize,
    #[serde(default)]
    pub tls_proxy: TlsProxyConfig,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

impl Default for FirewallSettings {
    fn default() -> Self {
        let mut metadata = HashMap::new();
        metadata.insert("version".to_string(), "2.0.0".to_string());
        metadata.insert(
            "description".to_string(),
            "HydraDragon Next-Gen Firewall Configuration".to_string(),
        );
        metadata.insert("theme".to_string(), "cyberpunk".to_string());

        Self {
            app_decisions: HashMap::new(),
            website_path: String::new(),
            rules: Vec::new(),
            late_blocking_mode: false,
            headless_mode: false,
            log_mode: false,
            no_alert_mode: false,
            save_all_logs: true,
            prune_old_logs: true,
            max_visible_logs: default_max_visible_logs(),
            tls_proxy: TlsProxyConfig::default(),
            metadata,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_max_visible_logs() -> usize {
    2000
}

fn default_queue_position() -> usize {
    1
}

fn default_queue_total() -> usize {
    1
}

#[component]
pub fn App() -> impl IntoView {
    let (logs, set_logs) = create_signal(Vec::<LogEntry>::new());
    let (blocked_count, set_blocked_count) = create_signal(0);
    let (_threats_count, set_threats_count) = create_signal(0);
    let (allowed_count, set_allowed_count) = create_signal(0);
    let (total_count, set_total_count) = create_signal(0);

    // Navigation State
    let (current_view, set_current_view) = create_signal(AppView::Dashboard);
    let (raw_packets, set_raw_packets) = create_signal(Vec::<RawPacket>::new());
    let (selected_packet, set_selected_packet) = create_signal(Option::<RawPacket>::None);
    let (proxy_events, set_proxy_events) = create_signal(Vec::<ProxyHttpEvent>::new());
    let (selected_proxy_event, set_selected_proxy_event) = create_signal(Option::<ProxyHttpEvent>::None);


    let (sdk_rules, set_sdk_rules) = create_signal(Vec::<SdkRuleView>::new());
    let (body_changers, set_body_changers) = create_signal(Vec::<BodyChangerRule>::new());
    // Fields for the body changer editor form
    let (bc_edit_id, set_bc_edit_id) = create_signal(Option::<String>::None);
    let (bc_name, set_bc_name) = create_signal(String::new());
    let (bc_target, set_bc_target) = create_signal("request".to_string());
    let (bc_url_pattern, set_bc_url_pattern) = create_signal(String::new());
    let (bc_method_pattern, set_bc_method_pattern) = create_signal(String::new());
    let (bc_replacement, set_bc_replacement) = create_signal(String::new());
    let (bc_enabled, set_bc_enabled) = create_signal(true);
    let (show_bc_form, set_show_bc_form) = create_signal(false);
    
    let (pending_app, set_pending_app) = create_signal(Option::<PendingApp>::None);
    let (app_decisions, set_app_decisions) = create_signal(HashMap::<String, AppDecision>::new());

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
        }
        
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

    let (settings, set_settings) = create_signal(FirewallSettings::default());
    
    let (show_editor, set_show_editor) = create_signal(false);
    let (rules_raw_content, set_rules_raw_content) = create_signal(String::new());
    let (_validation_result, set_validation_result) = create_signal(String::from("Ready to validate."));
    let (show_owlyshield_editor, set_show_owlyshield_editor) = create_signal(false);
    let (owlyshield_rules_content, set_owlyshield_rules_content) = create_signal(String::new());

    let fetch_sdk_rules = move || {
        spawn_local(async move {
            let args = js_sys::Object::new();
            let val = invoke("get_sdk_rules", args.into()).await;
            let rules: Vec<SdkRuleView> = serde_wasm_bindgen::from_value(val).unwrap_or_default();
            set_sdk_rules.set(rules);
        });
    };

    let fetch_body_changers = move || {
        spawn_local(async move {
            let val = invoke("get_body_changers", JsValue::NULL).await;
            let rules: Vec<BodyChangerRule> = serde_wasm_bindgen::from_value(val).unwrap_or_default();
            set_body_changers.set(rules);
        });
    };

    let save_body_changers_fn = move |rules: Vec<BodyChangerRule>| {
        spawn_local(async move {
            let args = serde_wasm_bindgen::to_value(&serde_json::json!({ "rules": rules })).unwrap();
            let _ = invoke("save_body_changers", args).await;
            let val = invoke("get_body_changers", JsValue::NULL).await;
            let updated: Vec<BodyChangerRule> = serde_wasm_bindgen::from_value(val).unwrap_or_default();
            set_body_changers.set(updated);
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

    let fetch_owlyshield_rules = move || {
        spawn_local(async move {
            let val = invoke("get_owlyshield_rules_raw", JsValue::NULL).await;
            if let Ok(s) = serde_wasm_bindgen::from_value::<String>(val) {
                set_owlyshield_rules_content.set(s);
            }
        });
    };

    let save_owlyshield_rules = move || {
        let content = owlyshield_rules_content.get();
        spawn_local(async move {
            let args = js_sys::Object::new();
            js_sys::Reflect::set(&args, &"content".into(), &content.into()).unwrap();
            let _ = invoke("save_owlyshield_rules_raw", args.into()).await;
        });
    };

    let fetch_app_decisions = move || {
        spawn_local(async move {
            let res = invoke("get_app_decisions", JsValue::NULL).await;
            if let Ok(decisions) = serde_wasm_bindgen::from_value::<HashMap<String, AppDecision>>(res) {
                set_app_decisions.set(decisions);
            }
        });
    };

    let fetch_settings = move || {
        spawn_local(async move {
            let res = invoke("get_settings", JsValue::NULL).await;
            if let Ok(current_settings) = serde_wasm_bindgen::from_value::<FirewallSettings>(res) {
                set_settings.set(current_settings);
            }
        });
    };

    let fetch_saved_logs = move || {
        spawn_local(async move {
            let res = invoke("get_saved_logs", JsValue::NULL).await;
            if let Ok(saved_logs) = serde_wasm_bindgen::from_value::<Vec<LogEntry>>(res) {
                if !saved_logs.is_empty() {
                    set_logs.set(saved_logs);
                }
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

    let (confirm_quit, set_confirm_quit) = create_signal(false);
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
    let (settings_loaded, set_settings_loaded) = create_signal(false);
    let (_graph_data, set_graph_data) = create_signal(vec![180, 160, 170, 150, 140, 130, 110, 120, 100]);

    create_effect(move |_| {
        match current_view.get() {
            AppView::Rules => { fetch_sdk_rules(); fetch_rules_raw(); fetch_body_changers(); fetch_owlyshield_rules(); }
            AppView::Logs => { fetch_saved_logs(); }
            AppView::Exclusions => { fetch_app_decisions(); }
            AppView::Settings => { fetch_settings(); }
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
                        set_logs.update(|l| {
                            l.push(entry.clone());
                            let current_settings = settings.get_untracked();
                            if current_settings.prune_old_logs {
                                let keep = current_settings.max_visible_logs.max(1);
                                if l.len() > keep {
                                    let remove_count = l.len() - keep;
                                    l.drain(0..remove_count);
                                }
                            }
                        });
                        set_total_count.update(|n| *n += 1);
                        if entry.message.contains("ACTIVE") || entry.message.contains("Engine") {
                            set_engine_status.set(entry.message.clone());
                            if entry.message.contains("ACTIVE") { set_engine_active.set(true); }
                        }
                        match entry.level {
                            LogLevel::Warning | LogLevel::Error => {
                                let message_lower = entry.message.to_lowercase();
                                if message_lower.starts_with("blocked:")
                                    || message_lower.contains("proxy intercept blocked")
                                {
                                    set_blocked_count.update(|n| *n += 1);
                                }
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

        let proxy_closure = Closure::wrap(Box::new(move |event: JsValue| {
            if let Ok(payload) = serde_wasm_bindgen::from_value::<serde_json::Value>(event) {
                if let Some(payload_obj) = payload.get("payload") {
                    if let Ok(ev) = serde_json::from_value::<ProxyHttpEvent>(payload_obj.clone()) {
                        set_proxy_events.update(|p| { p.push(ev); if p.len() > 200 { p.remove(0); } });
                    }
                }
            }
        }) as Box<dyn FnMut(JsValue)>);
        spawn_local(async move { let _ = listen("proxy_http", &proxy_closure).await; proxy_closure.forget(); });
    });

    {
        let refresh_engine_state = move || {
            spawn_local(async move {
                let res = invoke("get_engine_runtime_status", JsValue::NULL).await;
                if let Ok(status) = serde_wasm_bindgen::from_value::<EngineRuntimeStatus>(res) {
                    set_engine_active.set(status.active);
                    set_engine_status.set(status.status);
                    if status.active && !settings_loaded.get_untracked() {
                        fetch_settings();
                        fetch_saved_logs();
                        set_settings_loaded.set(true);
                    }
                }
            });
        };

        refresh_engine_state();
        set_interval(refresh_engine_state, Duration::from_millis(1000));
    }

    let save_settings_action = move || {
        spawn_local(async move {
            let s = settings.get();
            let args = serde_wasm_bindgen::to_value(&s).unwrap();
            let _ = invoke("save_settings", args).await;
            fetch_settings();
            fetch_saved_logs();
            set_saved_status.set(true);
            set_timeout(move || set_saved_status.set(false), Duration::from_secs(2));
        });
    };

    let update_path = move |path: String| { set_settings.update(|s| s.website_path = path); };

    view! {
        {move || if is_alert.get() {
            view! { <AlertWindow pending_app=pending_app set_pending_app=set_pending_app /> }.into_view()
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
                            <a href="#" class={move || if current_view.get() == AppView::HttpInspector { "nav-item active" } else { "nav-item" }}
                               on:click=move |ev| { ev.prevent_default(); set_current_view.set(AppView::HttpInspector); }>
                               "HTTP Inspector"
                            </a>
                            <a href="#" class={move || if current_view.get() == AppView::Exclusions { "nav-item active" } else { "nav-item" }}
                               on:click=move |ev| { ev.prevent_default(); set_current_view.set(AppView::Exclusions); }>
                               "Exclusions"
                            </a>
                            <a href="#" class={move || if current_view.get() == AppView::Settings { "nav-item active" } else { "nav-item" }}
                               on:click=move |ev| { ev.prevent_default(); set_current_view.set(AppView::Settings); }>
                               "Settings"
                            </a>
                            <a href="#" class="nav-item nav-item-quit"
                               on:click=move |ev| {
                                   ev.prevent_default();
                                   set_confirm_quit.set(true);
                               }>
                               "Quit"
                            </a>

                            {move || if confirm_quit.get() {
                                view! {
                                    <div class="quit-confirm">
                                        <span>"Are you sure?"</span>
                                        <div style="display: flex; gap: 6px; margin-top: 8px">
                                            <button class="btn-primary" style="background: var(--accent-red); flex: 1; padding: 5px"
                                                on:click=move |_| {
                                                    spawn_local(async move {
                                                        let _ = invoke("quit_app", JsValue::NULL).await;
                                                    });
                                                }>
                                                "Yes, Quit"
                                            </button>
                                            <button class="btn-secondary" style="flex: 1; padding: 5px"
                                                on:click=move |_| set_confirm_quit.set(false)>
                                                "Cancel"
                                            </button>
                                        </div>
                                    </div>
                                }.into_view()
                            } else {
                                view! {}.into_view()
                            }}
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
                                    AppView::HttpInspector => "HTTP Inspector",
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
                                                    <span class={move || if engine_active.get() { "status-badge secure" } else { "status-badge" }}>
                                                        {move || if engine_active.get() { "SECURE" } else { "INITIALIZING" }}
                                                    </span>
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
                                        <div class="glass-card stat-item-compact">
                                            <h4>"Allowed"</h4>
                                            <div class="stat-value" style="color: var(--accent-green)">{move || allowed_count.get()}</div>
                                        </div>
                                    </div>
                                </div>
                            }.into_view(),

                            AppView::Rules => view! {
                                <div style="height: calc(100vh - 120px); display: flex; flex-direction: column; gap: 0">
                                    // ── Tab Bar ──────────────────────────────────────────────
                                    <div style="display: flex; border-bottom: 1px solid #333; margin-bottom: 12px">
                                        <button
                                            class={move || if !show_editor.get() && !show_bc_form.get() && !show_owlyshield_editor.get() { "nav-item active" } else { "nav-item" }}
                                            style="padding: 8px 18px; border-radius: 4px 4px 0 0"
                                            on:click=move |_| { set_show_editor.set(false); set_show_bc_form.set(false); set_show_owlyshield_editor.set(false); }>
                                            "Rules Wiki"
                                        </button>
                                        <button
                                            class={move || if show_editor.get() { "nav-item active" } else { "nav-item" }}
                                            style="padding: 8px 18px; border-radius: 4px 4px 0 0"
                                            on:click=move |_| { set_show_editor.set(true); set_show_bc_form.set(false); set_show_owlyshield_editor.set(false); fetch_rules_raw(); }>
                                            "Edit YAML"
                                        </button>
                                        <button
                                            class={move || if show_bc_form.get() { "nav-item active" } else { "nav-item" }}
                                            style="padding: 8px 18px; border-radius: 4px 4px 0 0"
                                            on:click=move |_| { set_show_bc_form.set(true); set_show_editor.set(false); set_show_owlyshield_editor.set(false); fetch_body_changers(); }>
                                            "Body Changer"
                                        </button>
                                        <button
                                            class={move || if show_owlyshield_editor.get() { "nav-item active" } else { "nav-item" }}
                                            style="padding: 8px 18px; border-radius: 4px 4px 0 0"
                                            on:click=move |_| { set_show_owlyshield_editor.set(true); set_show_editor.set(false); set_show_bc_form.set(false); fetch_owlyshield_rules(); }>
                                            "OwlyShield Rules"
                                        </button>
                                        // save/validate buttons for YAML tabs
                                        {move || if show_editor.get() {
                                            view! {
                                                <div style="margin-left: auto; display: flex; gap: 10px; align-items: center">
                                                    <button class="btn-secondary" on:click=move |_| validate_rules_raw()> "Validate" </button>
                                                    <button class="btn-primary" on:click=move |_| save_rules_raw()> "Save" </button>
                                                </div>
                                            }.into_view()
                                        } else if show_owlyshield_editor.get() {
                                            view! {
                                                <div style="margin-left: auto; display: flex; gap: 10px; align-items: center">
                                                    <button class="btn-primary" on:click=move |_| save_owlyshield_rules()> "Save" </button>
                                                </div>
                                            }.into_view()
                                        } else { view!{}.into_view() }}
                                    </div>

                                    // ── Tab Content ──────────────────────────────────────────
                                    <div style="flex: 1; overflow: hidden">
                                    {move || if show_editor.get() {
                                        view! {
                                            <textarea class="glass-card" style="width: 100%; height: 100%; box-sizing: border-box; padding: 20px; font-family: monospace; resize: none"
                                                prop:value=move || rules_raw_content.get()
                                                on:input=move |ev| set_rules_raw_content.set(event_target_value(&ev)) />
                                        }.into_view()
                                    } else if show_owlyshield_editor.get() {
                                        view! {
                                            <div style="display: flex; flex-direction: column; height: 100%; gap: 8px">
                                                <div class="glass-card" style="padding: 10px 16px; font-size: 12px; color: var(--text-muted)">
                                                    "Editing OwlyShield behavioral rules — path resolved from "
                                                    <code style="color: var(--accent-blue)">"SOFTWARE\\Owlyshield → RULES_PATH"</code>
                                                </div>
                                                <textarea class="glass-card" style="flex: 1; width: 100%; box-sizing: border-box; padding: 20px; font-family: monospace; resize: none"
                                                    prop:value=move || owlyshield_rules_content.get()
                                                    on:input=move |ev| set_owlyshield_rules_content.set(event_target_value(&ev)) />
                                            </div>
                                        }.into_view()
                                    } else if show_bc_form.get() {
                                        // ── Body Changer Panel ────────────────────────────────
                                        view! {
                                            <div style="display: flex; gap: 15px; height: 100%; overflow: hidden">
                                                // Left: list
                                                <div class="glass-card" style="flex: 1; overflow-y: auto; display: flex; flex-direction: column">
                                                    <div class="section-header">
                                                        <h3 style="margin: 0">"Body Changer Rules"</h3>
                                                        <button class="btn-primary" style="padding: 5px 14px; font-size: 12px"
                                                            on:click=move |_| {
                                                                // Clear the form for a new rule
                                                                set_bc_edit_id.set(None);
                                                                set_bc_name.set(String::new());
                                                                set_bc_target.set("request".to_string());
                                                                set_bc_url_pattern.set(String::new());
                                                                set_bc_method_pattern.set(String::new());
                                                                set_bc_replacement.set(String::new());
                                                                set_bc_enabled.set(true);
                                                            }>"+ New Rule"</button>
                                                    </div>
                                                    <div style="flex: 1; overflow-y: auto">
                                                        <For
                                                            each={move || body_changers.get()}
                                                            key={|r| r.id.clone()}
                                                            children={move |rule| {
                                                                let r2 = rule.clone();
                                                                let r3 = rule.clone();
                                                                let target_label = if rule.target == "response" { "Response" } else { "Request" };
                                                                let target_color = if rule.target == "response" { "#a78bfa" } else { "#60a5fa" };
                                                                view! {
                                                                    <div class="log-row lvl-info"
                                                                        style="display: flex; justify-content: space-between; align-items: center; cursor: pointer"
                                                                        on:click=move |_| {
                                                                            set_bc_edit_id.set(Some(r2.id.clone()));
                                                                            set_bc_name.set(r2.name.clone());
                                                                            set_bc_target.set(r2.target.clone());
                                                                            set_bc_url_pattern.set(r2.url_pattern.clone());
                                                                            set_bc_method_pattern.set(r2.method_pattern.clone());
                                                                            set_bc_replacement.set(r2.replacement.clone());
                                                                            set_bc_enabled.set(r2.enabled);
                                                                        }>
                                                                        <div style="display: flex; align-items: center; gap: 8px; flex: 1; overflow: hidden">
                                                                            <span style={format!("color: {}; font-size: 11px; font-weight: 700; min-width: 60px", target_color)}>{target_label}</span>
                                                                            <span style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap">{rule.name.clone()}</span>
                                                                            {if !rule.url_pattern.is_empty() {
                                                                                view! { <span style="color: var(--text-muted); font-size: 10px; margin-left: 4px">{rule.url_pattern.clone()}</span> }.into_view()
                                                                            } else { view!{}.into_view() }}
                                                                        </div>
                                                                        <div style="display: flex; align-items: center; gap: 6px">
                                                                            {if !rule.enabled { view! { <span style="color: #888; font-size: 10px">"disabled"</span> }.into_view() } else { view!{}.into_view() }}
                                                                            <button
                                                                                style="background: var(--accent-red); border: none; border-radius: 3px; color: white; padding: 2px 8px; font-size: 11px; cursor: pointer"
                                                                                on:click=move |ev| {
                                                                                    ev.stop_propagation();
                                                                                    let id = r3.id.clone();
                                                                                    let mut updated = body_changers.get();
                                                                                    updated.retain(|r| r.id != id);
                                                                                    save_body_changers_fn(updated);
                                                                                }>"Delete"</button>
                                                                        </div>
                                                                    </div>
                                                                }
                                                            }}
                                                        />
                                                    </div>
                                                </div>

                                                // Right: edit form
                                                <div class="glass-card" style="flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 12px; padding: 20px">
                                                    <h3 style="margin: 0">
                                                        {move || if bc_edit_id.get().is_some() { "Edit Rule" } else { "New Rule" }}
                                                    </h3>
                                                    <div class="input-group">
                                                        <label>"Rule Name"</label>
                                                        <input type="text" placeholder="My Body Changer"
                                                            prop:value=move || bc_name.get()
                                                            on:input=move |ev| set_bc_name.set(event_target_value(&ev)) />
                                                    </div>
                                                    <div class="input-group">
                                                        <label>"Target"</label>
                                                        <select
                                                            on:change=move |ev| set_bc_target.set(event_target_value(&ev))>
                                                            <option value="request" selected={move || bc_target.get() == "request"}>"Request Body"</option>
                                                            <option value="response" selected={move || bc_target.get() == "response"}>"Response Body"</option>
                                                        </select>
                                                    </div>
                                                    <div class="input-group">
                                                        <label>"URL Pattern (substring match, empty = all)"</label>
                                                        <input type="text" placeholder="example.com/api"
                                                            prop:value=move || bc_url_pattern.get()
                                                            on:input=move |ev| set_bc_url_pattern.set(event_target_value(&ev)) />
                                                    </div>
                                                    <div class="input-group">
                                                        <label>"HTTP Method (e.g. POST, empty = any)"</label>
                                                        <input type="text" placeholder="POST"
                                                            prop:value=move || bc_method_pattern.get()
                                                            on:input=move |ev| set_bc_method_pattern.set(event_target_value(&ev)) />
                                                    </div>
                                                    <div class="input-group">
                                                        <label>"Replacement Body"</label>
                                                        <textarea
                                                            style="font-family: monospace; min-height: 120px; resize: vertical; padding: 8px"
                                                            placeholder=r#"{"key":"value"}"#
                                                            prop:value=move || bc_replacement.get()
                                                            on:input=move |ev| set_bc_replacement.set(event_target_value(&ev)) />
                                                    </div>
                                                    <div class="input-group">
                                                        <label style="display: flex; align-items: center; gap: 8px">
                                                            <input type="checkbox"
                                                                prop:checked=move || bc_enabled.get()
                                                                on:change=move |ev| set_bc_enabled.set(event_target_checked(&ev)) />
                                                            "Enabled"
                                                        </label>
                                                    </div>
                                                    <div style="display: flex; gap: 10px; margin-top: 8px">
                                                        <button class="btn-primary" on:click=move |_| {
                                                            let name = bc_name.get();
                                                            if name.trim().is_empty() { return; }
                                                            let id = bc_edit_id.get()
                                                                .unwrap_or_else(|| {
                                                                    // simple unique id: timestamp millis
                                                                    js_sys::Date::now().to_bits().to_string()
                                                                });
                                                            let new_rule = BodyChangerRule {
                                                                id: id.clone(),
                                                                name,
                                                                enabled: bc_enabled.get(),
                                                                target: bc_target.get(),
                                                                url_pattern: bc_url_pattern.get(),
                                                                method_pattern: bc_method_pattern.get(),
                                                                replacement: bc_replacement.get(),
                                                            };
                                                            let mut updated = body_changers.get();
                                                            if let Some(pos) = updated.iter().position(|r| r.id == id) {
                                                                updated[pos] = new_rule;
                                                            } else {
                                                                updated.push(new_rule);
                                                            }
                                                            save_body_changers_fn(updated);
                                                            // Reset form
                                                            set_bc_edit_id.set(None);
                                                            set_bc_name.set(String::new());
                                                            set_bc_url_pattern.set(String::new());
                                                            set_bc_method_pattern.set(String::new());
                                                            set_bc_replacement.set(String::new());
                                                            set_bc_enabled.set(true);
                                                        }>"Save Rule"</button>
                                                        <button class="btn-secondary" on:click=move |_| {
                                                            set_bc_edit_id.set(None);
                                                            set_bc_name.set(String::new());
                                                            set_bc_url_pattern.set(String::new());
                                                            set_bc_method_pattern.set(String::new());
                                                            set_bc_replacement.set(String::new());
                                                            set_bc_enabled.set(true);
                                                        }>"Clear"</button>
                                                    </div>
                                                </div>
                                            </div>
                                        }.into_view()
                                    } else {
                                        view! {
                                            <div style="display: flex; flex-direction: column; gap: 15px; height: 100%; overflow: hidden">
                                                <div class="glass-card" style="flex: 1; overflow-y: auto; display: flex; flex-direction: column">
                                                    <div class="section-header">
                                                        <h3 style="margin: 0">"Active SDK Rules"</h3>
                                                        <span style="font-size: 11px; opacity: 0.6">"Real-time Behavioral Enforcement"</span>
                                                    </div>
                                                    <div style="padding: 15px; flex: 1; overflow-y: auto">
                                                        <For
                                                            each={move || sdk_rules.get()}
                                                            key={|r| r.name.clone()}
                                                            children={move |rule| {
                                                                let bg = if rule.enabled { "rgba(96, 165, 250, 0.05)" } else { "rgba(0,0,0,0.2)" };
                                                                let border = if rule.enabled { "1px solid rgba(96, 165, 250, 0.2)" } else { "1px solid rgba(255,255,255,0.05)" };
                                                                view! {
                                                                    <div style={format!("background: {}; border: {}; border-radius: 8px; padding: 15px; margin-bottom: 12px; display: flex; flex-direction: column; gap: 8px", bg, border)}>
                                                                        <div style="display: flex; justify-content: space-between; align-items: flex-start">
                                                                            <div>
                                                                                <h4 style="margin: 0; color: var(--text-bright); font-size: 14px">{rule.name.clone()}</h4>
                                                                                <p style="margin: 4px 0 0 0; font-size: 12px; color: var(--text-muted)">{rule.description.clone()}</p>
                                                                            </div>
                                                                            <div style="display: flex; gap: 8px">
                                                                                <span class={format!("badge {}", if rule.enabled { "badge-success" } else { "badge-secondary" })}>
                                                                                    {if rule.enabled { "ENABLED" } else { "DISABLED" }}
                                                                                </span>
                                                                                <span class="badge" style="background: var(--accent-blue); color: white">
                                                                                    {format!("{:?}", rule.action)}
                                                                                </span>
                                                                            </div>
                                                                        </div>
                                                                        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-top: 5px; font-size: 11px; opacity: 0.8">
                                                                            <div>"Protocol: " <span style="color: var(--accent-orange)">{rule.protocol.clone()}</span></div>
                                                                            <div>"Logic: " <span style="color: var(--accent-blue)">{rule.condition_logic.clone()}</span></div>
                                                                            <div>"Encoding: " <span style="color: #a78bfa">{rule.encoding.clone()}</span></div>
                                                                        </div>
                                                                        {if rule.change_request_body.is_some() || rule.change_response_body.is_some() {
                                                                            view! {
                                                                                <div style="margin-top: 5px; padding: 8px; background: rgba(0,0,0,0.3); border-radius: 4px; font-size: 10px; font-family: monospace">
                                                                                    <div style="color: #60a5fa">"⚡ BODY MODIFICATION ACTIVE"</div>
                                                                                </div>
                                                                            }.into_view()
                                                                        } else { view!{}.into_view() }}
                                                                    </div>
                                                                }
                                                            }}
                                                        />
                                                    </div>
                                                </div>
                                                <RulesWiki />
                                            </div>
                                        }.into_view()
                                    }}
                                    </div>
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
                                        <button class="btn-primary" style="padding: 5px 15px; font-size: 11px" on:click=move |_| set_logs.set(Vec::new())> "Clear Screen" </button>
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
                                                    <div><strong>"Process:"</strong> {if !p.process_path.trim().is_empty() && p.process_path != "Unknown" { p.process_path.clone() } else { p.process_name.clone() }}</div>
                                                    <div><strong>"PID:"</strong> {p.process_id}</div>
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

                            AppView::HttpInspector => view! {
                                <div class="dashboard-grid" style="height: calc(100vh - 120px)">
                                    <div class="glass-card dash-col-main" style="flex: 2; overflow-y: auto">
                                        <div class="section-header">
                                            <h3>"HTTP Traffic (TLS Proxy)"</h3>
                                            <button class="btn-primary" style="padding: 5px 15px; font-size: 11px"
                                                on:click=move |_| { set_proxy_events.set(Vec::new()); set_selected_proxy_event.set(None); }>
                                                "Clear"
                                            </button>
                                        </div>
                                        <div class="logs-viewport">
                                            <For
                                                each={move || proxy_events.get().into_iter().rev().collect::<Vec<_>>()}
                                                key={|e| e.id.clone()}
                                                children={move |ev| {
                                                    let ev_sel = ev.clone();
                                                    let badge_color = if ev.status < 300 { "#22c55e" } else if ev.status < 400 { "#f59e0b" } else { "#ef4444" };
                                                    let method_color = match ev.method.as_str() { "POST" | "PUT" | "PATCH" => "#f59e0b", "DELETE" => "#ef4444", _ => "#60a5fa" };
                                                    view! {
                                                        <div class="log-row lvl-info" style="cursor: pointer"
                                                            on:click=move |_| set_selected_proxy_event.set(Some(ev_sel.clone()))>
                                                            <span class="log-time" style={format!("color: {}; font-weight: 700; min-width: 50px", method_color)}>{ev.method.clone()}</span>
                                                            <span class="log-msg" style="flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap">{ev.full_url.clone()}</span>
                                                            <span style={format!("color: {}; font-size: 11px; margin-left: 8px", badge_color)}>{ev.status}</span>
                                                        </div>
                                                    }
                                                }}
                                            />
                                        </div>
                                    </div>
                                    <div class="glass-card dash-col-side" style="flex: 1; overflow-y: auto">
                                        <h3>"Request Detail"</h3>
                                        {move || match selected_proxy_event.get() {
                                            None => view! { <div style="color: var(--text-muted)">"Select a request to inspect"</div> }.into_view(),
                                            Some(ev) => view! {
                                                <div style="font-size: 12px; display: flex; flex-direction: column; gap: 8px">
                                                    <div><strong>"URL: "</strong>{ev.full_url.clone()}</div>
                                                    <div><strong>"Status: "</strong>{ev.status}</div>
                                                    {ev.content_type.clone().map(|ct| view! { <div><strong>"Content-Type: "</strong>{ct}</div> })}
                                                    {ev.user_agent.clone().map(|ua| view! { <div><strong>"User-Agent: "</strong>{ua}</div> })}
                                                    {ev.referer.clone().map(|r| view! { <div><strong>"Referer: "</strong>{r}</div> })}
                                                    {ev.response_content_type.clone().map(|ct| view! { <div><strong>"Response Content-Type: "</strong>{ct}</div> })}
                                                    {ev.response_content_length.clone().map(|cl| view! { <div><strong>"Response Content-Length: "</strong>{cl}</div> })}
                                                    {ev.request_body.clone().map(|body| view! {
                                                        <div>
                                                            <div style="margin-top: 8px">
                                                                <strong>"Request Body"</strong>
                                                                {if ev.request_body_truncated { " (truncated at 64 KB)" } else { "" }}
                                                                ":"
                                                            </div>
                                                            <div style="background: #000; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 11px; word-break: break-all; white-space: pre-wrap; max-height: 200px; overflow-y: auto">
                                                                {body}
                                                            </div>
                                                        </div>
                                                    })}
                                                    {ev.response_body.clone().map(|body| view! {
                                                        <div>
                                                            <div style="margin-top: 8px">
                                                                <strong>"Response Body"</strong>
                                                                {if ev.response_body_truncated { " (truncated at 64 KB)" } else { "" }}
                                                                ":"
                                                            </div>
                                                            <div style="background: #000; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 11px; word-break: break-all; white-space: pre-wrap; max-height: 200px; overflow-y: auto">
                                                                {body}
                                                            </div>
                                                        </div>
                                                    })}
                                                </div>
                                            }.into_view(),
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
                                        <div class="input-group">
                                            <label style="display: flex; align-items: center; gap: 10px">
                                                <input
                                                    type="checkbox"
                                                    prop:checked=move || settings.get().save_all_logs
                                                    on:change=move |ev| {
                                                        set_settings.update(|s| s.save_all_logs = event_target_checked(&ev));
                                                    }
                                                />
                                                "Save all logs to disk"
                                            </label>
                                        </div>
                                        <div class="input-group">
                                            <label style="display: flex; align-items: center; gap: 10px">
                                                <input
                                                    type="checkbox"
                                                    prop:checked=move || settings.get().prune_old_logs
                                                    on:change=move |ev| {
                                                        set_settings.update(|s| s.prune_old_logs = event_target_checked(&ev));
                                                    }
                                                />
                                                "Remove old logs from the GUI when the list gets too large"
                                            </label>
                                        </div>
                                        <div class="input-group">
                                            <label>"Maximum visible logs"</label>
                                            <input
                                                type="number"
                                                min="1"
                                                prop:value=move || settings.get().max_visible_logs.to_string()
                                                on:input=move |ev| {
                                                    if let Ok(value) = event_target_value(&ev).parse::<usize>() {
                                                        set_settings.update(|s| s.max_visible_logs = value.max(1));
                                                    }
                                                }
                                            />
                                        </div>
                                        <div class="input-group">
                                            <label style="display: flex; align-items: center; gap: 10px">
                                                <input
                                                    type="checkbox"
                                                    prop:checked=move || settings.get().late_blocking_mode
                                                    on:change=move |ev| {
                                                        set_settings.update(|s| s.late_blocking_mode = event_target_checked(&ev));
                                                    }
                                                />
                                                "Late blocking mode"
                                            </label>
                                        </div>
                                        <div class="input-group">
                                            <label style="display: flex; align-items: center; gap: 10px">
                                                <input
                                                    type="checkbox"
                                                    prop:checked=move || settings.get().headless_mode
                                                    on:change=move |ev| {
                                                        set_settings.update(|s| s.headless_mode = event_target_checked(&ev));
                                                    }
                                                />
                                                "Headless mode (hide main window on start)"
                                            </label>
                                        </div>
                                        <div class="input-group">
                                            <label style="display: flex; align-items: center; gap: 10px">
                                                <input
                                                    type="checkbox"
                                                    prop:checked=move || settings.get().log_mode
                                                    on:change=move |ev| {
                                                        set_settings.update(|s| s.log_mode = event_target_checked(&ev));
                                                    }
                                                />
                                                "Log mode (log all packets, including forwarded)"
                                            </label>
                                        </div>
                                        <div class="input-group">
                                            <label style="display: flex; align-items: center; gap: 10px">
                                                <input
                                                    type="checkbox"
                                                    prop:checked=move || settings.get().no_alert_mode
                                                    on:change=move |ev| {
                                                        set_settings.update(|s| s.no_alert_mode = event_target_checked(&ev));
                                                    }
                                                />
                                                <span>
                                                    "No-alert mode "
                                                    <span style="color: var(--accent-orange); font-size: 11px; font-weight: 700">"[not recommended — skips firewall decision prompts for testing]"</span>
                                                </span>
                                            </label>
                                        </div>
                                        <p style="margin: 8px 0 18px 0; color: var(--text-muted); font-size: 12px; line-height: 1.5">
                                            "Saved logs stay on disk. GUI pruning only controls how many entries remain visible in the on-screen log list."
                                        </p>
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
    set_pending_app: WriteSignal<Option<PendingApp>>,
) -> impl IntoView {
    // Poll the backend every second to keep queue_position/queue_total accurate.
    create_effect(move |_| {
        set_interval(move || {
            spawn_local(async move {
                let res = invoke("get_active_alert", JsValue::NULL).await;
                if let Ok(app_opt) = serde_wasm_bindgen::from_value::<Option<PendingApp>>(res) {
                    set_pending_app.set(app_opt);
                }
            });
        }, Duration::from_millis(1000));
    });

    let next_alert_action = move || {
        spawn_local(async move {
            let _ = invoke("next_alert", JsValue::NULL).await;
        });
    };

    let prev_alert_action = move || {
        spawn_local(async move {
            let _ = invoke("previous_alert", JsValue::NULL).await;
        });
    };

    let resolve_decision_internal = move |name: String, path: String, decision: String| {
        spawn_local(async move {
            // Prioritize path for "Always Allow" (TRUST)
            let identifier = if (decision == "allow_always" || decision == "block") && !path.trim().is_empty() && !path.eq_ignore_ascii_case("unknown") {
                path
            } else {
                name
            };

            let args = serde_wasm_bindgen::to_value(&ResolveArgs { name: identifier, decision }).unwrap();
            let _ = invoke("resolve_app_decision", args).await;
            
            // Close via backend command for reliability
            let _ = invoke("close_window", JsValue::NULL).await;
        });
    };

    view! {
        <div class="alert-window-root">
             <div class="alert-window-header">
                 <div class="alert-window-brand"> <div class="dragon-icon"></div> "HYDRADRAGON" </div>
                 <div class="alert-window-meta">
                     {move || pending_app.get().and_then(|app| {
                         let n = next_alert_action.clone();
                         let p = prev_alert_action.clone();
                         Some(view! {
                             <div style="display: flex; align-items: center; gap: 8px">
                                 <div class="alert-nav-controls" style="display: flex; gap: 4px; margin-right: 4px">
                                     <button class="nav-arrow" title="Previous Alert" on:click=move |_| p() style="background: rgba(255,255,255,0.1); border: none; color: #fff; cursor: pointer; padding: 2px 6px; border-radius: 4px; font-size: 10px"> "❮" </button>
                                     <button class="nav-arrow" title="Next Alert" on:click=move |_| n() style="background: rgba(255,255,255,0.1); border: none; color: #fff; cursor: pointer; padding: 2px 6px; border-radius: 4px; font-size: 10px"> "❯" </button>
                                 </div>
                                 <div class="alert-window-count">
                                     {format!("{}/{}", app.queue_position.max(1), app.queue_total)}
                                 </div>
                             </div>
                         })
                     })}
                     <div class="alert-window-tag">"THREAT INTERCEPTED"</div>
                 </div>
             </div>
             <div class="alert-window-body">
                 {move || pending_app.get().map(|app| {
                     let n1 = app.name.clone(); let n2 = app.name.clone(); let n3 = app.name.clone(); let n4 = app.name.clone();
                     let res1 = resolve_decision_internal.clone(); let res2 = resolve_decision_internal.clone(); let res3 = resolve_decision_internal.clone(); let res4 = resolve_decision_internal.clone();
                     let is_registry_alert = app.alert_kind.as_deref() == Some("registry");
                     let is_owlyshield_alert = app.alert_source.as_deref() == Some("owlyshield");
                     let is_website_alert = app.alert_source.as_deref() == Some("website")
                         || app.alert_kind.as_deref() == Some("malicious_website")
                         || app.decision_key.as_deref().map(|value| value.starts_with("website:")).unwrap_or(false);
                     let is_behavior_alert = is_owlyshield_alert && !is_registry_alert;
                     let title = if is_registry_alert {
                         "Registry protection triggered".to_string()
                     } else if is_website_alert {
                         app.full_url
                             .clone()
                             .or_else(|| app.target.clone())
                             .or_else(|| app.hostname.clone())
                             .map(|value| format!("Malicious website detected: {}", value))
                             .unwrap_or_else(|| format!("Malicious website detected in {}", app.name))
                     } else if is_behavior_alert {
                         format!("Behavioral threat detected in {}", app.name)
                     } else if let Some(ref h) = app.hostname {
                         format!("{} wants connection", h)
                     } else {
                         app.name.clone()
                     };
                     let description = if is_registry_alert {
                         app.reason
                             .clone()
                             .filter(|value| !value.trim().is_empty())
                             .unwrap_or_else(|| format!("{} is attempting a protected registry modification.", app.name))
                     } else if is_website_alert {
                         app.reason
                             .clone()
                             .filter(|value| !value.trim().is_empty())
                             .unwrap_or_else(|| "The request matched the website intelligence feeds and is waiting for your decision.".to_string())
                     } else if is_behavior_alert {
                         app.reason
                             .clone()
                             .filter(|value| !value.trim().is_empty())
                             .unwrap_or_else(|| format!("{} triggered a behavioral detection.", app.name))
                     } else {
                         format!(
                             "{} is attempting network access.",
                             if app.hostname.is_some() {
                                 app.name.clone()
                             } else {
                                 "System intercept".to_string()
                             }
                         )
                     };
                     let target_label = if is_registry_alert {
                         "Registry:"
                     } else if is_website_alert {
                         "URL:"
                     } else if is_behavior_alert {
                         "Detection:"
                     } else {
                         "Target:"
                     };
                     let target_value = if is_registry_alert {
                         app.target
                             .clone()
                             .filter(|value| !value.trim().is_empty())
                             .unwrap_or_else(|| "Protected registry target".to_string())
                     } else if is_website_alert {
                         app.full_url
                             .clone()
                             .filter(|value| !value.trim().is_empty())
                             .or_else(|| app.target.clone().filter(|value| !value.trim().is_empty()))
                             .or_else(|| app.hostname.clone().filter(|value| !value.trim().is_empty()))
                             .unwrap_or_else(|| format!("{}:{} ({})", app.dst_ip, app.dst_port, match app.protocol {
                                 Protocol::TCP => "TCP",
                                 Protocol::UDP => "UDP",
                                 Protocol::ICMP => "ICMP",
                                 Protocol::Raw(_) => "RAW",
                             }))
                     } else if is_behavior_alert {
                         app.target
                             .clone()
                             .filter(|value| !value.trim().is_empty())
                             .unwrap_or_else(|| app.alert_kind.clone().unwrap_or_else(|| "Behavioral Threat".to_string()))
                     } else {
                         format!(
                             "{}:{} ({})",
                             app.dst_ip,
                             app.dst_port,
                             match app.protocol {
                                 Protocol::TCP => "TCP",
                                 Protocol::UDP => "UDP",
                                 Protocol::ICMP => "ICMP",
                                 Protocol::Raw(_) => "RAW",
                             }
                         )
                     };
                     view! {
                         <div class="alert-window-scroll">
                             <div class="alert-content-grid" style="margin-top: 0">
                                 <div class="alert-info-container">
                                      <h2 class="alert-title" style="margin-bottom: 5px">
                                          {title}
                                      </h2>
                                      <div class="alert-desc" style="margin-bottom: 8px">
                                          {description}
                                      </div>
                                      <div class="alert-details-box">
                                          <div class="detail-row"> <span class="detail-label">{target_label}</span> <span class="detail-value" title=target_value.clone()>{target_value}</span> </div>
                                          <div class="detail-row"> <span class="detail-label">"Path:"</span> <span class="detail-value path" title=app.path.clone()>{app.path.clone()}</span> </div>
                                          {app.http_method.clone().filter(|value| !value.trim().is_empty()).map(|value| view! {
                                              <div class="detail-row"> <span class="detail-label">"Method:"</span> <span class="detail-value">{value}</span> </div>
                                          })}
                                          {app.hostname.clone().filter(|value| !value.trim().is_empty()).map(|value| view! {
                                              <div class="detail-row"> <span class="detail-label">"Host:"</span> <span class="detail-value" title=value.clone()>{value}</span> </div>
                                          })}
                                          {app.http_referer.clone().filter(|value| !value.trim().is_empty()).map(|value| view! {
                                              <div class="detail-row"> <span class="detail-label">"Referer:"</span> <span class="detail-value path" title=value.clone()>{value}</span> </div>
                                          })}
                                          {app.http_content_type.clone().filter(|value| !value.trim().is_empty()).map(|value| view! {
                                              <div class="detail-row"> <span class="detail-label">"Content-Type:"</span> <span class="detail-value" title=value.clone()>{value}</span> </div>
                                          })}
                                          {app.detected_file_type.clone().filter(|value| !value.trim().is_empty()).map(|value| view! {
                                              <div class="detail-row"> <span class="detail-label">"File Type:"</span> <span class="detail-value">{value}</span> </div>
                                          })}
                                      </div>
                                      {app.http_request_body.clone().filter(|value| !value.trim().is_empty()).map(|value| view! {
                                          <div class="alert-details-box" style="margin-top: 12px;">
                                              <div class="detail-row" style="display: block;">
                                                  <span class="detail-label">"Request Body:"</span>
                                                  <pre class="detail-value path" style="display: block; white-space: pre-wrap; max-height: 140px; overflow: auto; margin-top: 6px;">{value}</pre>
                                              </div>
                                          </div>
                                      })}
                                      {app.http_response_body.clone().filter(|value| !value.trim().is_empty()).map(|value| view! {
                                          <div class="alert-details-box" style="margin-top: 12px;">
                                              <div class="detail-row" style="display: block;">
                                                  <span class="detail-label">"Response Body:"</span>
                                                  <pre class="detail-value path" style="display: block; white-space: pre-wrap; max-height: 140px; overflow: auto; margin-top: 6px;">{value}</pre>
                                              </div>
                                          </div>
                                      })}
                                      {app.packet_json.clone().filter(|value| !value.trim().is_empty()).map(|value| view! {
                                          <div class="alert-details-box" style="margin-top: 12px;">
                                              <div class="detail-row" style="display: block;">
                                                  <span class="detail-label">"Packet JSON:"</span>
                                                  <pre class="detail-value path" style="display: block; white-space: pre-wrap; max-height: 180px; overflow: auto; margin-top: 6px;">{value}</pre>
                                              </div>
                                          </div>
                                      })}
                                 </div>
                             </div>
                         </div>
                         <div class="alert-footer-actions">
                                                           <button class="alert-btn block" on:click={let p = app.path.clone(); move |_| res3(n3.clone(), p.clone(), "block".to_string())}> "BLOCK" </button>
                                                           <button class="alert-btn quarantine" on:click={let p = app.path.clone(); move |_| res4(n4.clone(), p.clone(), "quarantine".to_string())}> "QUARANTINE" </button>
                                                           <button class="alert-btn session" on:click={let p = app.path.clone(); move |_| res1(n1.clone(), p.clone(), "allow_once".to_string())}> "ONCE" </button>
                                                           <button class="alert-btn always" on:click={let p = app.path.clone(); move |_| res2(n2.clone(), p.clone(), "allow_always".to_string())}> "TRUST" </button>
                         </div>
                     }
                 })}
             </div>
        </div>
    }
}
