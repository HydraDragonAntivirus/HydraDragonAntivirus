use leptos::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "core"], catch)]
    async fn invoke(cmd: &str, args: JsValue) -> Result<JsValue, JsValue>;
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ComponentStatus {
    pub name: String,
    pub running: bool,
    pub gui_visible: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct LauncherSettings {
    pub owlyshield_verbose_logging: bool,
}

#[derive(Serialize)]
struct ComponentArgs {
    name: String,
}

#[derive(Serialize)]
struct ToggleGuiArgs {
    component: String,
    show: bool,
}

#[derive(Serialize)]
struct VerboseLoggingArgs {
    enabled: bool,
}

fn js_error_to_string(error: JsValue) -> String {
    error
        .as_string()
        .or_else(|| {
            js_sys::JSON::stringify(&error)
                .ok()
                .and_then(|value| value.as_string())
        })
        .unwrap_or_else(|| "Failed to update Owlyshield verbose logging.".to_string())
}

#[component]
fn App() -> impl IntoView {
    let (statuses, set_statuses) = create_signal(Vec::<ComponentStatus>::new());
    let (settings, set_settings) = create_signal(LauncherSettings {
        owlyshield_verbose_logging: false,
    });
    let (settings_error, set_settings_error) = create_signal(Option::<String>::None);
    let (is_dark, set_is_dark) = create_signal(true);

    // Fetch status helper
    let fetch_status = move || {
        spawn_local(async move {
            if let Ok(res) = invoke("get_components_status", JsValue::NULL).await {
                if let Ok(parsed) = serde_wasm_bindgen::from_value::<Vec<ComponentStatus>>(res) {
                    set_statuses.set(parsed);
                }
            }
        });
    };

    let fetch_settings = move || {
        spawn_local(async move {
            if let Ok(res) = invoke("get_launcher_settings", JsValue::NULL).await {
                if let Ok(parsed) = serde_wasm_bindgen::from_value::<LauncherSettings>(res) {
                    set_settings.set(parsed);
                }
            }
        });
    };

    // Initial load
    fetch_status();
    fetch_settings();

    // Set interval for periodic status updates (every 1.5 seconds)
    let fetch_clone = fetch_status.clone();
    use std::time::Duration;
    leptos::set_interval(
        move || {
            fetch_clone();
        },
        Duration::from_millis(1500),
    );

    // Start component helper
    let start_comp = move |name: String| {
        let name_clone = name.clone();
        spawn_local(async move {
            let args = serde_wasm_bindgen::to_value(&ComponentArgs { name: name_clone }).unwrap();
            let _ = invoke("start_component", args).await;
            fetch_status();
        });
    };

    // Stop component helper
    let stop_comp = move |name: String| {
        let name_clone = name.clone();
        spawn_local(async move {
            let args = serde_wasm_bindgen::to_value(&ComponentArgs { name: name_clone }).unwrap();
            let _ = invoke("stop_component", args).await;
            fetch_status();
        });
    };

    // Toggle GUI visibility helper
    let toggle_gui = move |component: String, show: bool| {
        let comp_clone = component.clone();
        spawn_local(async move {
            let args = serde_wasm_bindgen::to_value(&ToggleGuiArgs {
                component: comp_clone,
                show,
            })
            .unwrap();
            let _ = invoke("toggle_gui_visibility", args).await;
            fetch_status();
        });
    };

    let set_owlyshield_verbose = move |enabled: bool| {
        set_settings_error.set(None);
        set_settings.update(|current| current.owlyshield_verbose_logging = enabled);
        spawn_local(async move {
            let args = serde_wasm_bindgen::to_value(&VerboseLoggingArgs { enabled }).unwrap();
            if let Err(error) = invoke("set_owlyshield_verbose_logging", args).await {
                set_settings.update(|current| current.owlyshield_verbose_logging = !enabled);
                set_settings_error.set(Some(js_error_to_string(error)));
            }
            fetch_settings();
            fetch_status();
        });
    };

    // Start all components
    let start_all = move |_| {
        spawn_local(async move {
            let _ = invoke("start_all_components", JsValue::NULL).await;
            fetch_status();
        });
    };

    // Stop all components
    let stop_all = move |_| {
        spawn_local(async move {
            let _ = invoke("stop_all_components", JsValue::NULL).await;
            fetch_status();
        });
    };

    // Quit launcher
    let quit_launcher = move |_| {
        spawn_local(async move {
            let _ = invoke("quit_launcher", JsValue::NULL).await;
        });
    };

    // Descriptions mapper
    let get_desc = |name: &str| -> &'static str {
        match name {
            "Owlyshield" => "Behavioral ransomware blocking & filesystem interceptor service.",
            "Firewall" => "Real-time network traffic packet inspection and filter engine.",
            "AV Engine" => "High-performance static threat signature analysis scanner.",
            "Python Engine" => "AI model & advanced heuristics execution server.",
            "OpenEDR" => "Endpoint Event Detection and telemetry collection agent.",
            "Sanctum" => "Kernel-mode PPL protection and system integrity monitor.",
            _ => "HydraDragon security component.",
        }
    };

    view! {
        <div class=move || if is_dark.get() { "app-container" } else { "app-container light-theme" }>
            // Header
            <header class="app-header">
                <div class="brand-section">
                    <svg class="brand-logo" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                    </svg>
                    <span class="brand-title">"HYDRADRAGON"</span>
                    <span class="brand-badge">"CONTROLLER"</span>
                </div>
                <div class="header-actions">
                    <button class="btn btn-secondary" on:click=move |_| set_is_dark.set(!is_dark.get())>
                        {move || if is_dark.get() { "☀️ Light" } else { "🌙 Dark" }}
                    </button>
                    <button class="btn btn-secondary" on:click=start_all>"Start All"</button>
                    <button class="btn btn-danger" on:click=stop_all style="border-color: rgba(255,62,62,0.2); color: var(--accent-red)">"Stop All"</button>
                </div>
            </header>

            <section class="settings-strip">
                <div class="setting-meta">
                    <span class="setting-title">"Owlyshield verbose logging"</span>
                    <span class=move || {
                        if settings.get().owlyshield_verbose_logging {
                            "setting-state enabled"
                        } else {
                            "setting-state"
                        }
                    }>
                        {move || if settings.get().owlyshield_verbose_logging { "Enabled" } else { "Disabled" }}
                    </span>
                    {move || settings_error.get().map(|message| view! {
                        <span class="setting-error">{message}</span>
                    })}
                </div>
                <label class="toggle-switch">
                    <input
                        type="checkbox"
                        prop:checked=move || settings.get().owlyshield_verbose_logging
                        on:change=move |ev| set_owlyshield_verbose(event_target_checked(&ev))
                    />
                    <span class="toggle-track"></span>
                </label>
            </section>

            // Main Dashboard Grid
            <main class="dashboard-grid">
                {move || statuses.get().into_iter().map(|comp| {
                    let name = comp.name.clone();
                    let name_for_start = name.clone();
                    let name_for_stop = name.clone();
                    let name_for_gui = name.clone();
                    let desc = get_desc(&comp.name);
                    let is_running = comp.running;
                    let is_gui_visible = comp.gui_visible.unwrap_or(false);

                    view! {
                        <div class=format!("component-card {}", if is_running { "running" } else { "stopped" })>
                            <div>
                                <div class="component-header">
                                    <span class="component-name">{name.clone()}</span>
                                    <span class=format!("status-pill {}", if is_running { "running" } else { "stopped" })>
                                        <span class=format!("status-dot {}", if is_running { "pulse" } else { "" })></span>
                                        {if is_running { "Running" } else { "Stopped" }}
                                    </span>
                                </div>
                                <div class="component-desc">{desc}</div>
                            </div>

                            <div class="card-actions">
                                <div style="display: flex; gap: 8px;">
                                    {if is_running {
                                        view! {
                                            <button class="btn btn-danger" on:click=move |_| stop_comp(name_for_stop.clone())>
                                                "Stop"
                                            </button>
                                        }.into_view()
                                    } else {
                                        view! {
                                            <button class="btn btn-primary" on:click=move |_| start_comp(name_for_start.clone())>
                                                "Start"
                                            </button>
                                        }.into_view()
                                    }}
                                </div>

                                {if comp.gui_visible.is_some() && is_running {
                                    view! {
                                        <button
                                            class=format!("btn btn-gui-toggle {}", if is_gui_visible { "visible" } else { "" })
                                            on:click=move |_| toggle_gui(name_for_gui.clone(), !is_gui_visible)
                                        >
                                            {if is_gui_visible {
                                                "Hide GUI"
                                            } else {
                                                "Show GUI"
                                            }}
                                        </button>
                                    }.into_view()
                                } else {
                                    view! { <div></div> }.into_view()
                                }}
                            </div>
                        </div>
                    }
                }).collect::<Vec<_>>()}
            </main>

            // Footer
            <footer class="app-footer">
                <div class="global-status">
                    <span class="status-dot pulse" style="color: var(--accent-green)"></span>
                    <span>"Launcher service running as Administrator."</span>
                </div>
                <div class="footer-controls">
                    <button class="btn btn-secondary" on:click=quit_launcher style="border-color: rgba(255,59,48,0.2); color: var(--accent-red)">
                        "Exit & Stop All Services"
                    </button>
                </div>
            </footer>
        </div>
    }
}

fn main() {
    console_error_panic_hook::set_once();
    mount_to_body(|| view! { <App /> });
}
