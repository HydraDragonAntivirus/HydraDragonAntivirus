use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{error, info, warn};

const BASE_DIR: &str = r"C:\Program Files\HydraDragonAntivirus";

struct Components {
    owlyshield: Option<Child>,
    firewall: Option<Child>,
    av_engine: Option<Child>,
    python_engine: Option<Child>,
}

impl Components {
    fn new() -> Self {
        Self {
            owlyshield: None,
            firewall: None,
            av_engine: None,
            python_engine: None,
        }
    }

    fn kill_all(&mut self) {
        for (name, child) in [
            ("Owlyshield", &mut self.owlyshield),
            ("Firewall", &mut self.firewall),
            ("AV Engine", &mut self.av_engine),
            ("Python Engine", &mut self.python_engine),
        ] {
            if let Some(mut proc) = child.take() {
                info!("Stopping {}", name);
                let _ = proc.kill();
                let _ = proc.wait();
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(false)
        .with_level(true)
        .init();

    info!("HydraDragon Launcher starting...");

    let components = Arc::new(Mutex::new(Components::new()));
    let components_clone = components.clone();

    // Setup Ctrl+C handler
    ctrlc::set_handler(move || {
        info!("Shutdown signal received");
        let components = components_clone.clone();
        tokio::spawn(async move {
            let mut comps = components.lock().await;
            comps.kill_all();
            std::process::exit(0);
        });
    })
    .context("Failed to set Ctrl+C handler")?;

    // Start all components
    if let Err(e) = start_components(components.clone()).await {
        error!("Failed to start components: {:#}", e);
        return Err(e);
    }

    info!("All components started. Press Ctrl+C to stop.");

    // Idle loop
    loop {
        sleep(Duration::from_secs(60)).await;
    }
}

async fn start_components(components: Arc<Mutex<Components>>) -> Result<()> {
    info!("Starting HydraDragon components...");

    // 1. Start Owlyshield
    info!("Starting Owlyshield Service...");
    let owlyshield_path = PathBuf::from(BASE_DIR)
        .join("hydradragon")
        .join("Owlyshield")
        .join("Owlyshield Service")
        .join("owlyshield_ransom.exe");
    
    if let Ok(child) = start_process(&owlyshield_path, None) {
        components.lock().await.owlyshield = Some(child);
        sleep(Duration::from_secs(2)).await;
    }

    // 2. Start Firewall
    info!("Starting HydraDragon Firewall...");
    let firewall_path = PathBuf::from(BASE_DIR)
        .join("hydradragon")
        .join("HydraDragonFirewall")
        .join("hydradragonfirewall.exe");
    
    if let Ok(child) = start_process(&firewall_path, None) {
        components.lock().await.firewall = Some(child);
        sleep(Duration::from_secs(2)).await;
    }

    // 3. Start OpenEDR
    info!("Starting OpenEDR...");
    let openedr_path = PathBuf::from(BASE_DIR).join("OpenEDR").join("edrsvc.exe");
    if openedr_path.exists() {
        let _ = Command::new(&openedr_path)
            .arg("start")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        sleep(Duration::from_secs(2)).await;
    }

    // 4. Start Sanctum sequence
    info!("Starting Sanctum components...");
    start_sanctum_sequence().await?;

    // 5. Start AV Engine
    info!("Starting HydraDragon AV Engine...");
    let av_path = PathBuf::from(BASE_DIR)
        .join("hydradragon")
        .join("HydraDragonAV")
        .join("HydraDragonAV.exe");
    
    if let Ok(child) = start_process(&av_path, None) {
        components.lock().await.av_engine = Some(child);
        sleep(Duration::from_secs(1)).await;
    }

    // 6. Start Python Engine
    info!("Starting HydraDragon Python Engine...");
    let activate_bat = PathBuf::from(BASE_DIR)
        .join("venv")
        .join("Scripts")
        .join("activate.bat");
    
    if activate_bat.exists() {
        let cmd_args = format!(
            "/c \"\"{}\" && poetry run hydradragon\"",
            activate_bat.display()
        );
        
        if let Ok(child) = Command::new("cmd.exe")
            .args(["/c", &cmd_args])
            .current_dir(BASE_DIR)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            components.lock().await.python_engine = Some(child);
        }
    }

    info!("✓ All components started successfully");
    Ok(())
}

async fn start_sanctum_sequence() -> Result<()> {
    let sanctum_dir = PathBuf::from(BASE_DIR).join("hydradragon").join("Sanctum");

    // 1. ELAM Installer
    let elam_path = sanctum_dir.join("elam_installer.exe");
    if elam_path.exists() {
        info!("  → Running ELAM installer...");
        let _ = Command::new(&elam_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        sleep(Duration::from_secs(2)).await;
    }

    // 2. Start Sanctum PPL Runner service
    info!("  → Starting sanctum_ppl_runner service...");
    let _ = Command::new("sc")
        .args(["start", "sanctum_ppl_runner"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    sleep(Duration::from_millis(1500)).await;

    // 3. UM Engine
    let um_path = sanctum_dir.join("um_engine.exe");
    if um_path.exists() {
        info!("  → Starting Sanctum UM Engine...");
        let _ = Command::new(&um_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        sleep(Duration::from_secs(2)).await;
    }

    // 4. GUI App
    let app_path = sanctum_dir.join("app.exe");
    if app_path.exists() {
        info!("  → Starting Sanctum GUI...");
        let _ = Command::new(&app_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        sleep(Duration::from_secs(1)).await;
    }

    Ok(())
}

fn start_process(path: &PathBuf, args: Option<&[&str]>) -> Result<Child> {
    if !path.exists() {
        warn!("Executable not found: {}", path.display());
        anyhow::bail!("File not found");
    }

    let mut cmd = Command::new(path);
    cmd.stdout(Stdio::null()).stderr(Stdio::null());

    if let Some(args) = args {
        cmd.args(args);
    }

    if let Some(dir) = path.parent() {
        cmd.current_dir(dir);
    }

    cmd.spawn().context("Failed to spawn process")
}
