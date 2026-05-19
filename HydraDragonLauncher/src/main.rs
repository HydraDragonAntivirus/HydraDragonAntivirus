use anyhow::{Context, Result};
use std::env;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{error, info, warn};

const BASE_DIR: &str = r"C:\Program Files\HydraDragonAntivirus";
const DATA_DIR: &str = r"C:\ProgramData\HydraDragonAntivirus";

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

    // Start all components concurrently except Sanctum (which has a specific order)
    let (
        owlyshield_result,
        firewall_result,
        openedr_result,
        av_result,
        python_result,
        sanctum_result,
    ) = tokio::join!(
        start_owlyshield(),
        start_firewall(),
        start_openedr(),
        start_av_engine(),
        start_python_engine(),
        start_sanctum_sequence()
    );

    // Store the child processes
    let mut comps = components.lock().await;
    if let Ok(child) = owlyshield_result {
        comps.owlyshield = child;
    }
    if let Ok(child) = firewall_result {
        comps.firewall = child;
    }
    if let Ok(child) = av_result {
        comps.av_engine = child;
    }
    if let Ok(child) = python_result {
        comps.python_engine = child;
    }
    drop(comps);

    // Check if OpenEDR or Sanctum failed
    openedr_result?;
    sanctum_result?;

    info!("✓ All components started successfully");
    Ok(())
}

async fn start_owlyshield() -> Result<Option<Child>> {
    info!("Starting Owlyshield Service...");
    let owlyshield_path = PathBuf::from(BASE_DIR)
        .join("hydradragon")
        .join("Owlyshield")
        .join("Owlyshield Service")
        .join("owlyshield_ransom.exe");

    match start_process(&owlyshield_path, None) {
        Ok(child) => Ok(Some(child)),
        Err(_) => Ok(None),
    }
}

async fn start_firewall() -> Result<Option<Child>> {
    info!("Starting HydraDragon Firewall...");
    let firewall_path = PathBuf::from(BASE_DIR)
        .join("hydradragon")
        .join("HydraDragonFirewall")
        .join("hydradragonfirewall.exe");

    match start_process(&firewall_path, None) {
        Ok(child) => Ok(Some(child)),
        Err(_) => Ok(None),
    }
}

async fn start_openedr() -> Result<()> {
    info!("Starting OpenEDR...");
    let openedr_path = PathBuf::from(BASE_DIR).join("OpenEDR").join("edrsvc.exe");
    if openedr_path.exists() {
        let _ = Command::new(&openedr_path)
            .arg("start")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }
    Ok(())
}

async fn start_av_engine() -> Result<Option<Child>> {
    info!("Starting HydraDragon AV Engine...");
    let av_path = PathBuf::from(BASE_DIR)
        .join("hydradragon")
        .join("HydraDragonAV")
        .join("HydraDragonAV.exe");

    match start_process(&av_path, None) {
        Ok(child) => Ok(Some(child)),
        Err(_) => Ok(None),
    }
}

async fn start_python_engine() -> Result<Option<Child>> {
    info!("Starting HydraDragon Python Engine...");
    let root_dir = PathBuf::from(BASE_DIR);
    let venv_dir = root_dir.join("venv");
    let venv_scripts = venv_dir.join("Scripts");
    let venv_python = venv_scripts.join("python.exe");
    let poetry_exe = venv_scripts.join("poetry.exe");
    let activate_bat = venv_scripts.join("activate.bat");
    let pyproject = root_dir.join("pyproject.toml");

    if !venv_dir.exists() {
        warn!("Python venv not found: {}", venv_dir.display());
        return Ok(None);
    }
    if !pyproject.exists() {
        warn!("pyproject.toml not found: {}", pyproject.display());
        return Ok(None);
    }

    if venv_python.exists() {
        let mut cmd = Command::new(&venv_python);
        cmd.args(["-m", "poetry", "run", "hydradragon"])
            .current_dir(&root_dir);
        configure_python_command(&mut cmd, &root_dir, &venv_dir)?;
        if let Some(child) =
            spawn_python_candidate(cmd, "venv python -m poetry run hydradragon").await?
        {
            return Ok(Some(child));
        }
    } else {
        warn!("venv python.exe not found: {}", venv_python.display());
    }

    if poetry_exe.exists() {
        let mut cmd = Command::new(&poetry_exe);
        cmd.args(["run", "hydradragon"]).current_dir(&root_dir);
        configure_python_command(&mut cmd, &root_dir, &venv_dir)?;
        if let Some(child) = spawn_python_candidate(cmd, "venv poetry.exe run hydradragon").await? {
            return Ok(Some(child));
        }
    } else {
        warn!("venv poetry.exe not found: {}", poetry_exe.display());
    }

    if activate_bat.exists() {
        let cmd_args = format!(
            "call \"{}\" && poetry run hydradragon",
            activate_bat.display()
        );
        let mut cmd = Command::new("cmd.exe");
        cmd.args(["/d", "/s", "/c", &cmd_args])
            .current_dir(&root_dir);
        configure_python_command(&mut cmd, &root_dir, &venv_dir)?;
        if let Some(child) =
            spawn_python_candidate(cmd, "activate.bat && poetry run hydradragon").await?
        {
            return Ok(Some(child));
        }
    }

    warn!("HydraDragon Python Engine did not stay running. Check hydradragonlauncher-python.log.");
    Ok(None)
}

fn configure_python_command(cmd: &mut Command, root_dir: &Path, venv_dir: &Path) -> Result<()> {
    let scripts_dir = venv_dir.join("Scripts");
    let current_path = env::var_os("PATH").unwrap_or_default();
    let mut path_value = scripts_dir.as_os_str().to_os_string();
    if !current_path.is_empty() {
        path_value.push(";");
        path_value.push(current_path);
    }

    let (stdout_log, stderr_log) = python_engine_log_stdio()?;
    cmd.env("VIRTUAL_ENV", venv_dir)
        .env("PYTHONPATH", root_dir)
        .env("POETRY_VIRTUALENVS_CREATE", "false")
        .env("POETRY_CACHE_DIR", root_dir.join("poetry_cache"))
        .env("POETRY_CONFIG_DIR", root_dir.join("poetry_config"))
        .env("PATH", path_value)
        .stdout(stdout_log)
        .stderr(stderr_log);
    Ok(())
}

fn python_engine_log_stdio() -> Result<(Stdio, Stdio)> {
    let log_path = PathBuf::from(DATA_DIR)
        .join("hydradragon")
        .join("logs")
        .join("hydradragonlauncher-python.log");

    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "Failed to create launcher log directory: {}",
                parent.display()
            )
        })?;
    }

    let stdout_log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("Failed to open launcher log: {}", log_path.display()))?;
    let stderr_log = stdout_log
        .try_clone()
        .context("Failed to clone launcher log handle")?;

    Ok((Stdio::from(stdout_log), Stdio::from(stderr_log)))
}

async fn spawn_python_candidate(mut cmd: Command, label: &str) -> Result<Option<Child>> {
    match cmd.spawn() {
        Ok(mut child) => {
            sleep(Duration::from_secs(2)).await;
            match child
                .try_wait()
                .context("Failed to query Python engine status")?
            {
                Some(status) => {
                    warn!("{} exited immediately with status: {}", label, status);
                    Ok(None)
                }
                None => {
                    info!("Python engine started via {}", label);
                    Ok(Some(child))
                }
            }
        }
        Err(e) => {
            warn!("Failed to start {}: {}", label, e);
            Ok(None)
        }
    }
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
