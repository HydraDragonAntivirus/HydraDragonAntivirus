use std::error::Error;
use std::fmt::{Debug, Formatter};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::time::SystemTime;

use chrono::{DateTime, Local};
use log::{error, warn};

use crate::config::{Config, Param};
use crate::connectors::register::Connectors;
use crate::predictions::prediction::input_tensors::VecvecCappedF32;
use crate::process::{ProcessRecord, ProcessState};
use crate::logging::Logging;
use crate::utils::{FILE_TIME_FORMAT, LONG_TIME_FORMAT};

/// New struct to hold detailed threat information.
#[derive(Debug, Clone)]
pub struct ThreatInfo<'a> {
    pub threat_type_label: &'a str, // e.g., "Ransomware", "Malware", "PUA"
    pub virus_name: &'a str,      // e.g., "Behavioural Detection", "Trojan.Generic"
    pub prediction: f32,
}

pub struct ActionsOnKill {
    actions: Vec<Box<dyn ActionOnKill>>,
}

pub struct WriteReportFile();
pub struct WriteReportHtmlFile();

pub trait ActionOnKill {
    fn run(
        &self,
        config: &Config,
        proc: &ProcessRecord,
        pred_mtrx: &VecvecCappedF32,
        // MODIFIED: Use ThreatInfo struct
        threat_info: &ThreatInfo,
        now: &str,
    ) -> Result<(), Box<dyn Error>>;
}

impl ActionsOnKill {
    pub fn new() -> ActionsOnKill {
        ActionsOnKill {
            actions: vec![
                Box::new(WriteReportFile()),
                Box::new(WriteReportHtmlFile()),
                Box::new(Connectors),
                Box::new(Logging),
            ],
        }
    }

    /// NEW run_actions_with_info: The main logic, now takes ThreatInfo
    pub fn run_actions_with_info(
        &self,
        config: &Config,
        proc: &ProcessRecord,
        pred_mtrx: &VecvecCappedF32,
        threat_info: &ThreatInfo, // Takes the new struct
    ) {
        let now = (DateTime::from(SystemTime::now()) as DateTime<Local>)
            .format(FILE_TIME_FORMAT)
            .to_string();
        for action in &self.actions {
            action
                // MODIFIED: Pass threat_info
                .run(config, proc, pred_mtrx, threat_info, &now)
                .unwrap_or_else(|e| {
                    Logging::error(format!("Error with post_kill action: {e}").as_str());
                });
        }
    }
}

impl ActionOnKill for WriteReportFile {
    fn run(
        &self,
        config: &Config,
        proc: &ProcessRecord,
        _pred_mtrx: &VecvecCappedF32,
        // MODIFIED: Use ThreatInfo
        threat_info: &ThreatInfo,
        now: &str,
    ) -> Result<(), Box<dyn Error>> {
        let report_dir = Path::new(&config[Param::ConfigPath]).join("threats");
        if !report_dir.exists() {
            error!(
                "Cannot Write report file: dir does not exist: {}",
                report_dir.to_str().unwrap()
            );
            Logging::error(format!("Cannot Write report file: dir does not exist: {}", report_dir.to_str().unwrap()).as_str());
        } else {
            let basename = Path::new(&proc.appname).file_name().unwrap().to_str().unwrap();
            let temp = report_dir.join(Path::new(&format!(
                "{}_{}_report_{}.log",
                &basename,
                now,
                &proc.gid,
            )));
            let report_path = temp.to_str().unwrap_or("");
            println!("{report_path}");
            let mut file = File::create(Path::new(&report_path))?;
            let stime_started: DateTime<Local> = proc.time_started.into();
            file.write_all(b"Owlyshield report file\n\n")?;
            file.write_all(
                // MODIFIED: Use threat_type_label
                format!("{} detected running from: {}\n\n", threat_info.threat_type_label, proc.appname).as_bytes(),
            )?;
            file.write_all(
                format!("Started at {}\n", stime_started.format(LONG_TIME_FORMAT)).as_bytes(),
            )?;
            file.write_all(
                format!(
                    "Killed at {}\n\n",
                    DateTime::<Local>::from(proc.time_killed.unwrap_or_else(SystemTime::now))
                        .format(LONG_TIME_FORMAT)
                )
                .as_bytes(),
            )?;
            // MODIFIED: Add virus_name and use prediction from struct
            file.write_all(format!("Detection: {}\n", threat_info.virus_name).as_bytes())?;
            file.write_all(format!("Certainty: {}\n\n", threat_info.prediction).as_bytes())?;
            file.write_all(b"Files modified:\n")?;
            for f in &proc.fpaths_updated {
                file.write_all(format!("\t{f:?}\n").as_bytes())?;
            }
        }
        Ok(())
    }
}

impl ActionOnKill for WriteReportHtmlFile {
    fn run(
        &self,
        config: &Config,
        proc: &ProcessRecord,
        _pred_mtrx: &VecvecCappedF32,
        // MODIFIED: Use ThreatInfo
        threat_info: &ThreatInfo,
        now: &str,
    ) -> Result<(), Box<dyn Error>> {
        let report_dir = Path::new(&config[Param::ConfigPath]).join("threats");
        if !report_dir.exists() {
            error!(
                "Cannot Write report file: dir does not exist: {}",
                report_dir.to_str().unwrap()
            );
            Logging::error(format!("Cannot Write report file: dir does not exist: {}", report_dir.to_str().unwrap()).as_str());
        } else {
            let basename = Path::new(&proc.appname).file_name().unwrap().to_str().unwrap();
            let temp = match proc.process_state {
                ProcessState::Suspended => report_dir.join(Path::new(&format!(
                    "~{}_{}_report_{}.html",
                    &basename,
                    now,
                    &proc.gid,
                ))),
                _ => report_dir.join(Path::new(&format!(
                    "{}_{}_report_{}.html",
                    &basename,
                    now,
                    &proc.gid,
                ))),
            };

            let report_path = temp.to_str().unwrap_or("");
            println!("{report_path}");
            let mut file = File::create(Path::new(&report_path))?;
            let stime_started: DateTime<Local> = proc.time_started.into();
            file.write_all(b"<!DOCTYPE html><html><head>")?;
            file.write_all(format!("<title>Owlyshield Report {}</title><link rel='icon' href='https://static.thenounproject.com/png/3420953-200.png'/><meta name='viewport' content='width=device-width, initial-scale=1'/>\n", proc.gid).as_bytes())?;
            file.write_all(b"<style>body{font-family: Arial;}.tab{overflow: hidden;border: 1px solid #ccc;background-color: #f1f1f1;}.tab button{background-color: inherit;    float: inherit;    border: none;    outline: none;    cursor: pointer;    padding: 14px 16px;    transition: 0.3s;    font-size: 17px;    width: 33%;}.tab button:hover{    background-color: #ddd;}.tab button.active{	background-color: #ccc;}.tabcontent{	display: none;	padding: 6px 12px;/*border: 1px solid #ccc;border-top: none;*/}table{	width: 80%;	align: center;	margin-left: auto;	margin-right: auto;}th{	background-color: red;}select{	width: 100%;    align: center;	margin-left: auto;	margin-right: auto;}</style>")?;
            file.write_all(b"</head><body>\n")?;
            // MODIFIED: Use threat_type_label
            file.write_all(
                format!("<table><tr><th><h1><b>Owlyshield detected a </b><span style='color: white;'>{}</span><b>!</b></h1></th></tr></table>\n", 
                threat_info.threat_type_label).as_bytes()
            )?;
            // MODIFIED: Use threat_type_label and add Detection (virus_name)
            file.write_all(format!(
                "<br/><table><tr><td style='text-align: center;'><h3>{} detected running from: <span style='color: red;' id='fullPath'>{}</span></h3></td></tr><tr valign='top'><td style='text-align: left;'><ul><li>Process State:<b id='processState'> {}</b></li> <li>Started on<b id='startDate'> {}</b></li><li>Killed on<b id='killedDate'> {}</b></li><li>GID: <b id='gid'> {}</b></li><li>Detection: <b id='detection'> {}</b></li><li>Certainty: <b id='certainty'> {}</b></li></ul></td></tr></table>\n", 
                threat_info.threat_type_label, // 1. Threat Type
                proc.exepath.to_string_lossy(), // 2. Path
                proc.process_state, // 3. State
                stime_started.format(LONG_TIME_FORMAT), // 4. Start time
                DateTime::<Local>::from(proc.time_killed.unwrap_or_else(SystemTime::now)).format(LONG_TIME_FORMAT), // 5. Kill time
                proc.gid, // 6. GID
                threat_info.virus_name, // 7. Virus Name
                threat_info.prediction // 8. Certainty
            ).as_bytes())?;
            file.write_all(b"<table><tr><td><div class='tab'>\n")?;
            file.write_all(format!("<button class='tablinks' onclick=\"openTab(event,'files_u')\">Files updated ({})</button>\n", &proc.fpaths_updated.len()).as_bytes())?;
            file.write_all(format!("<button class='tablinks' onclick=\"openTab(event,'files_c')\">Files created ({})</button>\n", &proc.fpaths_created.len()).as_bytes())?;
            file.write_all(b"</div></td></tr></table>\n")?;
            file.write_all(b"<div id='files_u' class='tabcontent'><table><tr><td><select name='files_u' size='30' multiple='multiple'>\n")?;
            for f in &proc.fpaths_updated {
                file.write_all(format!("<option value='{f}'>{f}</option>\n").as_bytes())?;
            }
            file.write_all(b"</select></td></tr></table></div>\n")?;
            file.write_all(b"<div id='files_c' class='tabcontent'><table><tr><td><select name='files_c' size='30' multiple='multiple'>\n")?;
            for f in &proc.fpaths_created {
                file.write_all(format!("<option value='{f}'>{f}</option>\n").as_bytes())?;
            }
            file.write_all(b"</select></td></tr></table></div>\n")?;
            file.write_all(b"<script>function openTab(evt, tab) {	var i, tabcontent, tablinks;	tabcontent = document.getElementsByClassName('tabcontent');	for (i = 0; i != tabcontent.length; i++) {		tabcontent[i].style.display = 'none';	}	tablinks = document.getElementsByClassName('tablinks');	for (i = 0; i != tablinks.length; i++) {		tablinks[i].className = tablinks[i].className.replace(' active', '');	}	document.getElementById(tab).style.display = 'block';	evt.currentTarget.className += ' active';}document.getElementById('defaultOpen').click();</script>\n")?;
            file.write_all(b"</body></html>")?;
        }
        Ok(())
    }
}

impl ActionOnKill for Connectors {
    fn run(
        &self,
        config: &Config,
        proc: &ProcessRecord,
        _pred_mtrx: &VecvecCappedF32,
        // MODIFIED: Use ThreatInfo
        threat_info: &ThreatInfo,
        _now: &str,
    ) -> Result<(), Box<dyn Error>> {
        // MODIFIED: Use prediction from struct
        Connectors::on_event_kill(config, proc, threat_info.prediction);
        Ok(())
    }
}

impl ActionOnKill for Logging {
    fn run(
        &self,
        _config: &Config,
        proc: &ProcessRecord,
        _pred_mtrx: &VecvecCappedF32,
        // MODIFIED: Use ThreatInfo
        threat_info: &ThreatInfo,
        _now: &str
    ) -> Result<(), Box<dyn Error>> {
        let stime_started: DateTime<Local> = proc.time_started.into();
        // MODIFIED: Use details from threat_info
        let msg = format!("{} detected running from: {}[{}] with certainty {} (detection: {}) (started at {})", 
            threat_info.threat_type_label, 
            proc.appname, 
            proc.gid, 
            threat_info.prediction, 
            threat_info.virus_name, 
            stime_started.format(LONG_TIME_FORMAT)
        );
        Logging::alert(msg.as_str());
        warn!("ALERT: {}", msg);
        Ok(())
    }
}

impl Debug for ActionsOnKill {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActionsOnKill").finish()
    }
}
