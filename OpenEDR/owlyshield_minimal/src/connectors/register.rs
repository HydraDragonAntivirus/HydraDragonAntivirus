//! [Connectors] allows to manage the list of [Connector].

use crate::Logging;
use crate::config::Config;
use crate::connectors::connector::Connector;
use crate::process::ProcessRecord;

/// Manages registered connectors. Add custom connectors here.
pub struct Connectors;

impl Connectors {
    fn register_connectors() -> Vec<Box<dyn Connector>> {
        vec![]
    }

    pub fn on_startup(config: &Config) {
        for connector in Connectors::register_connectors() {
            if let Err(e) = connector.on_startup(config) {
                println!("{e}");
                Logging::error(format!("{e}").as_str());
            }
        }
    }

    pub fn on_event_kill(config: &Config, proc: &ProcessRecord, prediction: f32) {
        for connector in Connectors::register_connectors() {
            if let Err(e) = connector.on_event_kill(config, proc, prediction) {
                println!("{e}");
                Logging::error(format!("{e}").as_str());
            }
        }
    }
}
