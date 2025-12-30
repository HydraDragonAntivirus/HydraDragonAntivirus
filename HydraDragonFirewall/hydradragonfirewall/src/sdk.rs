use crate::engine::{PacketInfo, FirewallSettings, Protocol};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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

#[derive(Clone, Debug)]
pub struct PacketContext {
    pub process_id: u32,
    pub process_name: String,
    pub process_path: String,
}

/// Trait for components that passively listen to/log network traffic.
pub trait PacketListener: Send + Sync {
    fn on_packet(&self, data: &[u8], info: &PacketInfo, context: &PacketContext);
}

/// Trait for components that can modify network packets.
pub trait PacketChanger: Send + Sync {
    /// Modify packet data. Returns true if modification occurred.
    fn modify(&self, data: &mut Vec<u8>, info: &PacketInfo, context: &PacketContext) -> bool;
}

/// Trait for security signatures that evaluate packet payloads for threats.
pub trait SecuritySignature: Send + Sync {
    /// Evaluate the payload. Returns Some(reason) if a threat is detected.
    fn evaluate(&self, data: &[u8], settings: &FirewallSettings, context: &PacketContext) -> Option<String>;
    
    /// Unique name/identifier for this signature.
    fn name(&self) -> &str;
}

pub struct SdkRegistry {
    pub listeners: Vec<Arc<dyn PacketListener>>,
    pub changers: Vec<Arc<dyn PacketChanger>>,
    pub signatures: Vec<Arc<dyn SecuritySignature>>,
}

impl SdkRegistry {
    pub fn new() -> Self {
        Self {
            listeners: Vec::new(),
            changers: Vec::new(),
            signatures: Vec::new(),
        }
    }

    pub fn register_listener(&mut self, listener: Arc<dyn PacketListener>) {
        self.listeners.push(listener);
    }

    pub fn register_changer(&mut self, changer: Arc<dyn PacketChanger>) {
        self.changers.push(changer);
    }

    pub fn register_signature(&mut self, signature: Arc<dyn SecuritySignature>) {
        self.signatures.push(signature);
    }
}

// Example implementation of a signature that could replace the hardcoded Discord check
pub struct DiscordWebhookSignature;

impl SecuritySignature for DiscordWebhookSignature {
    fn evaluate(&self, data: &[u8], _settings: &FirewallSettings, context: &PacketContext) -> Option<String> {
        let text = String::from_utf8_lossy(data);
        if text.contains("discordapp.com/api/webhooks") || text.contains("discord.com/api/webhooks") {
            return Some(format!("Discord Webhook detected in {} ({})", context.process_name, context.process_id));
        }
        None
    }

    fn name(&self) -> &str {
        "DiscordWebhook"
    }
}
