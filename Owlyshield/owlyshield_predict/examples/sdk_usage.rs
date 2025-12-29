//! Example usage of the OwlyShield SDK
//!
//! This example demonstrates how to use the SDK for:
//! 1. Behavioral signature detection
//! 2. Malware pattern matching
//! 3. Machine learning data collection

use owlyshield_ransom::sdk::{OwlyShieldSDK, CollectionMode};
use owlyshield_ransom::shared_def::IOMessage;
use owlyshield_ransom::process::ProcessRecord;
use std::path::PathBuf;

fn main() {
    // Example 1: Basic signature detection
    example_signature_detection();

    // Example 2: Machine learning data collection
    example_ml_collection();

    // Example 3: Real-time threat analysis
    example_realtime_analysis();
}

/// Example 1: Basic behavioral signature detection
fn example_signature_detection() {
    println!("=== Example 1: Behavioral Signature Detection ===\n");

    // Initialize SDK with ML collection disabled
    let mut sdk = OwlyShieldSDK::new(
        false,  // ML mode disabled
        "models/malapi.json"
    );

    // Simulate processing messages from kernel driver
    // In real usage, these would come from the kernel driver

    println!("SDK initialized successfully!");
    println!("Ready to process kernel driver messages for threat detection.\n");
}

/// Example 2: Machine learning data collection
fn example_ml_collection() {
    println!("=== Example 2: Machine Learning Data Collection ===\n");

    // Initialize SDK with ML collection enabled
    let mut sdk = OwlyShieldSDK::new(
        true,  // ML mode enabled
        "models/malapi.json"
    );

    println!("ML data collection mode enabled!");
    println!("The SDK will now collect comprehensive behavioral data from:");
    println!("  - Malicious processes (for training)");
    println!("  - Benign processes (for training)");
    println!();

    // After collecting data, export it
    match sdk.export_ml_data("ml_data/collected_dataset.json") {
        Ok(_) => println!("ML dataset exported successfully!"),
        Err(e) => println!("Failed to export ML data: {}", e),
    }

    println!();
}

/// Example 3: Real-time threat analysis
fn example_realtime_analysis() {
    println!("=== Example 3: Real-time Threat Analysis ===\n");

    let mut sdk = OwlyShieldSDK::new(false, "models/malapi.json");

    // Simulate a GID (process group ID) for analysis
    let gid = 12345u64;

    // Get detailed analysis for a process
    if let Some(analysis) = sdk.get_analysis(gid) {
        println!("Threat Analysis for GID {}:", gid);
        println!("  Process: {}", analysis.app_name);
        println!("  Threat Level: {:?}", analysis.threat_level);
        println!("  Signatures Matched: {}", analysis.signatures_matched.len());
        println!("  Patterns Matched: {:?}", analysis.patterns_matched);
        println!();

        // Display matched signatures
        for sig_match in &analysis.signatures_matched {
            println!("  [{:?}] {}", sig_match.threat_level, sig_match.signature_name);
            println!("    Confidence: {:.2}%", sig_match.confidence * 100.0);
            println!("    Description: {}", sig_match.description);
            println!("    Recommended Action: {}", sig_match.recommended_action);
            println!("    Matched Behaviors:");
            for behavior in &sig_match.matched_behaviors {
                println!("      - {}", behavior);
            }
            println!();
        }
    }
}

/// Example 4: Integration with kernel driver
#[allow(dead_code)]
fn example_kernel_integration() {
    println!("=== Example 4: Kernel Driver Integration ===\n");

    let mut sdk = OwlyShieldSDK::new(true, "models/malapi.json");

    // In a real implementation, you would:
    // 1. Initialize the kernel driver connection
    // 2. Start receiving IOMessage events from the driver
    // 3. Process each message through the SDK
    // 4. Take action based on threat detections

    println!("Integration pattern:");
    println!("  1. Kernel driver sends IOMessage");
    println!("  2. SDK processes message with process_message()");
    println!("  3. SDK returns true if malicious behavior detected");
    println!("  4. Your code can then:");
    println!("     - Suspend the process");
    println!("     - Terminate the process");
    println!("     - Alert the user");
    println!("     - Log the incident");
    println!();
}

/// Example 5: Custom signature creation
#[allow(dead_code)]
fn example_custom_signatures() {
    use owlyshield_ransom::sdk::behavioral_signature::{BehavioralSignature, ThreatLevel};

    println!("=== Example 5: Custom Signature Creation ===\n");

    let mut sdk = OwlyShieldSDK::new(false, "models/malapi.json");

    // Create a custom signature for detecting a specific threat
    let custom_signature = BehavioralSignature {
        name: "Custom Backdoor Pattern".to_string(),
        description: "Detects a specific backdoor implementation".to_string(),
        threat_level: ThreatLevel::Critical,
        required_api_categories: vec!["internet".to_string(), "helper".to_string()],
        required_apis: vec![
            "WSAStartup".to_string(),
            "Socket".to_string(),
            "Bind".to_string(),
            "Listen".to_string(),
        ],
        min_files_written: Some(1),
        min_files_deleted: None,
        min_files_encrypted: None,
        requires_mass_file_ops: None,
        requires_network_activity: Some(true),
        requires_process_injection: None,
        requires_privilege_escalation: None,
        required_dlls: vec![],
        suspicious_dll_patterns: vec!["ws2_32".to_string()],
        suspicious_extensions: vec![],
        required_api_sequences: vec![
            ("Socket".to_string(), "Bind".to_string()),
            ("Bind".to_string(), "Listen".to_string()),
        ],
        min_confidence: 0.75,
    };

    if let Some(engine) = sdk.signature_engine.as_mut() {
        engine.add_signature(custom_signature);
    } else {
        println!("Signature engine is disabled; cannot add custom signatures in this configuration.");
    }

    println!("Custom signature added successfully!");
    println!("The SDK will now detect this specific backdoor pattern.");
    println!();
}

/// Example 6: Analyzing specific malware families
#[allow(dead_code)]
fn example_malware_family_detection() {
    use owlyshield_ransom::sdk::PatternType;

    println!("=== Example 6: Malware Family Detection ===\n");

    println!("Supported malware patterns:");
    println!("  - RAT (Remote Access Trojan)");
    println!("  - Ransomware");
    println!("  - Keylogger");
    println!("  - Banking Trojan");
    println!("  - Credential Stealer");
    println!("  - Process Hollowing");
    println!("  - Cryptominer");
    println!("  - Botnet Client");
    println!();

    println!("Each pattern includes specific:");
    println!("  - Mandatory APIs (must all be present)");
    println!("  - Required APIs (N of M must be present)");
    println!("  - Behavioral indicators");
    println!("  - Network indicators");
    println!("  - DLL requirements");
    println!();
}

/// Example 7: Exporting ML data for model training
#[allow(dead_code)]
fn example_export_ml_data() {
    println!("=== Example 7: Exporting ML Data ===\n");

    let sdk = OwlyShieldSDK::new(true, "models/malapi.json");

    // Export to JSON (full dataset with all features)
    match sdk.export_ml_data("datasets/full_dataset.json") {
        Ok(_) => println!("✓ JSON dataset exported"),
        Err(e) => println!("✗ JSON export failed: {}", e),
    }

    // Export to CSV (for easy analysis in Python/R)
    if let Some(ref collector) = sdk.ml_collector {
        match collector.export_to_csv("datasets/full_dataset.csv") {
            Ok(_) => println!("✓ CSV dataset exported"),
            Err(e) => println!("✗ CSV export failed: {}", e),
        }

        // Export separated datasets
        match collector.export_separated(
            "datasets/malicious.json",
            "datasets/benign.json"
        ) {
            Ok(_) => println!("✓ Separated datasets exported"),
            Err(e) => println!("✗ Separated export failed: {}", e),
        }

        let (malicious_count, benign_count) = collector.get_counts();
        println!();
        println!("Dataset statistics:");
        println!("  Malicious samples: {}", malicious_count);
        println!("  Benign samples: {}", benign_count);
        println!("  Total samples: {}", malicious_count + benign_count);
    }

    println!();
}
