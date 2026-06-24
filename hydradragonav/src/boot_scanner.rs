#![cfg(windows)]

use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct BootSectorDetection {
    pub device: String,
    pub sector_type: String,
    pub details: String,
    pub raw_bytes: Vec<u8>,
}

/// Scan MBR/VBR of all physical drives and bootable volumes.
pub fn scan_boot_sectors() -> Vec<BootSectorDetection> {
    let mut results = Vec::new();

    // Scan physical drives (MBR/GPT)
    for i in 0..8u32 {
        let device = format!(r"\\.\PhysicalDrive{}", i);
        scan_physical_drive_mbr(&device, &mut results);
    }

    // Scan system/boot volumes' VBR
    let volumes = [r"\\.\C:", r"\\.\D:"];
    for vol in &volumes {
        let label = vol.trim_start_matches(r"\\.\").trim_end_matches(':');
        scan_volume_vbr(vol, label, &mut results);
    }

    // Also check SystemDrive env var
    if let Ok(sys) = std::env::var("SystemDrive") {
        let vol = format!(r"\\.\{}", sys.trim_end_matches('\\'));
        if !vol.contains('C') && !vol.contains('D') {
            scan_volume_vbr(&vol, sys.trim_end_matches(':'), &mut results);
        }
    }

    results
}

fn scan_physical_drive_mbr(device: &str, results: &mut Vec<BootSectorDetection>) {
    let mut f = match File::open(device) {
        Ok(f) => f,
        Err(_) => return,
    };

    let mut mbr = [0u8; 512];
    if f.read_exact(&mut mbr).is_err() {
        return;
    }

    let sig = u16::from_le_bytes([mbr[510], mbr[511]]);
    let details = if sig == 0xAA55 {
        let mut desc = format!("MBR with valid boot signature (0xAA55)");
        let oem = String::from_utf8_lossy(&mbr[3..11]);
        let oem_clean: String = oem.chars().filter(|c| c.is_ascii_graphic()).collect();
        if !oem_clean.is_empty() && oem_clean != "NTFS    " {
            desc.push_str(&format!(" [OEM: {}]", oem_clean));
        }
        desc
    } else {
        format!("MBR with unknown boot signature (0x{sig:04X})")
    };

    results.push(BootSectorDetection {
        device: device.to_string(),
        sector_type: "MBR".into(),
        details,
        raw_bytes: mbr.to_vec(),
    });

    // Read partition table entries
    for i in 0..4 {
        let offset = 446 + i * 16;
        if offset + 15 >= 512 {
            break;
        }
        let status = mbr[offset];
        let ptype = mbr[offset + 4];
        let start_lba = u32::from_le_bytes([
            mbr[offset + 8],
            mbr[offset + 9],
            mbr[offset + 10],
            mbr[offset + 11],
        ]);
        let sector_count = u32::from_le_bytes([
            mbr[offset + 12],
            mbr[offset + 13],
            mbr[offset + 14],
            mbr[offset + 15],
        ]);

        if ptype != 0 && sector_count > 0 {
            let bootable = if status == 0x80 { " (bootable)" } else { "" };
            let type_desc = partition_type_desc(ptype);
            results.push(BootSectorDetection {
                device: format!("{} partition {}", device, i + 1),
                sector_type: format!("Partition{}{}", bootable, type_desc),
                details: format!(
                    "type 0x{ptype:02X}, LBA start {}, {} sectors (~{} MB)",
                    start_lba,
                    sector_count,
                    (sector_count as u64 * 512) / (1024 * 1024)
                ),
                raw_bytes: Vec::new(),
            });
        }
    }
}

fn scan_volume_vbr(volume: &str, label: &str, results: &mut Vec<BootSectorDetection>) {
    // Check drive type via path presence — avoid removable drives
    let drive_root = format!("{}\\", label);
    if Path::new(&drive_root).exists() {
        // Skip if it looks like a removable drive (optional heuristic)
        let meta = match std::fs::metadata(&drive_root) {
            Ok(m) => m,
            Err(_) => return,
        };
        if meta.len() == 0 {
            // Possibly a removable drive with no media — skip
            return;
        }
    }

    let mut f = match File::open(volume) {
        Ok(f) => f,
        Err(_) => return,
    };

    let mut vbr = [0u8; 512];
    if f.read_exact(&mut vbr).is_err() {
        return;
    }

    let sig = u16::from_le_bytes([vbr[510], vbr[511]]);
    if sig != 0xAA55 {
        results.push(BootSectorDetection {
            device: volume.to_string(),
            sector_type: format!("VBR ({})", label),
            details: format!("{}: VBR with invalid boot signature (0x{sig:04X})", label),
            raw_bytes: vbr.to_vec(),
        });
        return;
    }

    let oem = String::from_utf8_lossy(&vbr[3..11]);
    let oem_clean: String = oem.chars().filter(|c| c.is_ascii_graphic()).collect();
    let mut desc = format!("{}: VBR (OEM: {})", label, oem_clean);

    // Detect filesystem type from boot sector
    if vbr[0..3] == [0xEB, 0x52, 0x90] && &vbr[3..11] == b"NTFS    " {
        desc.push_str(" [NTFS]");
    } else if vbr[0..3] == [0xEB, 0x3C, 0x90] {
        desc.push_str(" [FAT32]");
    } else if vbr[0..3] == [0xEB, 0x58, 0x90] {
        desc.push_str(" [FAT12/FAT16]");
    } else if vbr[0..2] == [0xEB, 0x3C] {
        desc.push_str(" [FAT32/exFAT]");
    }

    results.push(BootSectorDetection {
        device: volume.to_string(),
        sector_type: format!("VBR ({})", label),
        details: desc,
        raw_bytes: vbr.to_vec(),
    });
}

fn partition_type_desc(ptype: u8) -> &'static str {
    match ptype {
        0x01 => " FAT12",
        0x04 => " FAT16",
        0x05 => " Extended",
        0x06 => " FAT16B",
        0x07 => " NTFS/exFAT",
        0x0B => " FAT32",
        0x0C => " FAT32 LBA",
        0x0E => " FAT16B LBA",
        0x0F => " Extended LBA",
        0x11 => " Hidden FAT12",
        0x12 => " Config (Dell/OEM)",
        0x14 => " Hidden FAT16",
        0x16 => " Hidden FAT16B",
        0x1B => " Hidden FAT32",
        0x1C => " Hidden FAT32 LBA",
        0x1E => " Hidden FAT16B LBA",
        0x27 => " Windows RE",
        0x42 => " Dynamic/Windows LDM",
        0x63 => " Unix",
        0x82 => " Linux swap",
        0x83 => " Linux native",
        0x8E => " Linux LVM",
        0xA0 => " Laptop hibernate",
        0xA5 => " FreeBSD",
        0xAB => " Mac OS X boot",
        0xAF => " Mac OS X HFS+",
        0xEE => " GPT protective",
        0xEF => " EFI System (ESP)",
        0xFB => " VMware VMFS",
        _ => "",
    }
}
