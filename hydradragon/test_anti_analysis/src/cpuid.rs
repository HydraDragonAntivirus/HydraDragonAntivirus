//! CPUID-based hypervisor detection module
//! 
//! Detects Hyper-V and other hypervisors using CPUID instructions

use crate::{Result, SignatureMonsterError};

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::__cpuid;
#[cfg(target_arch = "x86")]
use core::arch::x86::__cpuid;

/// CPUID checker for hypervisor detection
pub struct CpuidChecker;

impl CpuidChecker {
    pub fn new() -> Self {
        Self
    }

    /// Check if running under any hypervisor using CPUID leaf 0x1
    pub fn is_hypervisor_present(&self) -> bool {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        unsafe {
            let result = __cpuid(0x1);
            // Bit 31 of ECX indicates hypervisor presence
            (result.ecx & (1 << 31)) != 0
        }
        
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        false
    }

    /// Get hypervisor vendor string (CPUID leaf 0x40000000)
    pub fn get_hypervisor_vendor(&self) -> Result<String> {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        unsafe {
            if !self.is_hypervisor_present() {
                return Err(SignatureMonsterError::Generic("No hypervisor detected".to_string()));
            }

            let result = __cpuid(0x40000000);
            
            // The vendor string is in EBX, ECX, EDX (12 bytes total)
            let mut vendor = Vec::with_capacity(12);
            vendor.extend_from_slice(&result.ebx.to_le_bytes());
            vendor.extend_from_slice(&result.ecx.to_le_bytes());
            vendor.extend_from_slice(&result.edx.to_le_bytes());
            
            String::from_utf8(vendor)
                .map_err(|e| SignatureMonsterError::Generic(format!("Invalid UTF-8 in vendor string: {}", e)))
        }
        
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        Err(SignatureMonsterError::Generic("CPUID not supported on this architecture".to_string()))
    }

    /// Check specifically for Hyper-V using CPUID leaf 0x40000001
    /// Hyper-V signature: EAX = 0x31237648 ("Hv#1")
    pub fn is_hyperv(&self) -> bool {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        unsafe {
            if !self.is_hypervisor_present() {
                return false;
            }

            // Check vendor string first
            if let Ok(vendor) = self.get_hypervisor_vendor() {
                if vendor != "Microsoft Hv" {
                    return false;
                }
            }

            // Check CPUID leaf 0x40000001 for Hyper-V signature
            let result = __cpuid(0x40000001);
            result.eax == 0x31237648  // "Hv#1"
        }
        
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        false
    }

    /// Check for VMware hypervisor
    pub fn is_vmware(&self) -> bool {
        if let Ok(vendor) = self.get_hypervisor_vendor() {
            vendor.starts_with("VMwareVMware")
        } else {
            false
        }
    }

    /// Check for KVM hypervisor
    pub fn is_kvm(&self) -> bool {
        if let Ok(vendor) = self.get_hypervisor_vendor() {
            vendor == "KVMKVMKVM\0\0\0"
        } else {
            false
        }
    }

    /// Check for Xen hypervisor
    pub fn is_xen(&self) -> bool {
        if let Ok(vendor) = self.get_hypervisor_vendor() {
            vendor.starts_with("XenVMMXenVMM")
        } else {
            false
        }
    }

    /// Check for VirtualBox
    pub fn is_virtualbox(&self) -> bool {
        if let Ok(vendor) = self.get_hypervisor_vendor() {
            vendor.starts_with("VBoxVBoxVBox")
        } else {
            false
        }
    }

    /// Check for Parallels
    pub fn is_parallels(&self) -> bool {
        if let Ok(vendor) = self.get_hypervisor_vendor() {
            vendor.starts_with("prl hyperv")
        } else {
            false
        }
    }

    /// Get detailed hypervisor information
    pub fn get_hypervisor_info(&self) -> Result<HypervisorInfo> {
        if !self.is_hypervisor_present() {
            return Err(SignatureMonsterError::Generic("No hypervisor detected".to_string()));
        }

        let vendor = self.get_hypervisor_vendor()?;
        let hypervisor_type = self.identify_hypervisor(&vendor);

        Ok(HypervisorInfo {
            vendor,
            hypervisor_type,
            is_hyperv: self.is_hyperv(),
        })
    }

    fn identify_hypervisor(&self, vendor: &str) -> HypervisorType {
        if vendor == "Microsoft Hv" {
            HypervisorType::HyperV
        } else if vendor.starts_with("VMwareVMware") {
            HypervisorType::VMware
        } else if vendor == "KVMKVMKVM\0\0\0" {
            HypervisorType::KVM
        } else if vendor.starts_with("XenVMMXenVMM") {
            HypervisorType::Xen
        } else if vendor.starts_with("VBoxVBoxVBox") {
            HypervisorType::VirtualBox
        } else if vendor.starts_with("prl hyperv") {
            HypervisorType::Parallels
        } else {
            HypervisorType::Unknown
        }
    }
}

impl Default for CpuidChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct HypervisorInfo {
    pub vendor: String,
    pub hypervisor_type: HypervisorType,
    pub is_hyperv: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HypervisorType {
    HyperV,
    VMware,
    VirtualBox,
    KVM,
    Xen,
    Parallels,
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hypervisor_detection() {
        let checker = CpuidChecker::new();
        
        println!("Hypervisor present: {}", checker.is_hypervisor_present());
        
        if let Ok(vendor) = checker.get_hypervisor_vendor() {
            println!("Hypervisor vendor: {}", vendor);
        }
        
        if let Ok(info) = checker.get_hypervisor_info() {
            println!("Hypervisor type: {:?}", info.hypervisor_type);
            println!("Is Hyper-V: {}", info.is_hyperv);
        }
    }
}
