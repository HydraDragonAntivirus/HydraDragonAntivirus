// module/mod.rs — Module registry.
//
// Ports TinyAntivirus's IModule + IModuleManager + the .plg plugin-loading
// machinery. In Rust there is no COM/CLSID registry; instead, scan modules
// are registered directly as Arc<dyn ScanModule> objects.
//
// The .plg DLL loading concept is preserved as a design comment but not
// implemented (Rust dynamic loading via libloading would be the equivalent;
// left as a future extension).

use crate::error::{AvError, AvResult};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// ModuleType
// ---------------------------------------------------------------------------

/// Mirrors the C++ `ModuleType` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleType {
    Default,
    ScanModule,
}

// ---------------------------------------------------------------------------
// ModuleInfo
// ---------------------------------------------------------------------------

/// Module metadata (ports MODULE_INFO struct).
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub module_type: ModuleType,
    pub name: String,
}

// ---------------------------------------------------------------------------
// Module trait
// ---------------------------------------------------------------------------

/// Base module interface (ports IModule).
/// All scan modules implement this.
pub trait Module: Send + Sync {
    fn module_info(&self) -> ModuleInfo;
    fn module_type(&self) -> ModuleType;
    fn name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// ModuleRegistry
// ---------------------------------------------------------------------------

/// Runtime module registry (ports IModuleManager / CModuleMgrService).
///
/// Modules are registered as Arc<dyn Module> and queried by name or type.
/// This replaces the COM/CLSID factory and the .plg directory scanner.
pub struct ModuleRegistry {
    modules: Vec<Arc<dyn Module>>,
}

impl ModuleRegistry {
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
        }
    }

    /// Register a module. Returns an error if a module with the same name
    /// is already registered.
    pub fn register(&mut self, module: Arc<dyn Module>) -> AvResult<()> {
        let name = module.name().to_owned();
        if self.modules.iter().any(|m| m.name() == name) {
            return Err(AvError::ModuleAlreadyRegistered { name });
        }
        self.modules.push(module);
        Ok(())
    }

    /// Unregister by name. Returns Ok even if the module was not registered.
    pub fn unregister_by_name(&mut self, name: &str) {
        self.modules.retain(|m| m.name() != name);
    }

    /// Unregister all modules of a given type.
    pub fn unregister_by_type(&mut self, ty: ModuleType) {
        self.modules.retain(|m| m.module_type() != ty);
    }

    /// Query modules by exact name. Returns all matching modules (usually one).
    pub fn query_by_name(&self, name: &str) -> Vec<Arc<dyn Module>> {
        self.modules
            .iter()
            .filter(|m| m.name() == name)
            .cloned()
            .collect()
    }

    /// Query modules by type. Pass `ModuleType::Default` to get all modules.
    pub fn query_by_type(&self, ty: ModuleType) -> Vec<Arc<dyn Module>> {
        if ty == ModuleType::Default {
            return self.modules.clone();
        }
        self.modules
            .iter()
            .filter(|m| m.module_type() == ty)
            .cloned()
            .collect()
    }

    /// Total number of registered modules.
    pub fn len(&self) -> usize {
        self.modules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }
}

impl Default for ModuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    struct DummyModule {
        name: String,
        ty: ModuleType,
    }

    impl DummyModule {
        fn new(name: &str, ty: ModuleType) -> Arc<Self> {
            Arc::new(Self {
                name: name.into(),
                ty,
            })
        }
    }

    impl Module for DummyModule {
        fn module_info(&self) -> ModuleInfo {
            ModuleInfo {
                module_type: self.ty,
                name: self.name.clone(),
            }
        }
        fn module_type(&self) -> ModuleType {
            self.ty
        }
        fn name(&self) -> &str {
            &self.name
        }
    }

    #[test]
    fn register_and_query_by_name() {
        let mut reg = ModuleRegistry::new();
        reg.register(DummyModule::new("W32.Sality.PE", ModuleType::ScanModule))
            .unwrap();
        let found = reg.query_by_name("W32.Sality.PE");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name(), "W32.Sality.PE");
    }

    #[test]
    fn duplicate_registration_errors() {
        let mut reg = ModuleRegistry::new();
        reg.register(DummyModule::new("ModA", ModuleType::ScanModule))
            .unwrap();
        let r = reg.register(DummyModule::new("ModA", ModuleType::ScanModule));
        assert!(matches!(r, Err(AvError::ModuleAlreadyRegistered { .. })));
    }

    #[test]
    fn query_by_type_filters() {
        let mut reg = ModuleRegistry::new();
        reg.register(DummyModule::new("A", ModuleType::ScanModule))
            .unwrap();
        reg.register(DummyModule::new("B", ModuleType::Default))
            .unwrap();

        let scanners = reg.query_by_type(ModuleType::ScanModule);
        assert_eq!(scanners.len(), 1);
        assert_eq!(scanners[0].name(), "A");

        let all = reg.query_by_type(ModuleType::Default);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn unregister_by_name() {
        let mut reg = ModuleRegistry::new();
        reg.register(DummyModule::new("ToRemove", ModuleType::ScanModule))
            .unwrap();
        reg.unregister_by_name("ToRemove");
        assert!(reg.query_by_name("ToRemove").is_empty());
    }
}
