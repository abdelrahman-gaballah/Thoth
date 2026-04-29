// src/sys/mod.rs

//! System profiling and command execution module.

use crate::{AuraModule, AuraResult};
use std::pin::Pin;
pub mod dbus_client;
pub mod executor;

pub mod profiler;

/// Central manager for system-level operations.
pub struct SysManager {
    profiler: profiler::Profiler,
}

impl AuraModule for SysManager {
    fn new() -> Self {
        Self {
            profiler: profiler::Profiler::new(),
        }
    }

    fn initialize(&mut self) -> Pin<Box<dyn std::future::Future<Output = AuraResult<()>> + Send + '_>> {
        Box::pin(async move {
            self.profiler.initialize().await?;
            Ok(())
        })
    }
}
