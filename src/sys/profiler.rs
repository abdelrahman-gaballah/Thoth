//! System Profiler Module
//!
//! Provides zero-copy, zero-dependency hardware and OS detection for Linux.
//! Parses pseudo-filesystems (`/proc`, `/sys`) directly using standard
//! library I/O to minimize overhead and binary size.

use std::pin::Pin;

use crate::{AuraError, AuraModule, AuraResult};

/// Represents a point-in-time snapshot of the system's hardware and OS state.
///
/// All fields are owned strings/u64 to allow the snapshot to outlive
/// the profiler and be passed safely across async boundaries.
#[derive(Debug, Clone)]
pub struct SystemInfo {
    /// The human-readable distribution name (e.g., "Linux Mint", "Ubuntu").
    pub os_name: String,
    /// The distribution version ID (e.g., "21.2", "22.04").
    pub os_version: String,
    /// The kernel release version (e.g., "5.15.0-76-generic").
    pub kernel_version: String,
    /// The CPU model name as reported by the hardware (e.g., "AMD Ryzen 9 7950X").
    pub cpu_model: String,
    /// Total physical system memory in bytes.
    pub total_memory: u64,
}

/// Profiler for detecting system capabilities and hardware constraints.
///
/// Designed to be initialized once at startup. It reads from `/proc` and
/// `/etc/os-release` during initialization and caches the result for
/// high-performance, zero-alloc access later via [`get_system_snapshot`].
pub struct Profiler {
    snapshot: Option<SystemInfo>,
}

impl AuraModule for Profiler {
    fn new() -> Self {
        Self { snapshot: None }
    }

    fn initialize(&mut self) -> Pin<Box<dyn std::future::Future<Output = AuraResult<()>> + Send + '_>> {
        Box::pin(async move {
            self.snapshot = Some(self.collect_system_info()?);
            Ok(())
        })
    }
}

impl Profiler {
    /// Retrieves the cached system snapshot.
    ///
    /// # Errors
    ///
    /// Returns an [`AuraError::Profiler`] if called before [`AuraModule::initialize`]
    /// has successfully completed.
    pub fn get_system_snapshot(&self) -> AuraResult<&SystemInfo> {
        self.snapshot
            .as_ref()
            .ok_or_else(|| AuraError::Profiler("Profiler has not been initialized".into()))
    }

    /// Performs the actual collection of system metrics from the filesystem.
    fn collect_system_info(&self) -> AuraResult<SystemInfo> {
        let (os_name, os_version) = parse_os_release()?;
        let kernel_version = parse_kernel_version()?;
        let cpu_model = parse_cpu_model()?;
        let total_memory = parse_total_memory()?;

        Ok(SystemInfo {
            os_name,
            os_version,
            kernel_version,
            cpu_model,
            total_memory,
        })
    }
}

/// Parses `/etc/os-release` to extract the distribution name and version.
///
/// Safety is ensured by strictly splitting on `=` and stripping quotes,
/// avoiding any unsafe string manipulation or shell execution.
fn parse_os_release() -> AuraResult<(String, String)> {
    let content =
        std::fs::read_to_string("/etc/os-release").map_err(|e| {
            AuraError::Profiler(format!("Failed to read /etc/os-release: {}", e))
        })?;

    let mut name = String::from("Unknown Linux");
    let mut version = String::from("Unknown");

    // Iterate using byte-level line splitting for performance
    for line in content.lines() {
        let line = line.trim();
        if let Some(val) = line.strip_prefix("NAME=") {
            name = strip_quotes(val).to_string();
        } else if let Some(val) = line.strip_prefix("VERSION_ID=") {
            version = strip_quotes(val).to_string();
        }
    }

    Ok((name, version))
}

/// Reads the kernel version directly from the `/proc/sys/kernel/osrelease` virtual file.
fn parse_kernel_version() -> AuraResult<String> {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .map_err(|e| {
            AuraError::Profiler(format!("Failed to read /proc/sys/kernel/osrelease: {}", e))
        })
}

/// Parses `/proc/cpuinfo` to find the CPU model name.
///
/// Only parses up to the first match of "model name" to avoid unnecessary
/// iteration over redundant core entries, optimizing for performance.
fn parse_cpu_model() -> AuraResult<String> {
    let content = std::fs::read_to_string("/proc/cpuinfo").map_err(|e| {
        AuraError::Profiler(format!("Failed to read /proc/cpuinfo: {}", e))
    })?;

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("model name") {
            // Line format: "model name\t: AMD Ryzen 9 7950X 16-Core Processor"
            if let Some(model) = rest.split(':').nth(1) {
                return Ok(model.trim().to_string());
            }
        }
    }

    Ok("Unknown CPU".to_string())
}

/// Parses `/proc/meminfo` to determine total physical RAM.
///
/// Returns the value in bytes. The file reports in kB, so we multiply by 1024.
fn parse_total_memory() -> AuraResult<u64> {
    let content = std::fs::read_to_string("/proc/meminfo").map_err(|e| {
        AuraError::Profiler(format!("Failed to read /proc/meminfo: {}", e))
    })?;

    for line in content.lines() {
        if line.starts_with("MemTotal:") {
            // Line format: "MemTotal:       16384000 kB"
            let mut parts = line.split_whitespace();
            
            // Skip "MemTotal:"
            parts.next();
            
            if let Some(kb_str) = parts.next() {
                let kb: u64 = kb_str.parse().map_err(|e| {
                    AuraError::Profiler(format!("Failed to parse MemTotal integer: {}", e))
                })?;
                
                // Convert kB to Bytes
                return Ok(kb * 1024);
            }
        }
    }

    Err(AuraError::Profiler(
        "Could not find MemTotal entry in /proc/meminfo".into(),
    ))
}

/// Strips surrounding double or single quotes from a string slice.
#[inline]
fn strip_quotes(s: &str) -> &str {
    s.trim_matches(|c| c == '"' || c == '\'')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_quotes() {
        assert_eq!(strip_quotes("\"Linux Mint\""), "Linux Mint");
        assert_eq!(strip_quotes("'Ubuntu'"), "Ubuntu");
        assert_eq!(strip_quotes("Fedora"), "Fedora");
    }
}
