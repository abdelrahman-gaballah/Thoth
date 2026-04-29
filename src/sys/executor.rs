use std::process::Command;
use crate::AuraResult;

pub struct SystemExecutor;

impl SystemExecutor {
    pub fn execute(cmd: &str) -> AuraResult<String> {
        // تنفيذ الأمر في الـ Shell بتاع اللينكس
        let output = Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .output()?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Ok(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }
}
