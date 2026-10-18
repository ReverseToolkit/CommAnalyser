//! Attach injection for CommAnalyser.
//!
//! M1 implements the aarch64 attach path: stop every thread, use remote calls
//! into libc/linker to create a memfd, `dlopen()` the agent, resolve
//! `ca_agent_main`, and call it.  The daemon then waits for the agent's hello
//! before resuming the target.

pub mod elf;
pub mod ptrace;
pub mod remote;
pub mod session;

#[cfg(test)]
use ca_core::Error;

pub use session::{attach, Session};

/// Whether injection is supported on this build target.
pub const fn supported() -> bool {
    cfg!(target_os = "android") || cfg!(target_os = "linux")
}

#[derive(Clone, Debug)]
pub struct AttachOptions {
    pub pid: u32,
    /// Path to the agent `.so` on the device.
    pub agent: String,
    /// Entrypoint symbol, default `ca_agent_main`.
    pub entrypoint: String,
    /// Abstract socket name the agent should connect to.
    pub config: String,
}

impl AttachOptions {
    pub fn new(pid: u32, agent: impl Into<String>) -> Self {
        Self {
            pid,
            agent: agent.into(),
            entrypoint: "ca_agent_main".to_owned(),
            config: String::new(),
        }
    }

    pub fn with_config(mut self, config: impl Into<String>) -> Self {
        self.config = config.into();
        self
    }
}

/// Check that a pid exists and is not a zombie.
pub fn pid_alive(pid: u32) -> bool {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"));
    match stat {
        Ok(text) => text
            .rfind(')')
            .and_then(|i| text.as_bytes().get(i + 2).copied())
            .is_some_and(|c| c != b'Z'),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_is_alive() {
        assert!(pid_alive(std::process::id()));
    }

    #[test]
    fn missing_pid_is_not_alive() {
        assert!(!pid_alive(u32::MAX));
    }

    #[test]
    fn attach_validates_pid() {
        let err = attach(&AttachOptions::new(0, "agent.so")).unwrap_err();
        assert!(matches!(err, Error::Parse(_)));
    }
}
