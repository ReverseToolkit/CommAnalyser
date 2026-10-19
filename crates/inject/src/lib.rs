//! Attach and spawn injection for CommAnalyser.
//!
//! The agent `.so` is mapped by the 自定义linker in [`loader`]: PT_LOAD +
//! reloc + init, not bionic `dlopen`.  Spawn starts a package or executable
//! and runs the same inject session on the new pid.

pub mod elf;
pub mod loader;
pub mod ptrace;
pub mod remote;
pub mod session;
pub mod spawn;

#[cfg(test)]
use runtime::Error;

pub use session::{attach, Session};
pub use spawn::{pids_named, start_executable, start_package};

/// Whether injection is supported on this build target.
pub const fn supported() -> bool {
    cfg!(target_os = "android") || cfg!(target_os = "linux")
}

#[derive(Clone, Debug)]
pub struct AttachOptions {
    pub pid: u32,
    /// Path to the agent `.so` on the device.
    pub agent: String,
    /// Entrypoint symbol, default `agent_main`.
    pub entrypoint: String,
    /// Abstract socket name the agent should connect to.
    pub config: String,
}

impl AttachOptions {
    pub fn new(pid: u32, agent: impl Into<String>) -> Self {
        Self {
            pid,
            agent: agent.into(),
            entrypoint: "agent_main".to_owned(),
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
        let options = AttachOptions::new(1, "agent.so").with_config("sock");
        assert_eq!(options.pid, 1);
        assert_eq!(options.agent, "agent.so");
        assert_eq!(options.entrypoint, "agent_main");
        assert_eq!(options.config, "sock");
        assert!(supported());
        let missing =
            attach(&AttachOptions::new(u32::MAX, "agent.so").with_config("sock")).unwrap_err();
        assert!(matches!(missing, Error::NotFound(_)));
    }
}
