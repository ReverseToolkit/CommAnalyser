//! Attach injection for CommAnalyser.
//!
//! M0 defines the session API and process checks.  The ptrace/PIC-loader
//! implementation lands in M1; see `docs/01-plan.md` §3.6.

use ca_core::{Error, Result};

/// Whether injection is supported on this build target.
pub const fn supported() -> bool {
    cfg!(target_os = "android") || cfg!(target_os = "linux")
}

#[derive(Clone, Debug)]
pub struct AttachOptions {
    pub pid: u32,
    /// Path or memfd name of the agent library.
    pub agent: String,
    /// Entrypoint symbol, default `ca_agent_main`.
    pub entrypoint: String,
}

impl AttachOptions {
    pub fn new(pid: u32, agent: impl Into<String>) -> Self {
        Self {
            pid,
            agent: agent.into(),
            entrypoint: "ca_agent_main".to_owned(),
        }
    }
}

/// An injected agent session.
#[derive(Debug)]
pub struct Session {
    pub pid: u32,
    pub agent_base: usize,
}

/// Attach to `pid` and load the agent.  M1.
pub fn attach(options: &AttachOptions) -> Result<Session> {
    if options.pid == 0 {
        return Err(Error::Parse("attach: pid 0".into()));
    }
    if !std::path::Path::new("/proc")
        .join(options.pid.to_string())
        .exists()
    {
        return Err(Error::NotFound(format!("pid {}", options.pid)));
    }
    Err(Error::Unsupported("attach injection: M1"))
}

/// Check that a pid exists and is not a zombie.
pub fn pid_alive(pid: u32) -> bool {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"));
    match stat {
        Ok(text) => {
            // state is the char after the final ')'.
            text.rfind(')')
                .and_then(|i| text.as_bytes().get(i + 2).copied())
                .is_some_and(|c| c != b'Z')
        }
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
