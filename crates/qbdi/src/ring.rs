//! Fixed-capacity event sink. DBI callbacks never enter JS.

/// Kind of a batched trace event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    Inst,
    Mem,
    Call,
}

/// One instruction, memory, or call-transfer event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceEvent {
    pub kind: EventKind,
    pub pc: u64,
    pub size: u16,
    pub mem_addr: u64,
    pub mem_value: u64,
    pub is_write: bool,
    /// Disassembly, `call module:symbol`, or a printable memory string.
    pub text: String,
}

impl TraceEvent {
    pub fn inst(pc: u64, size: u16, text: String) -> Self {
        Self {
            kind: EventKind::Inst,
            pc,
            size,
            mem_addr: 0,
            mem_value: 0,
            is_write: false,
            text,
        }
    }

    pub fn call(pc: u64, text: String) -> Self {
        Self {
            kind: EventKind::Call,
            pc,
            size: 0,
            mem_addr: 0,
            mem_value: 0,
            is_write: false,
            text,
        }
    }

    pub fn mem(
        pc: u64,
        size: u16,
        mem_addr: u64,
        mem_value: u64,
        is_write: bool,
        text: String,
    ) -> Self {
        Self {
            kind: EventKind::Mem,
            pc,
            size,
            mem_addr,
            mem_value,
            is_write,
            text,
        }
    }
}

/// Ring that drops newest events when full and counts drops.
pub struct EventRing {
    events: Vec<TraceEvent>,
    cap: usize,
    dropped: u64,
}

impl EventRing {
    pub fn new(cap: usize) -> Self {
        Self {
            // No up-front reservation: the cap is a budget, not a promise.
            // Pre-allocating the default 100k events would cost several MiB in
            // the target process before the first instruction executes.
            events: Vec::new(),
            cap: cap.max(1),
            dropped: 0,
        }
    }

    /// Returns whether the event was stored.  A dropped instruction must not
    /// leave "this is the newest event" pointing at the previous one, or the
    /// post-instruction pass appends its registers to the wrong instruction.
    pub fn push(&mut self, event: TraceEvent) -> bool {
        if self.events.len() >= self.cap {
            self.dropped = self.dropped.saturating_add(1);
            return false;
        }
        self.events.push(event);
        true
    }

    /// The most recent event, for the post-instruction pass that appends the
    /// registers an instruction wrote.
    pub fn last_mut(&mut self) -> Option<&mut TraceEvent> {
        self.events.last_mut()
    }

    pub fn drain(&mut self) -> Vec<TraceEvent> {
        std::mem::take(&mut self.events)
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batches_and_drops_when_full() {
        let mut ring = EventRing::new(2);
        ring.push(TraceEvent {
            kind: EventKind::Inst,
            pc: 1,
            size: 4,
            mem_addr: 0,
            mem_value: 0,
            is_write: false,
            text: String::new(),
        });
        ring.push(TraceEvent {
            kind: EventKind::Mem,
            pc: 2,
            size: 8,
            mem_addr: 0x10,
            mem_value: 7,
            is_write: true,
            text: String::new(),
        });
        ring.push(TraceEvent {
            kind: EventKind::Call,
            pc: 3,
            size: 4,
            mem_addr: 0,
            mem_value: 0,
            is_write: false,
            text: String::new(),
        });
        assert_eq!(ring.dropped(), 1);
        // The dropped event must not be addressable through last_mut(): it
        // still points at the previously stored event.
        assert!(ring.last_mut().is_some_and(|last| last.pc == 2));
        let batch = ring.drain();
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].pc, 1);
        assert_eq!(batch[1].kind, EventKind::Mem);
        assert!(ring.is_empty());
    }
}
