//! Fixed-capacity event sink. DBI callbacks never enter JS.

/// Kind of a batched trace event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    Inst,
    Mem,
    Call,
}

/// One instruction, memory, or call-transfer event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceEvent {
    pub kind: EventKind,
    pub pc: u64,
    pub size: u16,
    pub mem_addr: u64,
    pub mem_value: u64,
    pub is_write: bool,
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
            events: Vec::with_capacity(cap),
            cap: cap.max(1),
            dropped: 0,
        }
    }

    pub fn push(&mut self, event: TraceEvent) {
        if self.events.len() >= self.cap {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        self.events.push(event);
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
        });
        ring.push(TraceEvent {
            kind: EventKind::Mem,
            pc: 2,
            size: 8,
            mem_addr: 0x10,
            mem_value: 7,
            is_write: true,
        });
        ring.push(TraceEvent {
            kind: EventKind::Call,
            pc: 3,
            size: 4,
            mem_addr: 0,
            mem_value: 0,
            is_write: false,
        });
        assert_eq!(ring.dropped(), 1);
        let batch = ring.drain();
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].pc, 1);
        assert_eq!(batch[1].kind, EventKind::Mem);
        assert!(ring.is_empty());
    }
}
