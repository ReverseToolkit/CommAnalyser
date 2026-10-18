use std::fmt;

/// Half-open virtual address range `[start, end)`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Range {
    pub start: usize,
    pub end: usize,
}

impl Range {
    #[inline]
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    #[inline]
    pub const fn empty(at: usize) -> Self {
        Self { start: at, end: at }
    }

    #[inline]
    pub const fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.end <= self.start
    }

    #[inline]
    pub const fn contains(&self, addr: usize) -> bool {
        addr >= self.start && addr < self.end
    }

    #[inline]
    pub const fn contains_range(&self, other: Range) -> bool {
        other.start >= self.start && other.end <= self.end
    }

    #[inline]
    pub const fn intersects(&self, other: Range) -> bool {
        self.start < other.end && other.start < self.end
    }

    #[inline]
    pub fn offset_of(&self, addr: usize) -> Option<usize> {
        if self.contains(addr) {
            Some(addr - self.start)
        } else {
            None
        }
    }
}

impl fmt::Debug for Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Range({:#x}..{:#x})", self.start, self.end)
    }
}

#[cfg(test)]
mod tests {
    use super::Range;

    #[test]
    fn basics() {
        let r = Range::new(0x1000, 0x2000);
        assert_eq!(r.len(), 0x1000);
        assert!(r.contains(0x1000));
        assert!(r.contains(0x1fff));
        assert!(!r.contains(0x2000));
        assert!(r.contains_range(Range::new(0x1100, 0x1f00)));
        assert!(!r.contains_range(Range::new(0x0f00, 0x1100)));
        assert!(r.intersects(Range::new(0x1f00, 0x3000)));
        assert!(!r.intersects(Range::new(0x2000, 0x3000)));
        assert_eq!(r.offset_of(0x1234), Some(0x234));
        assert_eq!(r.offset_of(0x3000), None);
    }
}
