//! Generational handle table for foreign objects.
//!
//! Scripts reference objects by a small integer handle.  Slots are reused so
//! a long-running hook does not grow the table, and every reuse bumps the
//! slot generation so a stale wrapper can never release (or address) the new
//! occupant.

pub struct HandleTable<T> {
    slots: Vec<Slot<T>>,
    free: Vec<u32>,
}

struct Slot<T> {
    value: Option<T>,
    generation: u32,
}

impl<T> HandleTable<T> {
    pub const fn new() -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
        }
    }

    /// Store a value and return its handle.
    pub fn insert(&mut self, value: T) -> u32 {
        if let Some(id) = self.free.pop() {
            let slot = &mut self.slots[id as usize];
            slot.generation = slot.generation.wrapping_add(1);
            slot.value = Some(value);
            return id;
        }
        self.slots.push(Slot {
            value: Some(value),
            generation: 0,
        });
        (self.slots.len() - 1) as u32
    }

    pub fn generation(&self, id: u32) -> Option<u32> {
        self.slots.get(id as usize).map(|slot| slot.generation)
    }

    pub fn get(&self, id: u32) -> Option<&T> {
        self.slots.get(id as usize)?.value.as_ref()
    }

    /// Resolve only when the handle is still the one that was issued.
    ///
    /// Slot reuse means an id alone is ambiguous: a wrapper held by a script
    /// after `$dispose()` would otherwise address whatever object took its
    /// slot. Callers must pass the generation they were given.
    pub fn get_live(&self, id: u32, generation: u32) -> Option<&T> {
        let slot = self.slots.get(id as usize)?;
        if slot.generation != generation {
            return None;
        }
        slot.value.as_ref()
    }

    /// Drop the value.  Returns whether this exact handle was live; a stale
    /// generation is a no-op, which makes double release harmless.
    ///
    /// ```
    /// use runtime::handles::HandleTable;
    ///
    /// let mut table = HandleTable::new();
    /// let first = table.insert("a");
    /// assert!(table.release(first, 0));
    ///
    /// // The slot is reused, but the old handle cannot address the new value.
    /// let second = table.insert("b");
    /// assert_eq!(second, first);
    /// assert_eq!(table.get_live(first, 0), None);
    /// assert_eq!(table.get_live(second, 1), Some(&"b"));
    /// ```
    pub fn release(&mut self, id: u32, generation: u32) -> bool {
        let Some(slot) = self.slots.get_mut(id as usize) else {
            return false;
        };
        if slot.generation != generation || slot.value.is_none() {
            return false;
        }
        slot.value = None;
        self.free.push(id);
        true
    }

    pub fn live(&self) -> usize {
        self.slots.iter().filter(|slot| slot.value.is_some()).count()
    }

    /// Slots ever allocated; with `live` this shows reuse efficiency.
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    pub fn free_slots(&self) -> usize {
        self.free.len()
    }
}

impl<T> Default for HandleTable<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_frees_the_slot_and_get_stops_resolving() {
        let mut table = HandleTable::new();
        let id = table.insert("a");
        assert_eq!(table.get(id), Some(&"a"));
        assert_eq!(table.live(), 1);
        assert!(table.release(id, 0));
        assert_eq!(table.get(id), None);
        assert_eq!(table.live(), 0);
    }

    #[test]
    fn stale_handles_cannot_release_a_reused_slot() {
        let mut table = HandleTable::new();
        let first = table.insert("a");
        assert!(table.release(first, 0));
        let second = table.insert("b");
        assert_eq!(second, first, "the slot is reused");
        assert_eq!(table.generation(second), Some(1));
        // A finalizer for the old wrapper runs late.
        assert!(!table.release(first, 0));
        assert_eq!(table.get(second), Some(&"b"));
        assert!(table.release(second, 1));
        assert_eq!(table.get(second), None);
    }

    #[test]
    fn a_stale_handle_cannot_address_a_reused_slot() {
        let mut table = HandleTable::new();
        let first = table.insert("a");
        assert!(table.release(first, 0));
        let second = table.insert("b");
        assert_eq!(second, first);
        // The raw id resolves to the new occupant...
        assert_eq!(table.get(first), Some(&"b"));
        // ...but the handle that was issued for "a" does not.
        assert_eq!(table.get_live(first, 0), None);
        assert_eq!(table.get_live(second, 1), Some(&"b"));
    }

    #[test]
    fn double_release_is_a_no_op() {
        let mut table = HandleTable::new();
        let id = table.insert(7u32);
        assert!(table.release(id, 0));
        assert!(!table.release(id, 0));
    }
}
