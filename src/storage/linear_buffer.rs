//! Linear buffer implementation.
//!
//! A `LinearBuffer` is a buffer that never wraps around. It uses on-demand
//! compaction: when a write would exceed buffer capacity, data is moved to
//! the beginning before the write proceeds.

use managed::ManagedSlice;

use super::buffer_trait::SocketBufferT;

/// Default reserve for virtual window calculation.
/// Head space beyond this is added to the advertised window.
pub const DEFAULT_WINDOW_RESERVE: usize = 4 * 1024; // 4 KB

/// A linear (non-wrapping) buffer for TCP sockets.
///
/// Unlike `RingBuffer`, this buffer never wraps around. It uses on-demand
/// compaction: when a write operation would exceed the buffer capacity,
/// all existing data is moved to the beginning of the buffer first.
///
/// # Window Semantics
///
/// The `window()` method returns `capacity - read_at - length`, which is the
/// theoretical space available. This allows the TCP window to remain open
/// as long as there's unconsumed buffer capacity, preventing TCP deadlocks
/// caused by Window Scaling (RFC 1323) rounding small windows to zero.
#[derive(Debug)]
pub struct LinearBuffer<'a> {
    storage: ManagedSlice<'a, u8>,
    /// Position of the first allocated byte.
    read_at: usize,
    /// Number of allocated (in-use) bytes.
    length: usize,
    /// Extent of the furthest written unallocated data (for out-of-order writes).
    /// This is relative to `read_at + length`.
    unallocated_extent: usize,
    /// Reserve for virtual window calculation.
    /// Head space beyond this is added to the advertised window.
    window_reserve: usize,
}

impl<'a> LinearBuffer<'a> {
    /// Create a new linear buffer with custom window reserve.
    pub fn with_reserve<S>(storage: S, window_reserve: usize) -> Self
    where
        S: Into<ManagedSlice<'a, u8>>,
    {
        LinearBuffer {
            storage: storage.into(),
            read_at: 0,
            length: 0,
            unallocated_extent: 0,
            window_reserve,
        }
    }


    /// Return the total occupied extent (allocated + unallocated written data).
    #[inline]
    fn occupied_extent(&self) -> usize {
        self.length + self.unallocated_extent
    }

    /// Reset read_at if buffer is completely empty.
    #[inline]
    fn reset_if_empty(&mut self) {
        if self.occupied_extent() == 0 {
            self.read_at = 0;
        }
    }

    /// Compact buffer if writing to `required_end` would exceed capacity.
    /// Returns true if compaction occurred.
    #[inline]
    fn compact_if_needed(&mut self, required_end: usize) -> bool {
        if required_end > self.capacity() && self.read_at > 0 {
            let extent = self.occupied_extent();
            if extent > 0 {
                self.storage.copy_within(self.read_at..self.read_at + extent, 0);
            }
            self.read_at = 0;
            true
        } else {
            false
        }
    }

    /// "Free" compaction: only compact when buffer is empty (no data movement needed).
    #[inline]
    fn compact_if_free(&mut self) {
        if self.occupied_extent() == 0 {
            self.read_at = 0;
        }
    }

    /// Set the window reserve.
    pub fn set_window_reserve(&mut self, reserve: usize) {
        self.window_reserve = reserve;
    }

}

impl<'a> SocketBufferT<'a> for LinearBuffer<'a> {
    fn new<S: Into<ManagedSlice<'a, u8>>>(storage: S) -> Self {
        LinearBuffer::with_reserve(storage, DEFAULT_WINDOW_RESERVE)
    }

    fn clear(&mut self) {
        self.read_at = 0;
        self.length = 0;
        self.unallocated_extent = 0;
    }

    #[inline]
    fn capacity(&self) -> usize {
        self.storage.len()
    }

    #[inline]
    fn len(&self) -> usize {
        self.length
    }

    #[inline]
    fn window(&self) -> usize {
        // Virtual window = tail_space + max(head_space - reserve, 0)
        //
        // This advertises reclaimable head space (beyond the reserve) as available,
        // since we will compact on-demand when a write would exceed capacity.
        // This prevents TCP Window Scaling from rounding small windows to zero.
        //
        // Layout: [head_space][data][unalloc][tail_space]
        //         ^0         ^read_at       ^capacity
        let tail_space = self.capacity()
            .saturating_sub(self.read_at + self.length);
        let head_space = self.read_at;

        // Add reclaimable head space (beyond reserve) to the advertised window
        tail_space + head_space.saturating_sub(self.window_reserve)
    }

    #[inline]
    fn contiguous_window(&self) -> usize {
        // For writing NEW data (not retransmissions), we need space after OOO data
        self.capacity()
            .saturating_sub(self.read_at + self.occupied_extent())
    }

    fn enqueue_many_with<'b, R, F>(&'b mut self, f: F) -> (usize, R)
    where
        F: FnOnce(&'b mut [u8]) -> (usize, R),
    {
        self.reset_if_empty();

        // Try to get the full advertised window via on-demand compaction
        let window = self.window();
        let end_at = self.read_at + self.length + window;
        self.compact_if_needed(end_at);

        let write_at = self.read_at + self.length;
        let max_size = self.contiguous_window();
        let (size, result) = f(&mut self.storage[write_at..write_at + max_size]);
        assert!(size <= max_size);
        self.length += size;
        (size, result)
    }

    fn dequeue_many_with<'b, R, F>(&'b mut self, f: F) -> (usize, R)
    where
        F: FnOnce(&'b mut [u8]) -> (usize, R),
    {
        // Free compaction before borrow (reset if empty)
        self.compact_if_free();

        let max_size = self.length;
        let (size, result) = f(&mut self.storage[self.read_at..self.read_at + max_size]);
        assert!(size <= max_size);
        self.read_at += size;
        self.length -= size;

        // Free compaction after dequeue: if empty, reset read_at.
        // This is safe because we're only modifying read_at (a scalar),
        // and the returned slice still points to valid memory.
        if self.length == 0 && self.unallocated_extent == 0 {
            self.read_at = 0;
        }
        (size, result)
    }

    fn get_unallocated(&mut self, offset: usize, mut size: usize) -> &mut [u8] {
        // Calculate where we need to write
        let mut start_at = self.read_at + self.length + offset;
        let end_at = start_at + size;

        // On-demand compaction: if write would exceed capacity, compact first
        if self.compact_if_needed(end_at) {
            // Recalculate after compaction
            start_at = self.read_at + self.length + offset;
        }

        if start_at >= self.capacity() {
            return &mut [];
        }
        let available = self.capacity() - start_at;
        if size > available {
            size = available;
        }
        let end_offset = offset + size;
        if end_offset > self.unallocated_extent {
            self.unallocated_extent = end_offset;
        }
        &mut self.storage[start_at..start_at + size]
    }

    fn write_unallocated(&mut self, offset: usize, data: &[u8]) -> usize {
        // Note: get_unallocated calls compact_if_free
        let slice = self.get_unallocated(offset, data.len());
        let len = slice.len();
        slice.copy_from_slice(&data[..len]);
        len
    }

    fn enqueue_unallocated(&mut self, count: usize) {
        assert!(count <= self.window() + self.unallocated_extent);
        self.length += count;
        if count >= self.unallocated_extent {
            self.unallocated_extent = 0;
        } else {
            self.unallocated_extent -= count;
        }
        self.compact_if_free();
    }

    fn get_allocated(&self, offset: usize, mut size: usize) -> &[u8] {
        if offset > self.length {
            return &[];
        }

        let start_at = self.read_at + offset;
        let clamped_length = self.length - offset;
        if size > clamped_length {
            size = clamped_length;
        }

        &self.storage[start_at..start_at + size]
    }

    fn read_allocated(&mut self, offset: usize, data: &mut [u8]) -> usize {
        let slice = self.get_allocated(offset, data.len());
        let len = slice.len();
        data[..len].copy_from_slice(slice);
        len
    }

    fn dequeue_allocated(&mut self, count: usize) {
        assert!(count <= self.length);
        self.length -= count;
        self.read_at += count;
        self.compact_if_free();
    }

    fn enqueue_slice(&mut self, data: &[u8]) -> usize {
        self.reset_if_empty();

        // On-demand compaction if we need the space
        let end_at = self.read_at + self.length + data.len();
        self.compact_if_needed(end_at);

        let write_at = self.read_at + self.length;
        let max_size = self.contiguous_window();
        let size = core::cmp::min(data.len(), max_size);
        self.storage[write_at..write_at + size].copy_from_slice(&data[..size]);
        self.length += size;
        size
    }

    fn dequeue_slice(&mut self, data: &mut [u8]) -> usize {
        let size = core::cmp::min(data.len(), self.length);
        data[..size].copy_from_slice(&self.storage[self.read_at..self.read_at + size]);
        self.read_at += size;
        self.length -= size;
        self.compact_if_free();
        size
    }

    fn enqueue_many(&mut self, size: usize) -> &mut [u8] {
        self.reset_if_empty();

        // On-demand compaction if we need the space
        let end_at = self.read_at + self.length + size;
        self.compact_if_needed(end_at);

        let write_at = self.read_at + self.length;
        let max_size = core::cmp::min(size, self.contiguous_window());
        self.length += max_size;
        &mut self.storage[write_at..write_at + max_size]
    }

    fn dequeue_many(&mut self, size: usize) -> &mut [u8] {
        let size = core::cmp::min(size, self.length);
        let read_at = self.read_at;
        self.read_at += size;
        self.length -= size;
        // After dequeue: reset if empty, or compact for window
        // Note: must happen BEFORE returning slice to avoid invalidating it
        // But that's problematic... we return a mutable borrow
        // So we can only reset if empty (which doesn't invalidate)
        if self.occupied_extent() == 0 {
            self.read_at = 0;
        }
        &mut self.storage[read_at..read_at + size]
    }
}

// === From implementations for ergonomic construction ===

impl<'a> From<ManagedSlice<'a, u8>> for LinearBuffer<'a> {
    fn from(slice: ManagedSlice<'a, u8>) -> Self {
        LinearBuffer::new(slice)
    }
}

#[cfg(feature = "alloc")]
impl<'a> From<alloc::vec::Vec<u8>> for LinearBuffer<'a> {
    fn from(vec: alloc::vec::Vec<u8>) -> Self {
        LinearBuffer::new(vec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_basic_enqueue_dequeue() {
        let mut buf = LinearBuffer::new(vec![0u8; 64]);

        buf.enqueue_many_with(|slice| {
            slice[..4].copy_from_slice(&[1, 2, 3, 4]);
            (4, ())
        });
        assert_eq!(buf.len(), 4);
        assert_eq!(buf.window(), 60);

        let mut out = [0u8; 4];
        buf.dequeue_many_with(|slice| {
            out.copy_from_slice(&slice[..4]);
            (4, ())
        });
        assert_eq!(&out, &[1, 2, 3, 4]);
        assert_eq!(buf.len(), 0);
        // After dequeue, buffer is empty, read_at is reset to 0
        assert_eq!(buf.read_at, 0);
        assert_eq!(buf.window(), 64);
    }

    #[test]
    fn test_compaction() {
        // On-demand compaction: compaction happens when write would exceed capacity
        let mut buf = LinearBuffer::new(vec![0u8; 100]);

        // Position data near end
        buf.read_at = 96;
        buf.length = 4;
        // Tail space = 100 - 96 - 4 = 0
        // window() = 0

        assert_eq!(buf.window(), 0);

        // Try to write beyond capacity - should trigger compaction
        let slice_len = buf.get_unallocated(0, 10).len();
        // After compaction: read_at=0, so we can write
        assert_eq!(buf.read_at, 0);
        assert_eq!(buf.length, 4);
        assert_eq!(slice_len, 10);
    }

    #[test]
    fn test_window_is_contiguous() {
        let mut buf = LinearBuffer::new(vec![0u8; 100]);

        buf.read_at = 30;
        buf.length = 20;
        // Tail space = 100 - 30 - 20 = 50

        assert_eq!(buf.window(), 50);
        assert_eq!(buf.contiguous_window(), 50);
        assert_eq!(buf.window(), buf.contiguous_window());
    }

    // ==========================================================================
    // Edge Case Tests for LinearBuffer Compaction
    // ==========================================================================

    #[test]
    fn test_on_demand_compact_on_write() {
        // On-demand compaction triggers when write would exceed capacity
        let mut buf = LinearBuffer::new(vec![0u8; 100]);

        // Position data at the very end
        buf.read_at = 90;
        buf.length = 10;
        // Tail space = 100 - 90 - 10 = 0
        assert_eq!(buf.window(), 0);

        // Try to enqueue - should compact first
        let written = buf.enqueue_slice(b"hello");
        assert_eq!(buf.read_at, 0, "Should compact to start");
        assert_eq!(written, 5);
        assert_eq!(buf.length, 15); // 10 original + 5 new
    }

    #[test]
    fn test_no_compact_when_space_available() {
        // Should NOT compact when write fits in existing tail space
        let mut buf = LinearBuffer::new(vec![0u8; 100]);

        buf.read_at = 60;
        buf.length = 30;
        // Tail space = 100 - 60 - 30 = 10

        let written = buf.enqueue_slice(b"hi");
        assert_eq!(buf.read_at, 60, "Should NOT compact - space available");
        assert_eq!(written, 2);
    }

    #[test]
    fn test_compact_only_when_needed() {
        // Should NOT compact if write fits
        let mut buf = LinearBuffer::new(vec![0u8; 100]);

        buf.read_at = 80;
        buf.length = 10;
        // Tail space = 100 - 80 - 10 = 10

        // Write fits in tail space
        let slice_len = buf.get_unallocated(0, 5).len();
        assert_eq!(buf.read_at, 80, "Should NOT compact - fits in tail");
        assert_eq!(slice_len, 5);
    }

    #[test]
    fn test_reset_on_empty() {
        // read_at should reset to 0 when buffer becomes empty
        let mut buf = LinearBuffer::new(vec![0u8; 64]);

        buf.enqueue_slice(b"hello");
        buf.read_at = 30; // Simulate some previous activity
        buf.length = 5;

        buf.dequeue_allocated(5);
        assert_eq!(buf.length, 0);
        assert_eq!(buf.read_at, 0, "read_at should reset when empty");
    }

    #[test]
    fn test_out_of_order_write_extent_tracking() {
        // unallocated_extent should track furthest written position
        let mut buf = LinearBuffer::new(vec![0u8; 100]);

        // Write at offset 20 (out of order)
        buf.write_unallocated(20, b"data");
        assert_eq!(buf.unallocated_extent, 24, "Should track extent to 24");

        // Write at offset 0 (in order)
        buf.write_unallocated(0, b"start");
        // Still 24 since that's further
        assert_eq!(buf.unallocated_extent, 24);

        // Write further out
        buf.write_unallocated(50, b"far");
        assert_eq!(buf.unallocated_extent, 53);
    }

    #[test]
    fn test_compact_preserves_ooo_data() {
        // Compaction should preserve out-of-order data
        let mut buf = LinearBuffer::new(vec![0u8; 100]);

        // Simulate the buffer reaching edge with OOO data
        buf.read_at = 86;
        buf.length = 4;
        buf.unallocated_extent = 10;
        // occupied_extent = 4 + 10 = 14
        // Tail space = 100 - 86 - 14 = 0

        // Try to write beyond - should compact and preserve OOO
        let slice_len = buf.get_unallocated(15, 5).len();
        assert_eq!(buf.read_at, 0, "Should compact");
        assert_eq!(buf.length, 4);
        assert!(slice_len > 0, "Should be able to write after compact");
        // Note: unallocated_extent will be updated by get_unallocated
    }

    #[test]
    fn test_write_unallocated_triggers_compact() {
        // write_unallocated should compact if needed space exceeds tail
        let mut buf = LinearBuffer::new(vec![0u8; 100]);

        buf.read_at = 95;
        buf.length = 5;
        // Tail space = 100 - 95 - 5 = 0

        // Write needs more space - should trigger compact
        let written = buf.write_unallocated(0, b"new data here");
        assert_eq!(buf.read_at, 0, "Should compact before write");
        assert!(written > 0);
    }

    #[test]
    fn test_enqueue_unallocated_clears_extent() {
        // enqueue_unallocated should clear (or reduce) unallocated_extent
        let mut buf = LinearBuffer::new(vec![0u8; 100]);

        buf.write_unallocated(0, b"abcd");
        buf.write_unallocated(8, b"efgh");
        assert_eq!(buf.unallocated_extent, 12);

        // Enqueue 10 bytes (covers offset 0-9, partial OOO)
        buf.enqueue_unallocated(10);
        assert_eq!(buf.length, 10);
        assert_eq!(buf.unallocated_extent, 2, "Remaining extent at offset 10-12");
    }

    #[test]
    fn test_compact_if_free_at_start_noop() {
        // compact_if_free should be a no-op when already at start with data
        let mut buf = LinearBuffer::new(vec![0u8; 100]);
        buf.enqueue_slice(b"test");

        assert_eq!(buf.read_at, 0);
        buf.compact_if_free();
        assert_eq!(buf.read_at, 0);
        assert_eq!(buf.length, 4);
    }

    #[test]
    fn test_dequeue_then_write_triggers_compact() {
        // With on-demand compaction, dequeue doesn't compact
        // But subsequent write will compact if needed
        let mut buf = LinearBuffer::new(vec![0u8; 100]);

        buf.read_at = 90;
        buf.length = 10;
        // Tail = 0

        buf.dequeue_allocated(2);
        // read_at = 92, length = 8, tail = 0
        // dequeue doesn't compact anymore

        // But writing will trigger compact
        let written = buf.enqueue_slice(b"test");
        assert_eq!(buf.read_at, 0, "Write should trigger compact");
        assert_eq!(written, 4);
    }

    #[test]
    fn test_get_unallocated_beyond_capacity() {
        // get_unallocated beyond capacity returns empty slice
        let mut buf = LinearBuffer::new(vec![0u8; 10]);

        let slice = buf.get_unallocated(100, 10);
        assert!(slice.is_empty());
    }

    #[test]
    fn test_on_demand_compact_multiple_writes() {
        // Multiple writes should work correctly with on-demand compaction
        let mut buf = LinearBuffer::new(vec![0u8; 100]);

        // Fill buffer near end
        buf.read_at = 90;
        buf.length = 5;
        // Tail = 5

        // First write fits
        let w1 = buf.enqueue_slice(b"ab");
        assert_eq!(buf.read_at, 90, "First write fits, no compact");
        assert_eq!(w1, 2);

        // Now tail = 3, try to write 5 bytes
        let w2 = buf.enqueue_slice(b"cdefg");
        assert_eq!(buf.read_at, 0, "Second write triggers compact");
        assert_eq!(w2, 5);
        assert_eq!(buf.length, 12); // 5 + 2 + 5
    }
}
