//! Linear buffer implementation.
//!
//! A `LinearBuffer` is a buffer that never wraps around. When tail space is
//! exhausted and data length is below a threshold, it compacts by moving data
//! to the beginning.

use managed::ManagedSlice;

use super::buffer_trait::SocketBufferT;

/// Default threshold for compaction.
/// If data length is below this and tail space is zero, compact.
pub const DEFAULT_COMPACT_THRESHOLD: usize = 32 * 1024; // 32 KB

/// A linear (non-wrapping) buffer for TCP sockets.
///
/// Unlike `RingBuffer`, this buffer never wraps around. When the tail space
/// is exhausted and the data length is below `compact_threshold`, it moves
/// all data to the beginning of the buffer.
///
/// # Window Semantics
///
/// The `window()` method returns the contiguous tail space available for
/// writing. This is the same as `contiguous_window()`. When advertised to
/// TCP peers, this ensures they never send more than can be written contiguously.
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
    /// Threshold below which compaction is triggered.
    compact_threshold: usize,
}

impl<'a> LinearBuffer<'a> {
    /// Create a new linear buffer with custom compact threshold.
    pub fn with_threshold<S>(storage: S, compact_threshold: usize) -> Self
    where
        S: Into<ManagedSlice<'a, u8>>,
    {
        LinearBuffer {
            storage: storage.into(),
            read_at: 0,
            length: 0,
            unallocated_extent: 0,
            compact_threshold,
        }
    }

    /// Return the total occupied extent (allocated + unallocated written data).
    #[inline]
    fn occupied_extent(&self) -> usize {
        self.length + self.unallocated_extent
    }

    /// Ensure buffer has writable tail space.
    ///
    /// Priority:
    /// 1. If buffer is empty, reset read_at to 0 (free reset)
    /// 2. If tail space is zero and occupied extent < threshold, compact
    fn ensure_writable(&mut self) {
        let extent = self.occupied_extent();

        // Priority 1: Empty buffer → reset to start (no copy needed)
        if extent == 0 {
            self.read_at = 0;
            return;
        }

        // Priority 2: Buffer full → compact if below threshold
        let tail_space = self.capacity() - self.read_at - extent;
        if tail_space == 0 && extent < self.compact_threshold {
            self.storage.copy_within(self.read_at..self.read_at + extent, 0);
            self.read_at = 0;
        }
    }

    /// Set the compact threshold.
    pub fn set_compact_threshold(&mut self, threshold: usize) {
        self.compact_threshold = threshold;
    }
}

impl<'a> SocketBufferT<'a> for LinearBuffer<'a> {
    fn new<S: Into<ManagedSlice<'a, u8>>>(storage: S) -> Self {
        LinearBuffer::with_threshold(storage, DEFAULT_COMPACT_THRESHOLD)
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
        // LinearBuffer: window equals contiguous tail space
        self.contiguous_window()
    }

    #[inline]
    fn contiguous_window(&self) -> usize {
        self.capacity()
            .saturating_sub(self.read_at + self.occupied_extent())
    }

    fn enqueue_many_with<'b, R, F>(&'b mut self, f: F) -> (usize, R)
    where
        F: FnOnce(&'b mut [u8]) -> (usize, R),
    {
        self.ensure_writable();
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
        self.ensure_writable();
        let max_size = self.length;
        let (size, result) = f(&mut self.storage[self.read_at..self.read_at + max_size]);
        assert!(size <= max_size);
        self.read_at += size;
        self.length -= size;
        // Empty buffer reset (no storage access - only scalar fields)
        if self.length + self.unallocated_extent == 0 {
            self.read_at = 0;
        }
        (size, result)
    }

    fn get_unallocated(&mut self, offset: usize, mut size: usize) -> &mut [u8] {
        self.ensure_writable();
        let start_at = self.read_at + self.length + offset;
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
        // Note: get_unallocated calls ensure_writable
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
        self.ensure_writable();
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
        self.ensure_writable();
    }

    fn enqueue_slice(&mut self, data: &[u8]) -> usize {
        let write_at = self.read_at + self.length;
        let max_size = self.contiguous_window();
        let size = core::cmp::min(data.len(), max_size);
        self.storage[write_at..write_at + size].copy_from_slice(&data[..size]);
        self.length += size;
        self.ensure_writable();
        size
    }

    fn dequeue_slice(&mut self, data: &mut [u8]) -> usize {
        let size = core::cmp::min(data.len(), self.length);
        data[..size].copy_from_slice(&self.storage[self.read_at..self.read_at + size]);
        self.read_at += size;
        self.length -= size;
        self.ensure_writable();
        size
    }

    fn enqueue_many(&mut self, size: usize) -> &mut [u8] {
        self.ensure_writable();
        let write_at = self.read_at + self.length;
        let max_size = core::cmp::min(size, self.contiguous_window());
        self.length += max_size;
        &mut self.storage[write_at..write_at + max_size]
    }

    fn dequeue_many(&mut self, size: usize) -> &mut [u8] {
        self.ensure_writable();
        let size = core::cmp::min(size, self.length);
        let read_at = self.read_at;
        self.read_at += size;
        self.length -= size;
        // Empty buffer reset (no storage access)
        if self.length + self.unallocated_extent == 0 {
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
        assert_eq!(buf.read_at, 0); // Reset after empty
    }

    #[test]
    fn test_compaction() {
        let mut buf = LinearBuffer::with_threshold(vec![0u8; 100], 50);

        // Fill to near end
        buf.read_at = 80;
        buf.length = 10;

        // Tail space = 100 - 80 - 10 = 10
        assert_eq!(buf.window(), 10);

        // Consume some data to trigger potential compaction
        buf.dequeue_allocated(5);
        // Now: read_at=85, length=5, extent=5
        // Tail space = 100 - 85 - 5 = 10

        // Get unallocated should trigger compaction since tail=10 (not 0 yet)
        // Let's simulate reaching the end
        buf.read_at = 90;
        buf.length = 5;
        // Tail space = 100 - 90 - 5 = 5

        buf.read_at = 96;
        buf.length = 4;
        // Tail space = 100 - 96 - 4 = 0!
        // And length (4) < threshold (50)

        buf.ensure_writable();
        assert_eq!(buf.read_at, 0);
        assert_eq!(buf.length, 4);
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
    fn test_compact_trigger_tail_zero_below_threshold() {
        // Compaction should trigger when: tail_space == 0 AND length < threshold
        let mut buf = LinearBuffer::with_threshold(vec![0u8; 100], 50);

        // Position data at the very end
        buf.read_at = 90;
        buf.length = 10;
        // Tail space = 100 - 90 - 10 = 0
        assert_eq!(buf.window(), 0);

        // Data is 10 bytes, below threshold of 50
        buf.ensure_writable();
        assert_eq!(buf.read_at, 0, "Should compact to start");
        assert_eq!(buf.length, 10);
        assert_eq!(buf.window(), 90, "Should have 90 bytes available now");
    }

    #[test]
    fn test_no_compact_above_threshold() {
        // Should NOT compact when length >= threshold, even if tail_space == 0
        let mut buf = LinearBuffer::with_threshold(vec![0u8; 100], 20);

        buf.read_at = 60;
        buf.length = 40;
        // Tail space = 100 - 60 - 40 = 0
        // But length (40) >= threshold (20)
        assert_eq!(buf.window(), 0);

        buf.ensure_writable();
        assert_eq!(buf.read_at, 60, "Should NOT compact");
        assert_eq!(buf.length, 40);
    }

    #[test]
    fn test_no_compact_with_tail_space() {
        // Should NOT compact when tail_space > 0
        let mut buf = LinearBuffer::with_threshold(vec![0u8; 100], 50);

        buf.read_at = 80;
        buf.length = 10;
        // Tail space = 100 - 80 - 10 = 10 (not zero)

        buf.ensure_writable();
        assert_eq!(buf.read_at, 80, "Should NOT compact - tail space exists");
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
        let mut buf = LinearBuffer::with_threshold(vec![0u8; 100], 60);

        // Write in-order data
        buf.enqueue_slice(b"abcd");
        assert_eq!(buf.length, 4);

        // Write out-of-order data at offset 10
        buf.write_unallocated(10, b"XY");
        assert_eq!(buf.unallocated_extent, 12);

        // Simulate the buffer reaching edge
        buf.read_at = 86;
        buf.length = 4;
        buf.unallocated_extent = 10;
        // occupied_extent = max(4, 4+10) = 14
        // Tail space = 100 - 86 - 14 = 0

        buf.ensure_writable();
        assert_eq!(buf.read_at, 0);
        assert_eq!(buf.length, 4);
        assert_eq!(buf.unallocated_extent, 10, "OOO extent should be preserved");
    }

    #[test]
    fn test_write_unallocated_triggers_compact() {
        // write_unallocated should compact if needed space exceeds tail
        let mut buf = LinearBuffer::with_threshold(vec![0u8; 100], 50);

        buf.read_at = 95;
        buf.length = 5;
        // Tail space = 100 - 95 - 5 = 0
        // occupied_extent = 5 < threshold = 50

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
    fn test_ensure_writable_at_start_noop() {
        // ensure_writable should be a no-op when already at start with data
        let mut buf = LinearBuffer::new(vec![0u8; 100]);
        buf.enqueue_slice(b"test");

        assert_eq!(buf.read_at, 0);
        buf.ensure_writable();
        assert_eq!(buf.read_at, 0);
        assert_eq!(buf.length, 4);
    }

    #[test]
    fn test_dequeue_allocated_triggers_compact() {
        // dequeue_allocated may trigger compaction
        let mut buf = LinearBuffer::with_threshold(vec![0u8; 100], 30);

        // Position near end with enough data
        buf.read_at = 90;
        buf.length = 10;
        // After dequeue: tail=0, length < threshold -> compact

        buf.dequeue_allocated(2);
        // Now: read_at should be 0 due to compaction
        // (tail_space = 100 - 92 - 8 = 0, length=8 < threshold=30)
        assert_eq!(buf.read_at, 0, "Should compact after dequeue");
        assert_eq!(buf.length, 8);
    }

    #[test]
    fn test_get_unallocated_beyond_capacity() {
        // get_unallocated beyond capacity returns empty slice
        let mut buf = LinearBuffer::new(vec![0u8; 10]);

        let slice = buf.get_unallocated(100, 10);
        assert!(slice.is_empty());
    }

    #[test]
    fn test_threshold_configuration() {
        // Verify threshold affects compaction behavior
        let mut buf_low = LinearBuffer::with_threshold(vec![0u8; 100], 5);
        let mut buf_high = LinearBuffer::with_threshold(vec![0u8; 100], 50);

        // Same state: length=10, at end
        buf_low.read_at = 90;
        buf_low.length = 10;
        buf_high.read_at = 90;
        buf_high.length = 10;

        buf_low.ensure_writable();
        buf_high.ensure_writable();

        // buf_low: length(10) >= threshold(5) -> no compact
        assert_eq!(buf_low.read_at, 90, "Low threshold should NOT compact");
        // buf_high: length(10) < threshold(50) -> compact
        assert_eq!(buf_high.read_at, 0, "High threshold should compact");
    }
}
