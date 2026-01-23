//! Socket buffer trait abstraction.
//!
//! This module defines the `SocketBufferT` trait which abstracts over different
//! buffer implementations (RingBuffer, LinearBuffer) for TCP sockets.

use managed::ManagedSlice;

/// A trait for TCP socket buffers.
///
/// This trait abstracts the buffer operations needed by TCP sockets, allowing
/// different implementations (ring buffer, linear buffer) to be used interchangeably.
///
/// # Buffer Semantics
///
/// - `RingBuffer`: Uses wrap-around semantics. `window()` returns total available space
///   which may be non-contiguous.
/// - `LinearBuffer`: Never wraps. `window()` returns contiguous tail space.
///   Compacts data when tail space is exhausted and data is below threshold.
pub trait SocketBufferT<'a>: Sized + core::fmt::Debug {
    // === Construction and Basic Operations ===

    /// Create a new buffer with the given storage.
    fn new<S: Into<ManagedSlice<'a, u8>>>(storage: S) -> Self;

    /// Clear the buffer, resetting all pointers.
    fn clear(&mut self);

    // === Capacity Queries ===

    /// Return the maximum number of elements the buffer can hold.
    fn capacity(&self) -> usize;

    /// Return the current number of allocated (in-use) elements.
    fn len(&self) -> usize;

    /// Return the available space for new data.
    ///
    /// # Semantics
    /// - `RingBuffer`: `capacity - len` (total available, may be non-contiguous)
    /// - `LinearBuffer`: Contiguous tail space (always equals `contiguous_window`)
    fn window(&self) -> usize;

    /// Return the largest contiguous available space.
    ///
    /// For `LinearBuffer`, this equals `window()`.
    fn contiguous_window(&self) -> usize;

    /// Query whether the buffer is empty.
    #[inline]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Query whether the buffer is full.
    #[inline]
    fn is_full(&self) -> bool {
        self.window() == 0
    }

    // === Continuous Operations (Closure-based) ===

    /// Call `f` with the largest contiguous slice of unallocated buffer elements,
    /// and enqueue the amount of elements returned by `f`.
    ///
    /// # Panics
    /// Panics if the amount returned by `f` exceeds the slice size.
    fn enqueue_many_with<'b, R, F>(&'b mut self, f: F) -> (usize, R)
    where
        F: FnOnce(&'b mut [u8]) -> (usize, R);

    /// Call `f` with the largest contiguous slice of allocated buffer elements,
    /// and dequeue the amount of elements returned by `f`.
    ///
    /// # Panics
    /// Panics if the amount returned by `f` exceeds the slice size.
    fn dequeue_many_with<'b, R, F>(&'b mut self, f: F) -> (usize, R)
    where
        F: FnOnce(&'b mut [u8]) -> (usize, R);

    // === Random Access (for TCP out-of-order reassembly) ===

    /// Return a mutable slice of unallocated buffer elements starting at `offset`
    /// past the last allocated element.
    ///
    /// For `LinearBuffer`, this may trigger compaction if conditions are met.
    fn get_unallocated(&mut self, offset: usize, size: usize) -> &mut [u8];

    /// Write data into unallocated buffer elements starting at `offset`.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Important
    /// TCP expects this to write all data. For `RingBuffer`, this handles wrap-around.
    /// For `LinearBuffer`, this may trigger compaction to ensure contiguous space.
    fn write_unallocated(&mut self, offset: usize, data: &[u8]) -> usize;

    /// Mark `count` bytes of previously written unallocated data as allocated.
    ///
    /// # Panics
    /// Panics if `count` exceeds available window.
    fn enqueue_unallocated(&mut self, count: usize);

    /// Return a slice of allocated buffer elements starting at `offset`.
    fn get_allocated(&self, offset: usize, size: usize) -> &[u8];

    /// Read data from allocated buffer elements starting at `offset`.
    ///
    /// Returns the number of bytes read.
    fn read_allocated(&mut self, offset: usize, data: &mut [u8]) -> usize;

    /// Dequeue (consume) `count` bytes of allocated data.
    ///
    /// For `LinearBuffer`, this may trigger compaction if conditions are met.
    ///
    /// # Panics
    /// Panics if `count` exceeds allocated length.
    fn dequeue_allocated(&mut self, count: usize);

    // === Slice Operations ===

    /// Enqueue data from a slice into the buffer.
    ///
    /// Returns the number of bytes actually enqueued, limited by available space.
    fn enqueue_slice(&mut self, data: &[u8]) -> usize;

    /// Dequeue data from the buffer into a slice.
    ///
    /// Returns the number of bytes actually dequeued, limited by available data.
    fn dequeue_slice(&mut self, data: &mut [u8]) -> usize;

    /// Enqueue `size` bytes (or less, if not enough space), returning a mutable
    /// slice to write data into.
    ///
    /// This returns a contiguous slice; for ring buffers the returned size may
    /// be less than `size` if the buffer wraps.
    fn enqueue_many(&mut self, size: usize) -> &mut [u8];

    /// Dequeue `size` bytes (or less, if not enough data), returning a mutable
    /// slice containing the dequeued data.
    ///
    /// This returns a contiguous slice; for ring buffers the returned size may
    /// be less than `size` if the buffer wraps.
    fn dequeue_many(&mut self, size: usize) -> &mut [u8];
}
