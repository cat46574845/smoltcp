//! Generic tests for SocketBufferT implementations.
//!
//! These tests verify that both RingBuffer and LinearBuffer correctly implement
//! the SocketBufferT trait.

use super::buffer_trait::SocketBufferT;
use super::linear_buffer::LinearBuffer;
use super::ring_buffer::RingBuffer;
use alloc::vec;

/// Helper trait to create buffers with common test utilities
trait TestBuffer<'a>: SocketBufferT<'a> {
    fn test_new(size: usize) -> Self;
}

impl<'a> TestBuffer<'a> for RingBuffer<'a, u8> {
    fn test_new(size: usize) -> Self {
        RingBuffer::new(vec![0u8; size])
    }
}

impl<'a> TestBuffer<'a> for LinearBuffer<'a> {
    fn test_new(size: usize) -> Self {
        LinearBuffer::new(vec![0u8; size])
    }
}

// =============================================================================
// Generic test functions
// =============================================================================

fn test_basic_capacity_len_window<'a, B: TestBuffer<'a>>() {
    let mut buf = B::test_new(64);

    assert_eq!(buf.capacity(), 64);
    assert_eq!(buf.len(), 0);
    assert!(buf.is_empty());
    assert!(!buf.is_full());
    assert!(buf.window() > 0);

    // After enqueuing, length increases
    let enqueued = buf.enqueue_slice(&[1, 2, 3, 4]);
    assert_eq!(enqueued, 4);
    assert_eq!(buf.len(), 4);
    assert!(!buf.is_empty());
    assert_eq!(buf.window(), 60);

    // After dequeuing, length decreases
    let mut out = [0u8; 2];
    let dequeued = buf.dequeue_slice(&mut out);
    assert_eq!(dequeued, 2);
    assert_eq!(&out, &[1, 2]);
    assert_eq!(buf.len(), 2);
}

fn test_enqueue_dequeue_slice<'a, B: TestBuffer<'a>>() {
    let mut buf = B::test_new(64);

    // Enqueue data
    assert_eq!(buf.enqueue_slice(b"hello"), 5);
    assert_eq!(buf.len(), 5);

    // Dequeue data
    let mut out = [0u8; 5];
    assert_eq!(buf.dequeue_slice(&mut out), 5);
    assert_eq!(&out, b"hello");
    assert_eq!(buf.len(), 0);
}

fn test_enqueue_many_with<'a, B: TestBuffer<'a>>() {
    let mut buf = B::test_new(64);

    let (size, result) = buf.enqueue_many_with(|slice| {
        slice[..4].copy_from_slice(b"test");
        (4, 42)
    });
    assert_eq!(size, 4);
    assert_eq!(result, 42);
    assert_eq!(buf.len(), 4);

    // Verify data
    let mut out = [0u8; 4];
    buf.dequeue_slice(&mut out);
    assert_eq!(&out, b"test");
}

fn test_dequeue_many_with<'a, B: TestBuffer<'a>>() {
    let mut buf = B::test_new(64);
    buf.enqueue_slice(b"hello world");

    let (size, result) = buf.dequeue_many_with(|slice| {
        assert!(slice.starts_with(b"hello"));
        (5, slice[0])
    });
    assert_eq!(size, 5);
    assert_eq!(result, b'h');
    assert_eq!(buf.len(), 6);
}

fn test_get_write_unallocated<'a, B: TestBuffer<'a>>() {
    let mut buf = B::test_new(64);

    // Write at offset 0
    let written = buf.write_unallocated(0, b"abcd");
    assert_eq!(written, 4);

    // Verify via get_unallocated
    {
        let slice = buf.get_unallocated(0, 4);
        assert_eq!(slice, b"abcd");
    }

    // Enqueue makes it allocated
    buf.enqueue_unallocated(4);
    assert_eq!(buf.len(), 4);

    // Verify via get_allocated
    assert_eq!(buf.get_allocated(0, 4), b"abcd");
}

fn test_out_of_order_write<'a, B: TestBuffer<'a>>() {
    let mut buf = B::test_new(64);

    // Write at offset 4 first (out of order)
    buf.write_unallocated(4, b"efgh");

    // Write at offset 0
    buf.write_unallocated(0, b"abcd");

    // Enqueue all 8 bytes
    buf.enqueue_unallocated(8);
    assert_eq!(buf.len(), 8);

    // Verify contiguous read
    let mut out = [0u8; 8];
    buf.read_allocated(0, &mut out);
    assert_eq!(&out, b"abcdefgh");
}

fn test_read_allocated<'a, B: TestBuffer<'a>>() {
    let mut buf = B::test_new(64);
    buf.enqueue_slice(b"hello world");

    // Read at offset 0
    let mut out = [0u8; 5];
    let read = buf.read_allocated(0, &mut out);
    assert_eq!(read, 5);
    assert_eq!(&out, b"hello");

    // Read at offset
    let read = buf.read_allocated(6, &mut out);
    assert_eq!(read, 5);
    assert_eq!(&out, b"world");
}

fn test_dequeue_allocated<'a, B: TestBuffer<'a>>() {
    let mut buf = B::test_new(64);
    buf.enqueue_slice(b"hello world");

    // Dequeue first 6 bytes
    buf.dequeue_allocated(6);
    assert_eq!(buf.len(), 5);

    // Verify remaining data
    let mut out = [0u8; 5];
    buf.dequeue_slice(&mut out);
    assert_eq!(&out, b"world");
}

fn test_clear<'a, B: TestBuffer<'a>>() {
    let mut buf = B::test_new(64);
    buf.enqueue_slice(b"hello");
    assert_eq!(buf.len(), 5);

    buf.clear();
    assert_eq!(buf.len(), 0);
    assert!(buf.is_empty());
    assert_eq!(buf.window(), 64);
}

fn test_zero_capacity<'a, B: TestBuffer<'a>>() {
    let mut buf = B::test_new(0);

    assert_eq!(buf.capacity(), 0);
    assert_eq!(buf.len(), 0);
    assert!(buf.is_empty());
    assert!(buf.is_full());
    assert_eq!(buf.window(), 0);
    assert_eq!(buf.contiguous_window(), 0);

    // Operations should not panic
    assert_eq!(buf.enqueue_slice(b"test"), 0);
    assert_eq!(buf.get_unallocated(0, 4), &[]);
    assert_eq!(buf.get_allocated(0, 4), &[]);
}

fn test_full_buffer<'a, B: TestBuffer<'a>>() {
    let mut buf = B::test_new(8);

    // Fill the buffer
    assert_eq!(buf.enqueue_slice(b"12345678"), 8);
    assert!(buf.is_full());
    assert_eq!(buf.window(), 0);

    // Cannot enqueue more
    assert_eq!(buf.enqueue_slice(b"x"), 0);

    // Dequeue some
    buf.dequeue_allocated(4);
    assert!(!buf.is_full());
    assert!(buf.window() > 0);
}

fn test_window_contiguous<'a, B: TestBuffer<'a>>() {
    let buf = B::test_new(64);
    // For linear buffer, window == contiguous_window
    // For ring buffer, contiguous_window <= window
    assert!(buf.contiguous_window() <= buf.window());
}

// =============================================================================
// Test instantiation macros
// =============================================================================

macro_rules! buffer_generic_tests {
    ($buffer_type:ty, $mod_name:ident) => {
        mod $mod_name {
            use super::*;

            #[test]
            fn basic_capacity_len_window() {
                test_basic_capacity_len_window::<$buffer_type>();
            }

            #[test]
            fn enqueue_dequeue_slice() {
                test_enqueue_dequeue_slice::<$buffer_type>();
            }

            #[test]
            fn enqueue_many_with() {
                test_enqueue_many_with::<$buffer_type>();
            }

            #[test]
            fn dequeue_many_with() {
                test_dequeue_many_with::<$buffer_type>();
            }

            #[test]
            fn get_write_unallocated() {
                test_get_write_unallocated::<$buffer_type>();
            }

            #[test]
            fn out_of_order_write() {
                test_out_of_order_write::<$buffer_type>();
            }

            #[test]
            fn read_allocated() {
                test_read_allocated::<$buffer_type>();
            }

            #[test]
            fn dequeue_allocated() {
                test_dequeue_allocated::<$buffer_type>();
            }

            #[test]
            fn clear() {
                test_clear::<$buffer_type>();
            }

            #[test]
            fn zero_capacity() {
                test_zero_capacity::<$buffer_type>();
            }

            #[test]
            fn full_buffer() {
                test_full_buffer::<$buffer_type>();
            }

            #[test]
            fn window_contiguous() {
                test_window_contiguous::<$buffer_type>();
            }
        }
    };
}

// Generate tests for both buffer types
buffer_generic_tests!(RingBuffer<'static, u8>, ring_buffer_trait_tests);
buffer_generic_tests!(LinearBuffer<'static>, linear_buffer_trait_tests);
