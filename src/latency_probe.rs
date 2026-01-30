//! Latency instrumentation for debugging DPDK scheduling.
//!
//! This module provides precise timestamps at key points in the network stack:
//! - When data is enqueued to TCP rx_buffer
//! - When waker.wake() is called to schedule the async task
//!
//! Enable with the `latency-probe` feature.

use std::sync::atomic::{AtomicU64, Ordering};
use std::cell::Cell;

/// Thread-local timestamp storage for latency probing.
///
/// Each thread has its own copy to avoid contention.
thread_local! {
    /// Timestamp (nanoseconds) when data was last enqueued to rx_buffer
    static RX_ENQUEUE_TS: Cell<u64> = const { Cell::new(0) };

    /// Timestamp (nanoseconds) when waker.wake() was last called
    static WAKER_WAKE_TS: Cell<u64> = const { Cell::new(0) };

    /// Number of bytes enqueued in the last rx_buffer write
    static RX_ENQUEUE_BYTES: Cell<usize> = const { Cell::new(0) };
}

/// Global counter for total wake() calls (for statistics)
static TOTAL_WAKE_CALLS: AtomicU64 = AtomicU64::new(0);

/// Get current time in nanoseconds using clock_gettime(CLOCK_MONOTONIC)
#[inline(always)]
pub fn now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Record timestamp when data is enqueued to rx_buffer.
/// Called from tcp.rs when rx_buffer.enqueue_unallocated() succeeds.
#[inline(always)]
pub fn record_rx_enqueue(bytes: usize) {
    let ts = now_ns();
    RX_ENQUEUE_TS.with(|cell| cell.set(ts));
    RX_ENQUEUE_BYTES.with(|cell| cell.set(bytes));
}

/// Record timestamp when waker.wake() is called.
/// Called from tcp.rs rx_waker.wake().
#[inline(always)]
pub fn record_waker_wake() {
    let ts = now_ns();
    WAKER_WAKE_TS.with(|cell| cell.set(ts));
    TOTAL_WAKE_CALLS.fetch_add(1, Ordering::Relaxed);
}

/// Get the last recorded timestamps.
///
/// Returns (rx_enqueue_ns, waker_wake_ns, bytes_enqueued)
#[inline]
pub fn get_last_timestamps() -> (u64, u64, usize) {
    let rx_ts = RX_ENQUEUE_TS.with(|cell| cell.get());
    let wake_ts = WAKER_WAKE_TS.with(|cell| cell.get());
    let bytes = RX_ENQUEUE_BYTES.with(|cell| cell.get());
    (rx_ts, wake_ts, bytes)
}

/// Get total number of wake() calls across all threads.
#[inline]
pub fn get_total_wake_calls() -> u64 {
    TOTAL_WAKE_CALLS.load(Ordering::Relaxed)
}

/// Latency probe result for a single measurement.
#[derive(Debug, Clone, Copy)]
pub struct LatencyProbe {
    /// Time from rx_buffer enqueue to waker.wake() (nanoseconds)
    pub enqueue_to_wake_ns: u64,
    /// Time from waker.wake() to task execution (user must calculate)
    pub wake_to_recv_ns: u64,
    /// Total time from enqueue to task recv() (nanoseconds)
    pub total_latency_ns: u64,
    /// Bytes received
    pub bytes: usize,
}

impl LatencyProbe {
    /// Create a new probe measurement.
    ///
    /// Call this from your async task after recv() completes.
    /// Pass the current timestamp (from `now_ns()`) as `recv_ts`.
    #[inline]
    pub fn measure(recv_ts: u64) -> Self {
        let (enqueue_ts, wake_ts, bytes) = get_last_timestamps();

        let enqueue_to_wake = if wake_ts >= enqueue_ts {
            wake_ts - enqueue_ts
        } else {
            0
        };

        let wake_to_recv = if recv_ts >= wake_ts {
            recv_ts - wake_ts
        } else {
            0
        };

        let total = if recv_ts >= enqueue_ts {
            recv_ts - enqueue_ts
        } else {
            0
        };

        Self {
            enqueue_to_wake_ns: enqueue_to_wake,
            wake_to_recv_ns: wake_to_recv,
            total_latency_ns: total,
            bytes,
        }
    }
}
