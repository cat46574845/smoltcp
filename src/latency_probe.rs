//! 零分配延遲追蹤系統
//!
//! 設計：
//! - 固定大小緩衝區，無 heap 分配
//! - 每個樁點獨立的數據結構
//! - 通過 socket_id + buffer_state 唯一對應
//!
//! 入口：TCP rx_buffer enqueue (smoltcp)
//! 出口：WebSocket message complete (應用層)

use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

// ============================================================================
// 基礎設施
// ============================================================================

/// tick/exec_count 提供者
pub type TickProvider = fn() -> (u32, u64);

thread_local! {
    static TICK_PROVIDER: Cell<Option<TickProvider>> = const { Cell::new(None) };
    static TRACING_ENABLED: Cell<bool> = const { Cell::new(false) };
}

#[inline(always)]
pub fn now_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

#[inline]
pub fn set_tick_provider(provider: TickProvider) {
    TICK_PROVIDER.with(|p| p.set(Some(provider)));
}

#[inline]
pub fn set_tracing_enabled(enabled: bool) {
    TRACING_ENABLED.with(|e| e.set(enabled));
}

#[inline]
pub fn is_tracing_enabled() -> bool {
    TRACING_ENABLED.with(|e| e.get())
}

#[inline(always)]
fn get_tick_exec() -> (u32, u64) {
    TICK_PROVIDER.with(|p| p.get().map_or((0, 0), |f| f()))
}

// ============================================================================
// 緩衝區配置
// ============================================================================

pub const BUFFER_CAPACITY: usize = 50000;

// ============================================================================
// TCP 層：入口點 - rx_buffer enqueue
// ============================================================================

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct TcpEnqueueRecord {
    pub ts_ns: u64,
    pub tick: u32,
    pub exec_count: u64,
    pub socket_id: usize,
    pub enqueue_len: usize,
    /// enqueue 後的 buffer 長度，用於唯一標識這筆數據
    pub buffer_len_after: usize,
}

static mut TCP_ENQUEUE_BUF: [TcpEnqueueRecord; BUFFER_CAPACITY] =
    [TcpEnqueueRecord { ts_ns: 0, tick: 0, exec_count: 0, socket_id: 0, enqueue_len: 0, buffer_len_after: 0 }; BUFFER_CAPACITY];
static TCP_ENQUEUE_IDX: AtomicUsize = AtomicUsize::new(0);

#[inline(always)]
pub fn trace_tcp_enqueue(socket_id: usize, enqueue_len: usize, buffer_len_after: usize) {
    if !TRACING_ENABLED.with(|e| e.get()) { return; }

    let idx = TCP_ENQUEUE_IDX.fetch_add(1, Ordering::Relaxed);
    if idx >= BUFFER_CAPACITY { return; }

    let (tick, exec_count) = get_tick_exec();
    unsafe {
        TCP_ENQUEUE_BUF[idx] = TcpEnqueueRecord {
            ts_ns: now_ns(),
            tick,
            exec_count,
            socket_id,
            enqueue_len,
            buffer_len_after,
        };
    }
}

// ============================================================================
// TCP 層：waker.wake()
// ============================================================================

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct TcpWakeRecord {
    pub ts_ns: u64,
    pub tick: u32,
    pub exec_count: u64,
    pub socket_id: usize,
}

static mut TCP_WAKE_BUF: [TcpWakeRecord; BUFFER_CAPACITY] =
    [TcpWakeRecord { ts_ns: 0, tick: 0, exec_count: 0, socket_id: 0 }; BUFFER_CAPACITY];
static TCP_WAKE_IDX: AtomicUsize = AtomicUsize::new(0);

#[inline(always)]
pub fn trace_tcp_wake(socket_id: usize) {
    if !TRACING_ENABLED.with(|e| e.get()) { return; }

    let idx = TCP_WAKE_IDX.fetch_add(1, Ordering::Relaxed);
    if idx >= BUFFER_CAPACITY { return; }

    let (tick, exec_count) = get_tick_exec();
    unsafe {
        TCP_WAKE_BUF[idx] = TcpWakeRecord {
            ts_ns: now_ns(),
            tick,
            exec_count,
            socket_id,
        };
    }
}

// ============================================================================
// TLS 層：decrypt
// ============================================================================

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct TlsDecryptRecord {
    pub ts_ns: u64,
    pub tick: u32,
    pub exec_count: u64,
    pub socket_id: usize,
    pub input_len: usize,
    pub output_len: usize,
}

static mut TLS_DECRYPT_BUF: [TlsDecryptRecord; BUFFER_CAPACITY] =
    [TlsDecryptRecord { ts_ns: 0, tick: 0, exec_count: 0, socket_id: 0, input_len: 0, output_len: 0 }; BUFFER_CAPACITY];
static TLS_DECRYPT_IDX: AtomicUsize = AtomicUsize::new(0);

#[inline(always)]
pub fn trace_tls_decrypt(socket_id: usize, input_len: usize, output_len: usize) {
    if !TRACING_ENABLED.with(|e| e.get()) { return; }

    let idx = TLS_DECRYPT_IDX.fetch_add(1, Ordering::Relaxed);
    if idx >= BUFFER_CAPACITY { return; }

    let (tick, exec_count) = get_tick_exec();
    unsafe {
        TLS_DECRYPT_BUF[idx] = TlsDecryptRecord {
            ts_ns: now_ns(),
            tick,
            exec_count,
            socket_id,
            input_len,
            output_len,
        };
    }
}

// ============================================================================
// WebSocket 層：出口點 - message complete
// ============================================================================

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct WsMessageRecord {
    pub ts_ns: u64,
    pub tick: u32,
    pub exec_count: u64,
    pub socket_id: usize,
    pub message_len: usize,
}

static mut WS_MESSAGE_BUF: [WsMessageRecord; BUFFER_CAPACITY] =
    [WsMessageRecord { ts_ns: 0, tick: 0, exec_count: 0, socket_id: 0, message_len: 0 }; BUFFER_CAPACITY];
static WS_MESSAGE_IDX: AtomicUsize = AtomicUsize::new(0);

#[inline(always)]
pub fn trace_ws_message(socket_id: usize, message_len: usize) {
    if !TRACING_ENABLED.with(|e| e.get()) { return; }

    let idx = WS_MESSAGE_IDX.fetch_add(1, Ordering::Relaxed);
    if idx >= BUFFER_CAPACITY { return; }

    let (tick, exec_count) = get_tick_exec();
    unsafe {
        WS_MESSAGE_BUF[idx] = WsMessageRecord {
            ts_ns: now_ns(),
            tick,
            exec_count,
            socket_id,
            message_len,
        };
    }
}

// ============================================================================
// 數據導出（分析時使用）
// ============================================================================

pub fn get_tcp_enqueue_records() -> &'static [TcpEnqueueRecord] {
    let len = TCP_ENQUEUE_IDX.load(Ordering::Relaxed).min(BUFFER_CAPACITY);
    unsafe { &TCP_ENQUEUE_BUF[..len] }
}

pub fn get_tcp_wake_records() -> &'static [TcpWakeRecord] {
    let len = TCP_WAKE_IDX.load(Ordering::Relaxed).min(BUFFER_CAPACITY);
    unsafe { &TCP_WAKE_BUF[..len] }
}

pub fn get_tls_decrypt_records() -> &'static [TlsDecryptRecord] {
    let len = TLS_DECRYPT_IDX.load(Ordering::Relaxed).min(BUFFER_CAPACITY);
    unsafe { &TLS_DECRYPT_BUF[..len] }
}

pub fn get_ws_message_records() -> &'static [WsMessageRecord] {
    let len = WS_MESSAGE_IDX.load(Ordering::Relaxed).min(BUFFER_CAPACITY);
    unsafe { &WS_MESSAGE_BUF[..len] }
}

pub fn clear_all_records() {
    TCP_ENQUEUE_IDX.store(0, Ordering::Relaxed);
    TCP_WAKE_IDX.store(0, Ordering::Relaxed);
    TLS_DECRYPT_IDX.store(0, Ordering::Relaxed);
    WS_MESSAGE_IDX.store(0, Ordering::Relaxed);
}

pub fn record_counts() -> (usize, usize, usize, usize) {
    (
        TCP_ENQUEUE_IDX.load(Ordering::Relaxed).min(BUFFER_CAPACITY),
        TCP_WAKE_IDX.load(Ordering::Relaxed).min(BUFFER_CAPACITY),
        TLS_DECRYPT_IDX.load(Ordering::Relaxed).min(BUFFER_CAPACITY),
        WS_MESSAGE_IDX.load(Ordering::Relaxed).min(BUFFER_CAPACITY),
    )
}
