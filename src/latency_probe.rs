//! Latency instrumentation for debugging DPDK scheduling.
//!
//! 多層獨立追蹤系統：
//! - TCP 層: rx_buffer enqueue, waker wake
//! - TLS 層: decrypt complete
//! - WebSocket 層: message complete
//!
//! 每層獨立記錄，通過 socket_id 和時間順序關聯。

use std::sync::atomic::{AtomicU64, Ordering};
use std::cell::{Cell, RefCell};

// ============================================================================
// 基礎設施
// ============================================================================

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

/// tick/exec_count 提供者函數類型
pub type TickProvider = fn() -> (u32, u64);

thread_local! {
    static TICK_PROVIDER: Cell<Option<TickProvider>> = const { Cell::new(None) };
    static TRACING_ENABLED: Cell<bool> = const { Cell::new(false) };
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
// 打樁點 ID（每層獨立定義範圍）
// ============================================================================

pub mod probe_ids {
    // TCP 層 (1-10)
    pub const TCP_RX_ENQUEUE: u8 = 1;
    pub const TCP_WAKER_WAKE: u8 = 2;
    pub const TCP_POLL_READ_READY: u8 = 3;
    pub const TCP_PEEK_START: u8 = 4;
    pub const TCP_PEEK_END: u8 = 5;
    pub const TCP_CONSUME: u8 = 6;

    // TLS 層 (11-20)
    pub const TLS_DECRYPT_START: u8 = 11;
    pub const TLS_DECRYPT_END: u8 = 12;

    // WebSocket 層 (21-30)
    pub const WS_RECV_START: u8 = 21;
    pub const WS_FRAME_COMPLETE: u8 = 22;
    pub const WS_MESSAGE_COMPLETE: u8 = 23;
}

// ============================================================================
// 追蹤記錄
// ============================================================================

/// 追蹤記錄 - 每個打樁點記錄一條
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct TraceRecord {
    pub ts_ns: u64,
    pub tick: u32,
    pub exec_count: u64,
    pub socket_id: usize,
    pub probe_id: u8,
    pub data_len: usize,
    /// 層內序列號（每層獨立遞增）
    pub layer_seq: u64,
}

thread_local! {
    static TRACE_BUFFER: RefCell<Vec<TraceRecord>> = RefCell::new(Vec::with_capacity(200_000));

    // 每個 socket 的層內序列號（使用 HashMap 會有開銷，改用簡單的全局計數）
    static TCP_SEQ: Cell<u64> = const { Cell::new(0) };
    static TLS_SEQ: Cell<u64> = const { Cell::new(0) };
    static WS_SEQ: Cell<u64> = const { Cell::new(0) };
}

#[inline(always)]
fn record_internal(socket_id: usize, probe_id: u8, data_len: usize, layer_seq: u64) {
    if !TRACING_ENABLED.with(|e| e.get()) {
        return;
    }

    let ts = now_ns();
    let (tick, exec_count) = get_tick_exec();

    TRACE_BUFFER.with(|buf| {
        let mut buf = buf.borrow_mut();
        if buf.len() < buf.capacity() {
            buf.push(TraceRecord {
                ts_ns: ts,
                tick,
                exec_count,
                socket_id,
                probe_id,
                data_len,
                layer_seq,
            });
        }
    });
}

// ============================================================================
// TCP 層追蹤
// ============================================================================

/// TCP 層: rx_buffer enqueue
#[inline(always)]
pub fn trace_tcp_rx_enqueue(socket_id: usize, data_len: usize) {
    let seq = TCP_SEQ.with(|s| {
        let v = s.get();
        s.set(v.wrapping_add(1));
        v
    });
    record_internal(socket_id, probe_ids::TCP_RX_ENQUEUE, data_len, seq);
}

/// TCP 層: waker.wake()
#[inline(always)]
pub fn trace_tcp_waker_wake(socket_id: usize) {
    let seq = TCP_SEQ.with(|s| s.get().saturating_sub(1)); // 使用上一個 enqueue 的 seq
    record_internal(socket_id, probe_ids::TCP_WAKER_WAKE, 0, seq);
}

/// TCP 層: poll_read_ready 返回 Ready
#[inline(always)]
pub fn trace_tcp_poll_ready(socket_id: usize, queue_len: usize) {
    let seq = TCP_SEQ.with(|s| s.get());
    record_internal(socket_id, probe_ids::TCP_POLL_READ_READY, queue_len, seq);
}

/// TCP 層: peek 開始
#[inline(always)]
pub fn trace_tcp_peek_start(socket_id: usize, queue_len: usize) {
    let seq = TCP_SEQ.with(|s| s.get());
    record_internal(socket_id, probe_ids::TCP_PEEK_START, queue_len, seq);
}

/// TCP 層: peek 結束
#[inline(always)]
pub fn trace_tcp_peek_end(socket_id: usize, peeked_len: usize) {
    let seq = TCP_SEQ.with(|s| s.get());
    record_internal(socket_id, probe_ids::TCP_PEEK_END, peeked_len, seq);
}

/// TCP 層: consume
#[inline(always)]
pub fn trace_tcp_consume(socket_id: usize, consumed_len: usize) {
    let seq = TCP_SEQ.with(|s| s.get());
    record_internal(socket_id, probe_ids::TCP_CONSUME, consumed_len, seq);
}

// ============================================================================
// TLS 層追蹤
// ============================================================================

/// TLS 層: decrypt 開始
#[inline(always)]
pub fn trace_tls_decrypt_start(socket_id: usize, input_len: usize) {
    let seq = TLS_SEQ.with(|s| {
        let v = s.get();
        s.set(v.wrapping_add(1));
        v
    });
    record_internal(socket_id, probe_ids::TLS_DECRYPT_START, input_len, seq);
}

/// TLS 層: decrypt 結束
#[inline(always)]
pub fn trace_tls_decrypt_end(socket_id: usize, output_len: usize) {
    let seq = TLS_SEQ.with(|s| s.get().saturating_sub(1));
    record_internal(socket_id, probe_ids::TLS_DECRYPT_END, output_len, seq);
}

// ============================================================================
// WebSocket 層追蹤
// ============================================================================

/// WebSocket 層: recv 開始
#[inline(always)]
pub fn trace_ws_recv_start(socket_id: usize) {
    let seq = WS_SEQ.with(|s| {
        let v = s.get();
        s.set(v.wrapping_add(1));
        v
    });
    record_internal(socket_id, probe_ids::WS_RECV_START, 0, seq);
}

/// WebSocket 層: frame 完成
#[inline(always)]
pub fn trace_ws_frame_complete(socket_id: usize, frame_len: usize) {
    let seq = WS_SEQ.with(|s| s.get().saturating_sub(1));
    record_internal(socket_id, probe_ids::WS_FRAME_COMPLETE, frame_len, seq);
}

/// WebSocket 層: message 完成
#[inline(always)]
pub fn trace_ws_message_complete(socket_id: usize, message_len: usize) {
    let seq = WS_SEQ.with(|s| s.get().saturating_sub(1));
    record_internal(socket_id, probe_ids::WS_MESSAGE_COMPLETE, message_len, seq);
}

// ============================================================================
// 數據導出
// ============================================================================

/// 獲取所有追蹤記錄
#[inline]
pub fn get_trace_records() -> Vec<TraceRecord> {
    TRACE_BUFFER.with(|buf| buf.borrow().clone())
}

/// 清空追蹤記錄
#[inline]
pub fn clear_trace_records() {
    TRACE_BUFFER.with(|buf| buf.borrow_mut().clear());
    TCP_SEQ.with(|s| s.set(0));
    TLS_SEQ.with(|s| s.set(0));
    WS_SEQ.with(|s| s.set(0));
}

/// 獲取追蹤記錄數量
#[inline]
pub fn trace_record_count() -> usize {
    TRACE_BUFFER.with(|buf| buf.borrow().len())
}

// ============================================================================
// 向後兼容的舊 API
// ============================================================================

thread_local! {
    static RX_ENQUEUE_TS: Cell<u64> = const { Cell::new(0) };
    static WAKER_WAKE_TS: Cell<u64> = const { Cell::new(0) };
    static RX_ENQUEUE_BYTES: Cell<usize> = const { Cell::new(0) };
}

static TOTAL_WAKE_CALLS: AtomicU64 = AtomicU64::new(0);

#[inline(always)]
pub fn record_rx_enqueue(bytes: usize) {
    let ts = now_ns();
    RX_ENQUEUE_TS.with(|cell| cell.set(ts));
    RX_ENQUEUE_BYTES.with(|cell| cell.set(bytes));
}

#[inline(always)]
pub fn record_waker_wake() {
    let ts = now_ns();
    WAKER_WAKE_TS.with(|cell| cell.set(ts));
    TOTAL_WAKE_CALLS.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn get_last_timestamps() -> (u64, u64, usize) {
    let rx_ts = RX_ENQUEUE_TS.with(|cell| cell.get());
    let wake_ts = WAKER_WAKE_TS.with(|cell| cell.get());
    let bytes = RX_ENQUEUE_BYTES.with(|cell| cell.get());
    (rx_ts, wake_ts, bytes)
}

#[inline]
pub fn get_total_wake_calls() -> u64 {
    TOTAL_WAKE_CALLS.load(Ordering::Relaxed)
}

#[derive(Debug, Clone, Copy)]
pub struct LatencyProbe {
    pub enqueue_to_wake_ns: u64,
    pub wake_to_recv_ns: u64,
    pub total_latency_ns: u64,
    pub bytes: usize,
}

impl LatencyProbe {
    #[inline]
    pub fn measure(recv_ts: u64) -> Self {
        let (enqueue_ts, wake_ts, bytes) = get_last_timestamps();

        Self {
            enqueue_to_wake_ns: wake_ts.saturating_sub(enqueue_ts),
            wake_to_recv_ns: recv_ts.saturating_sub(wake_ts),
            total_latency_ns: recv_ts.saturating_sub(enqueue_ts),
            bytes,
        }
    }
}
