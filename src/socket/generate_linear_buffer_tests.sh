#!/bin/bash
# Generate LinearBuffer TCP tests from RingBuffer tests
# This script extracts tests from tcp.rs and adapts them for LinearBuffer

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TCP_RS="${SCRIPT_DIR}/tcp.rs"
OUTPUT="${SCRIPT_DIR}/tcp_linear_buffer_tests.inc.rs"

# Tests to exclude (RingBuffer-specific or window calculation differences)
EXCLUDED_TESTS=(
    # RingBuffer-specific wraparound tests
    "test_buffer_wraparound_rx"
    "test_buffer_wraparound_tx"
    # Window calculation difference tests
    "test_announce_window_after_read"
    "test_zero_window_ack_on_window_growth"
    "test_window_update_with_delay_ack"
    "test_out_of_order"
    "test_established_fin_after_missing"
    "test_recv_out_of_recv_win"
    "test_rx_close_fin_with_hole"
    "test_rx_close_rst_with_hole"
    # RFC 2018 cases - window size expectations differ
    "test_established_rfc2018_cases"
)

# Helper functions to exclude (will be redefined in the module)
EXCLUDED_HELPERS=(
    "socket_listen"
    "setup_rfc2018_cases"
)

echo "Generating LinearBuffer tests..."

# Step 1: Extract tests section (line 3194 to 8904)
sed -n '3194,8904p' "$TCP_RS" > "$OUTPUT"

# Step 2: Replace SocketBuffer::new with BufferType::new
sed -i 's/SocketBuffer::new/BufferType::new/g' "$OUTPUT"

# Step 3: Remove excluded helper functions using awk
for helper in "${EXCLUDED_HELPERS[@]}"; do
    echo "  Removing helper function: $helper"
    awk -v fname="$helper" '
    /^    fn / && $0 ~ fname"\\(\\)" { skip=1 }
    skip && /^    }$/ { skip=0; next }
    !skip { print }
    ' "$OUTPUT" > "$OUTPUT.tmp" && mv "$OUTPUT.tmp" "$OUTPUT"
done

# Step 4: Remove excluded tests using awk
for test in "${EXCLUDED_TESTS[@]}"; do
    echo "  Removing test: $test"
    awk -v tname="$test" '
    /^    #\[test\]/ { 
        testline=$0
        getline
        if ($0 ~ "fn "tname"\\(\\)") {
            skip=1
            next
        } else {
            print testline
            print
            next
        }
    }
    skip && /^    }$/ { skip=0; next }
    !skip { print }
    ' "$OUTPUT" > "$OUTPUT.tmp" && mv "$OUTPUT.tmp" "$OUTPUT"
done

# Count remaining tests
TEST_COUNT=$(grep -c "^    #\[test\]" "$OUTPUT" || echo "0")
echo "Generated $OUTPUT with $TEST_COUNT tests (original: 174, excluded: ${#EXCLUDED_TESTS[@]})"
echo "Expected: $((174 - ${#EXCLUDED_TESTS[@]}))"
