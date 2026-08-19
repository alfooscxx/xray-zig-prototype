const std = @import("std");

const packet = @import("packet.zig");

pub const max_tx_segments = 32;
pub const initial_rto_ms: u64 = 300;
pub const maximum_rto_ms: u64 = 8_000;
pub const maximum_retries: u8 = 8;
pub const handshake_timeout_ms: u64 = 20_000;
pub const established_idle_timeout_ms: u64 = 300_000;

pub const Phase = enum {
    syn_received,
    established,
    closing,
    terminal,
};

pub const TxSegment = struct {
    sequence: u32,
    flags: packet.Flags,
    payload_len: u16,
    payload: [packet.max_tcp_payload]u8,
    sent_at_ms: u64,
    retransmits: u8 = 0,

    pub fn bytes(self: *const TxSegment) []const u8 {
        return self.payload[0..self.payload_len];
    }

    pub fn endSequence(self: *const TxSegment) u32 {
        return self.sequence +% @as(u32, self.payload_len) +%
            @as(u32, @intFromBool(self.flags.syn)) +%
            @as(u32, @intFromBool(self.flags.fin));
    }
};

pub const ReceiveResult = struct {
    payload_skip: u16 = 0,
    payload_len: u16 = 0,
    accepted_fin: bool = false,
    send_ack: bool = false,
    reset: bool = false,
    became_terminal: bool = false,
    fast_retransmit: ?TxSegment = null,
};

pub const State = struct {
    phase: Phase = .syn_received,
    recv_next: u32,
    send_una: u32,
    send_next: u32,
    send_window: u32,
    mss: u16,
    cwnd: u32,
    ssthresh: u32,
    duplicate_acks: u8 = 0,
    rto_ms: u64 = initial_rto_ms,
    started_at_ms: u64,
    last_activity_ms: u64,
    local_fin_sent: bool = false,
    local_fin_acked: bool = false,
    remote_fin: bool = false,
    timed_out: bool = false,
    tx: [max_tx_segments]TxSegment = undefined,
    tx_count: u8 = 0,

    pub fn init(client_sequence: u32, server_isn: u32, window: u16, mss: u16, now_ms: u64) State {
        const effective_mss = @max(@as(u16, 1), @min(mss, packet.max_tcp_payload));
        return .{
            .recv_next = client_sequence +% 1,
            .send_una = server_isn,
            .send_next = server_isn,
            .send_window = window,
            .mss = effective_mss,
            .cwnd = @as(u32, effective_mss) * 2,
            .ssthresh = @as(u32, effective_mss) * 32,
            .started_at_ms = now_ms,
            .last_activity_ms = now_ms,
        };
    }

    pub fn queueSynAck(self: *State, now_ms: u64) ?TxSegment {
        if (self.tx_count != 0) return null;
        return self.enqueue(&.{}, .{ .syn = true, .ack = true }, now_ms);
    }

    pub fn queueData(self: *State, bytes: []const u8, now_ms: u64) ?TxSegment {
        if (self.phase == .terminal or self.local_fin_sent or bytes.len == 0) return null;
        const allowance = self.sendAllowance();
        if (allowance == 0 or self.tx_count == max_tx_segments) return null;
        const len = @min(bytes.len, allowance, self.mss);
        return self.enqueue(bytes[0..len], .{ .ack = true, .psh = true }, now_ms);
    }

    pub fn queueFin(self: *State, now_ms: u64) ?TxSegment {
        if (self.phase == .terminal or self.local_fin_sent or self.tx_count == max_tx_segments or self.sendAllowance() == 0) return null;
        const segment = self.enqueue(&.{}, .{ .fin = true, .ack = true }, now_ms) orelse return null;
        self.local_fin_sent = true;
        self.phase = .closing;
        return segment;
    }

    pub fn onSegment(
        self: *State,
        sequence: u32,
        acknowledgment: u32,
        flags: packet.Flags,
        window: u16,
        payload_len: usize,
        now_ms: u64,
    ) ReceiveResult {
        var result: ReceiveResult = .{};
        if (self.phase == .terminal) return result;
        self.last_activity_ms = now_ms;

        if (flags.rst) {
            self.phase = .terminal;
            result.reset = true;
            result.became_terminal = true;
            return result;
        }

        if (flags.ack) {
            const duplicate_eligible = payload_len == 0 and !flags.syn and !flags.fin and self.send_window == window;
            self.send_window = window;
            result.fast_retransmit = self.acceptAck(acknowledgment, now_ms, duplicate_eligible);
        }

        if (self.phase == .syn_received and self.send_una == self.send_next) {
            self.phase = .established;
        }

        if (payload_len != 0 or flags.fin) {
            result.send_ack = true;
            if (self.phase == .syn_received) return result;

            const relative = sequenceDistance(sequence, self.recv_next);
            if (relative > 0) return result;

            var skip: usize = 0;
            if (relative < 0) {
                skip = @min(payload_len, @as(usize, @intCast(-@as(i64, relative))));
            }
            const accepted_len = payload_len - skip;
            if (accepted_len != 0) {
                self.recv_next +%= @intCast(accepted_len);
                result.payload_skip = @intCast(skip);
                result.payload_len = @intCast(accepted_len);
            }

            const fin_sequence = sequence +% @as(u32, @intCast(payload_len));
            if (flags.fin and fin_sequence == self.recv_next) {
                self.recv_next +%= 1;
                self.remote_fin = true;
                result.accepted_fin = true;
            }
        }

        self.updateTerminal(&result);
        return result;
    }

    pub fn retransmitDue(self: *State, now_ms: u64) ?TxSegment {
        if (self.phase == .terminal or self.tx_count == 0) return null;
        var oldest = &self.tx[0];
        if (now_ms -| oldest.sent_at_ms < self.rto_ms) return null;
        if (oldest.retransmits >= maximum_retries) {
            self.timed_out = true;
            self.phase = .terminal;
            return null;
        }
        oldest.retransmits += 1;
        oldest.sent_at_ms = now_ms;
        self.ssthresh = @max(self.cwnd / 2, @as(u32, self.mss) * 2);
        self.cwnd = self.mss;
        self.rto_ms = @min(self.rto_ms * 2, maximum_rto_ms);
        self.duplicate_acks = 0;
        return oldest.*;
    }

    pub fn expired(self: *State, now_ms: u64) bool {
        if (self.phase == .terminal) return true;
        const elapsed = if (self.phase == .syn_received)
            now_ms -| self.started_at_ms
        else
            now_ms -| self.last_activity_ms;
        const limit = if (self.phase == .syn_received) handshake_timeout_ms else established_idle_timeout_ms;
        if (elapsed < limit) return false;
        self.timed_out = true;
        self.phase = .terminal;
        return true;
    }

    pub fn outstanding(self: *const State) u32 {
        return self.send_next -% self.send_una;
    }

    fn sendAllowance(self: *const State) usize {
        const flight_limit = @min(self.send_window, self.cwnd);
        const in_flight = self.outstanding();
        if (in_flight >= flight_limit) return 0;
        return @intCast(flight_limit - in_flight);
    }

    fn enqueue(self: *State, payload: []const u8, flags: packet.Flags, now_ms: u64) ?TxSegment {
        if (payload.len > packet.max_tcp_payload or self.tx_count == max_tx_segments) return null;
        const index: usize = self.tx_count;
        self.tx[index] = .{
            .sequence = self.send_next,
            .flags = flags,
            .payload_len = @intCast(payload.len),
            .payload = undefined,
            .sent_at_ms = now_ms,
        };
        @memcpy(self.tx[index].payload[0..payload.len], payload);
        self.send_next = self.tx[index].endSequence();
        self.tx_count += 1;
        return self.tx[index];
    }

    fn acceptAck(self: *State, acknowledgment: u32, now_ms: u64, duplicate_eligible: bool) ?TxSegment {
        if (sequenceAfter(acknowledgment, self.send_next)) return null;
        if (!sequenceAfter(acknowledgment, self.send_una)) {
            if (duplicate_eligible and acknowledgment == self.send_una and self.tx_count != 0) {
                self.duplicate_acks +|= 1;
                if (self.duplicate_acks == 3) {
                    self.ssthresh = @max(self.cwnd / 2, @as(u32, self.mss) * 2);
                    self.cwnd = self.ssthresh + @as(u32, self.mss) * 3;
                    self.tx[0].sent_at_ms = now_ms;
                    self.tx[0].retransmits +|= 1;
                    return self.tx[0];
                }
            }
            return null;
        }

        const acknowledged_bytes = acknowledgment -% self.send_una;
        const acknowledged_handshake = self.phase == .syn_received;
        self.send_una = acknowledgment;
        self.duplicate_acks = 0;
        self.rto_ms = initial_rto_ms;
        self.discardAcknowledged(acknowledgment);
        if (acknowledged_handshake) return null;
        if (self.cwnd < self.ssthresh) {
            self.cwnd = @min(self.cwnd + acknowledged_bytes, @as(u32, self.mss) * 64);
        } else {
            const increase = @max(@as(u32, 1), (@as(u32, self.mss) * self.mss) / self.cwnd);
            self.cwnd = @min(self.cwnd + increase, @as(u32, self.mss) * 64);
        }
        if (self.local_fin_sent and self.tx_count == 0) self.local_fin_acked = true;
        return null;
    }

    fn discardAcknowledged(self: *State, acknowledgment: u32) void {
        var remove_count: usize = 0;
        while (remove_count < self.tx_count and
            !sequenceAfter(self.tx[remove_count].endSequence(), acknowledgment))
        {
            remove_count += 1;
        }
        if (remove_count != 0) {
            const remaining: usize = self.tx_count - remove_count;
            std.mem.copyForwards(TxSegment, self.tx[0..remaining], self.tx[remove_count..self.tx_count]);
            self.tx_count = @intCast(remaining);
        }

        if (self.tx_count == 0) return;
        var first = &self.tx[0];
        if (!sequenceAfter(acknowledgment, first.sequence)) return;
        const consumed: usize = @intCast(acknowledgment -% first.sequence);
        if (first.flags.syn) {
            first.flags.syn = false;
            first.sequence +%= 1;
            return;
        }
        const payload_consumed = @min(consumed, first.payload_len);
        if (payload_consumed != 0) {
            const remaining = first.payload_len - payload_consumed;
            std.mem.copyForwards(u8, first.payload[0..remaining], first.payload[payload_consumed..first.payload_len]);
            first.payload_len = @intCast(remaining);
            first.sequence +%= @intCast(payload_consumed);
        }
    }

    fn updateTerminal(self: *State, result: *ReceiveResult) void {
        if (self.remote_fin and self.local_fin_acked) {
            self.phase = .terminal;
            result.became_terminal = true;
        }
    }
};

pub fn sequenceAfter(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) > 0;
}

pub fn sequenceDistance(a: u32, b: u32) i32 {
    return @bitCast(a -% b);
}

test "sequence arithmetic crosses wraparound" {
    try std.testing.expect(sequenceAfter(1, 0xfffffff0));
    try std.testing.expect(!sequenceAfter(0xfffffff0, 1));
    try std.testing.expectEqual(@as(i32, 17), sequenceDistance(1, 0xfffffff0));
}

test "SYN and data are retransmitted with exponential RTO" {
    var state = State.init(100, 0xfffffff0, 65535, 1000, 0);
    const syn = state.queueSynAck(0).?;
    try std.testing.expectEqual(@as(u32, 0xfffffff0), syn.sequence);
    try std.testing.expect(state.retransmitDue(initial_rto_ms - 1) == null);
    const retry = state.retransmitDue(initial_rto_ms).?;
    try std.testing.expect(retry.flags.syn);
    try std.testing.expectEqual(@as(u8, 1), retry.retransmits);
    try std.testing.expectEqual(initial_rto_ms * 2, state.rto_ms);

    _ = state.onSegment(101, 0xfffffff1, .{ .ack = true }, 65535, 0, 301);
    try std.testing.expectEqual(Phase.established, state.phase);
    const data = state.queueData("abc", 302).?;
    try std.testing.expectEqual(@as(u32, 0xfffffff1), data.sequence);
    try std.testing.expectEqual(@as(u32, 0xfffffff4), state.send_next);
}

test "ACK advances a partially acknowledged segment and handles duplicate ACKs" {
    var state = State.init(10, 20, 65535, 1000, 0);
    _ = state.queueSynAck(0);
    _ = state.onSegment(11, 21, .{ .ack = true }, 65535, 0, 1);
    _ = state.queueData("abcdef", 2);
    _ = state.onSegment(11, 24, .{ .ack = true }, 65535, 0, 3);
    try std.testing.expectEqual(@as(u32, 24), state.tx[0].sequence);
    try std.testing.expectEqualStrings("def", state.tx[0].bytes());
    try std.testing.expect(state.onSegment(11, 24, .{ .ack = true }, 65535, 0, 4).fast_retransmit == null);
    try std.testing.expect(state.onSegment(11, 24, .{ .ack = true }, 65535, 0, 5).fast_retransmit == null);
    const fast = state.onSegment(11, 24, .{ .ack = true }, 65535, 0, 6).fast_retransmit.?;
    try std.testing.expectEqualStrings("def", fast.bytes());
}

test "out of order data is rejected and overlapping retransmit is trimmed" {
    var state = State.init(100, 500, 65535, 1000, 0);
    _ = state.queueSynAck(0);
    _ = state.onSegment(101, 501, .{ .ack = true }, 65535, 0, 1);
    const future = state.onSegment(105, 501, .{ .ack = true }, 65535, 3, 2);
    try std.testing.expectEqual(@as(u16, 0), future.payload_len);
    try std.testing.expectEqual(@as(u32, 101), state.recv_next);
    const first = state.onSegment(101, 501, .{ .ack = true }, 65535, 6, 3);
    try std.testing.expectEqual(@as(u16, 6), first.payload_len);
    const overlap = state.onSegment(104, 501, .{ .ack = true }, 65535, 6, 4);
    try std.testing.expectEqual(@as(u16, 3), overlap.payload_skip);
    try std.testing.expectEqual(@as(u16, 3), overlap.payload_len);
    try std.testing.expectEqual(@as(u32, 110), state.recv_next);
}

test "FIN requires both half closes before terminal state" {
    var state = State.init(0xfffffff0, 100, 65535, 1000, 0);
    _ = state.queueSynAck(0);
    _ = state.onSegment(0xfffffff1, 101, .{ .ack = true }, 65535, 0, 1);
    const remote_fin = state.onSegment(0xfffffff1, 101, .{ .ack = true, .fin = true }, 65535, 0, 2);
    try std.testing.expect(remote_fin.accepted_fin);
    try std.testing.expectEqual(Phase.established, state.phase);
    const fin = state.queueFin(3).?;
    try std.testing.expectEqual(@as(u32, 101), fin.sequence);
    const ack = state.onSegment(0xfffffff2, 102, .{ .ack = true }, 65535, 0, 4);
    try std.testing.expect(ack.became_terminal);
    try std.testing.expectEqual(Phase.terminal, state.phase);
}

test "handshake and established idle deadlines are bounded" {
    var half_open = State.init(1, 2, 65535, 1000, 0);
    _ = half_open.queueSynAck(0);
    _ = half_open.onSegment(1, 0, .{ .syn = true }, 65535, 0, handshake_timeout_ms - 1);
    try std.testing.expect(!half_open.expired(handshake_timeout_ms - 1));
    try std.testing.expect(half_open.expired(handshake_timeout_ms));

    var established = State.init(1, 2, 65535, 1000, 0);
    _ = established.queueSynAck(0);
    _ = established.onSegment(2, 3, .{ .ack = true }, 65535, 0, 1);
    try std.testing.expect(!established.expired(established_idle_timeout_ms));
    try std.testing.expect(established.expired(established_idle_timeout_ms + 1));
}

test "send memory and congestion window are bounded" {
    var state = State.init(1, 2, 65535, 100, 0);
    _ = state.queueSynAck(0);
    _ = state.onSegment(2, 3, .{ .ack = true }, 65535, 0, 1);
    const payload = [_]u8{0xaa} ** 1000;
    var queued: usize = 0;
    while (state.queueData(payload[queued..], 2)) |segment| queued += segment.payload_len;
    try std.testing.expectEqual(@as(usize, 200), queued);
    try std.testing.expect(state.tx_count <= max_tx_segments);
    try std.testing.expect(@sizeOf(State) < 64 * 1024);
}

test "zero window blocks data until an update arrives" {
    var state = State.init(1, 10, 0, 1000, 0);
    _ = state.queueSynAck(0);
    _ = state.onSegment(2, 11, .{ .ack = true }, 0, 0, 1);
    try std.testing.expect(state.queueData("blocked", 2) == null);
    _ = state.onSegment(2, 11, .{ .ack = true }, 4096, 0, 3);
    try std.testing.expectEqualStrings("open", state.queueData("open", 4).?.bytes());
}

test "invalid ACK cannot release queued bytes" {
    var state = State.init(1, 100, 65535, 1000, 0);
    _ = state.queueSynAck(0);
    _ = state.onSegment(2, 101, .{ .ack = true }, 65535, 0, 1);
    _ = state.queueData("payload", 2);
    const before_una = state.send_una;
    const before_count = state.tx_count;
    _ = state.onSegment(2, state.send_next +% 100, .{ .ack = true }, 65535, 0, 3);
    try std.testing.expectEqual(before_una, state.send_una);
    try std.testing.expectEqual(before_count, state.tx_count);
}

test "retransmission retry budget eventually terminates a flow" {
    var state = State.init(1, 100, 65535, 1000, 0);
    _ = state.queueSynAck(0);
    var now: u64 = 0;
    var retries: u8 = 0;
    while (state.phase != .terminal) {
        now += state.rto_ms;
        if (state.retransmitDue(now) != null) retries += 1;
    }
    try std.testing.expectEqual(maximum_retries, retries);
    try std.testing.expect(state.timed_out);
}

test "data acknowledgment crosses sequence wraparound" {
    var state = State.init(1, 0xfffffffd, 65535, 1000, 0);
    _ = state.queueSynAck(0);
    _ = state.onSegment(2, 0xfffffffe, .{ .ack = true }, 65535, 0, 1);
    _ = state.queueData("wrap", 2);
    try std.testing.expectEqual(@as(u32, 2), state.send_next);
    _ = state.onSegment(2, 2, .{ .ack = true }, 65535, 0, 3);
    try std.testing.expectEqual(@as(u8, 0), state.tx_count);
    try std.testing.expectEqual(@as(u32, 2), state.send_una);
}
