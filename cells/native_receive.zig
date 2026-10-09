// Native service adapters keep an enqueued RPC pending across finite timeout
// wakeups. Every wake, including unrelated traffic, consumes the existing
// storage receive budget; no request is retransmitted or rebound here.
const abi = @import("abi.zig");
const transport = @import("storage_transport.zig");

pub const ticks = transport.receive_ticks;
pub const Action = enum { message, retry, failed };

pub const Budget = struct {
    endpoint: u64,
    attempts: u8 = 0,
    failed: bool = false,

    pub fn canReceive(self: *const Budget) bool {
        return !self.failed and self.endpoint != 0 and self.attempts < transport.receive_limit;
    }

    pub fn received(self: *Budget, current_endpoint: u64, result: i32) Action {
        if (!self.canReceive()) return .failed;
        self.attempts += 1;
        // A timeout never authorizes continuing against a replacement service.
        if (current_endpoint != self.endpoint) {
            self.failed = true;
            return .failed;
        }
        if (result == @intFromEnum(abi.Error.timeout) and self.attempts < transport.receive_limit) return .retry;
        if (result != 0) {
            self.failed = true;
            return .failed;
        }
        return .message;
    }
};
