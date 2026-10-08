// Compiled packet/finite-storage probe; Python independently decodes the bytes.
const std = @import("std");
const abi = @import("abi.zig");
const snapshot = @import("snapshot.zig");
const wire = @import("snapshot_wire.zig");
const analysis = @import("analysis_wire.zig");
const contracts = @import("contract_wire.zig");
fn hex(bytes: [32]u8) [64]u8 {
    const digits = "0123456789abcdef";
    var result: [64]u8 = undefined;
    for (bytes, 0..) |byte, index| {
        result[index * 2] = digits[byte >> 4];
        result[index * 2 + 1] = digits[byte & 15];
    }
    return result;
}
pub fn main() !void {
    const reference: snapshot.Ref = .{ .issuer = 0x123456789002, .token = 0x4242a2 };
    const transaction: u64 = 0x123456789abcdef;
    const packets = [_]abi.Message{
        wire.control(transaction, 0x1122334455667788, 0, .create),
        wire.control(transaction + 1, reference.token, 0xabcdef05, .bind_check),
        wire.read(.snapshot_read, transaction + 2, reference, 127, 1),
        wire.release(transaction + 3, reference, 0xabcdef06),
        wire.readReply(transaction + 4, reference, 127, 1, &.{255}),
        contracts.encode(16, .{ .id = transaction + 5, .command = .analysis_tuple, .kind = .response, .detail = 2, .token = contracts.token(0x4242, 1, 0xabcd05).?, .data = 128 | (127 << 16) }),
    };
    const tuple = analysis.calculate(&.{ 0, 255, 10, 128, 0, 10 }).?;
    var buffer: [4096]u8 = undefined;
    const output = try std.fmt.bufPrint(&buffer, "{{\"message_size\":{d},\"record_size\":{d},\"table_size\":{d},\"server_size\":{d},\"reader_size\":{d},\"results_size\":{d},\"broker_size\":{d},\"tuple\":[{d},{d},{d}],\"packets\":[\"{s}\",\"{s}\",\"{s}\",\"{s}\",\"{s}\",\"{s}\"]}}\n", .{ @sizeOf(abi.Message), @sizeOf(snapshot.Record), @sizeOf(snapshot.Table), @sizeOf(@import("storage_runtime.zig").Server), @sizeOf(@import("snapshot_client.zig").Reader), @sizeOf(analysis.Results), @sizeOf(@import("contract_core.zig").Broker), tuple.length, tuple.newlines, tuple.digest, hex(packets[0].payload), hex(packets[1].payload), hex(packets[2].payload), hex(packets[3].payload), hex(packets[4].payload), hex(packets[5].payload) });
    var offset: usize = 0;
    while (offset < output.len) offset += try std.posix.write(1, output[offset..]);
}
