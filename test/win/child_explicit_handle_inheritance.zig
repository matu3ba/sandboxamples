const std = @import("std");
const sec = @import("sec");
const ossec = sec.os;

pub fn main() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const arena = arena_state.allocator();
    defer arena_state.deinit();
    run(arena) catch |err| {
        std.debug.print("err: {}", .{err});
    };
}

fn run(allocator: std.mem.Allocator) !void {
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    _ = args.next() orelse @panic("no binary name"); // skip binary name

    var i: u16 = 0;

    while (true) {
        var msg_buf: [100]u8 = undefined;
        const s_handle = args.next() orelse break;
        const file_h = try ossec.stringToHandle(s_handle);
        defer std.os.close(file_h);
        const is_inheritable = try ossec.isInheritable(file_h);
        std.debug.assert(is_inheritable);
        try ossec.disableInheritance(file_h);
        var file = std.fs.File{ .handle = file_h };
        const file_wr = file.writer();

        const file_msg = try std.fmt.bufPrint(msg_buf[0..], "testfile{d}", .{i});
        try file_wr.writeAll(file_msg);
        i += 1;
    }
}