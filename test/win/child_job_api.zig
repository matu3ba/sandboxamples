//! Test killing child kills all 6 descendants based on
//! Descendent processes intended to be named "evildescendent" for checks.
const std = @import("std");
const sec = @import("sec");
const ossec = sec.os;
const childsec = sec.child;

pub fn main() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const arena = arena_state.allocator();
    defer arena_state.deinit();
    behavior(arena) catch |err| {
        std.debug.print("err: {}", .{err});
        return error.ErrorInChild;
    };
}

fn behavior(gpa: std.mem.Allocator) !void {
    var it = try std.process.argsWithAllocator(gpa);
    defer it.deinit();
    const child_path = it.next() orelse unreachable;
    const cli_number = it.next() orelse @panic("missing number for self spawn");
    const number = try std.fmt.parseUnsigned(u16, cli_number, 10);

    // self spawn
    if (number > 0) {
        const next_num = number - 1;
        var next_num_buf: [5]u8 = undefined;
        const next_num_s = try std.fmt.bufPrint(next_num_buf[0..], "{d}", .{next_num});
        var child = childsec.ChildProcess.init(&.{ child_path, next_num_s }, gpa);
        child.stdin_behavior = .Close;
        child.stdout_behavior = .Inherit;
        child.stderr_behavior = .Inherit;

        // TODO finish up
    }

    // switch (number) {
    //     0 => {},
    //     1 => attack1(),
    //     2 => attack2(),
    //     3 => attack3(),
    //     4 => attack4(),
    //     5 => attack5(),
    //     6 => attack6(),
    // }
}

// fn attack1() void { }
// fn attack2() void { }
// fn attack3() void { }
// fn attack4() void { }
// fn attack5() void { }
// fn attack6() void { }