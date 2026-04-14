// Linux process attribution via /proc/net and /proc/<pid>/fd.
//
// Joins socket inodes from /proc/net/{tcp,tcp6,udp,udp6} with
// file descriptors in /proc/<pid>/fd to map connections to PIDs.

const std = @import("std");
const builtin = @import("builtin");
const packet = @import("packet.zig");

const max_sockets = 4096;
const max_procs = 2048;

const SocketEntry = struct {
    local_port: u16,
    remote_port: u16,
    proto: packet.Protocol,
    inode: u64,
};

const InodeProc = struct {
    inode: u64,
    pid: u32,
    name: [16]u8,
    name_len: u8,
};

pub const ProcResult = struct {
    pid: u32,
    name: []const u8,
};

pub const ProcTable = struct {
    sockets: [max_sockets]SocketEntry = undefined,
    socket_count: usize = 0,
    procs: [max_procs]InodeProc = undefined,
    proc_count: usize = 0,
    last_refresh: i64 = 0,

    /// Refresh the proc table by scanning /proc. Call periodically.
    pub fn refresh(self: *ProcTable) void {
        if (comptime builtin.os.tag != .linux) return;
        self.socket_count = 0;
        self.proc_count = 0;
        self.readNetTable("/proc/net/tcp", .tcp);
        self.readNetTable("/proc/net/tcp6", .tcp);
        self.readNetTable("/proc/net/udp", .udp);
        self.readNetTable("/proc/net/udp6", .udp);
        self.scanProcFds();
        self.last_refresh = std.time.milliTimestamp();
    }

    /// Look up the owning process for a packet.
    pub fn lookup(self: *const ProcTable, pkt: *const packet.PacketInfo) ?ProcResult {
        if (self.socket_count == 0) return null;
        if (self.findByPort(pkt.protocol, pkt.src_port, pkt.dst_port)) |r| return r;
        if (self.findByPort(pkt.protocol, pkt.dst_port, pkt.src_port)) |r| return r;
        return null;
    }

    fn findByPort(self: *const ProcTable, proto: packet.Protocol, local_port: u16, remote_port: u16) ?ProcResult {
        if (local_port == 0) return null;
        for (self.sockets[0..self.socket_count]) |s| {
            if (s.proto != proto) continue;
            if (s.local_port != local_port) continue;
            if (s.remote_port != 0 and remote_port != 0 and s.remote_port != remote_port) continue;
            if (self.findProc(s.inode)) |p| return p;
        }
        return null;
    }

    fn findProc(self: *const ProcTable, inode: u64) ?ProcResult {
        for (self.procs[0..self.proc_count]) |p| {
            if (p.inode == inode) return .{ .pid = p.pid, .name = p.name[0..p.name_len] };
        }
        return null;
    }

    fn readNetTable(self: *ProcTable, path: []const u8, proto: packet.Protocol) void {
        var path_buf: [32]u8 = undefined;
        @memcpy(path_buf[0..path.len], path);
        path_buf[path.len] = 0;
        const file = std.fs.openFileAbsoluteZ(path_buf[0..path.len :0], .{}) catch return;
        defer file.close();
        var buf: [8192]u8 = undefined;
        var carry: [512]u8 = undefined;
        var carry_len: usize = 0;
        var first_line = true;
        while (true) {
            const n = file.read(&buf) catch return;
            if (n == 0 and carry_len == 0) break;
            var data: []const u8 = buf[0..n];
            while (true) {
                // Prepend any leftover from last chunk
                var line_buf: [1024]u8 = undefined;
                var line_len: usize = carry_len;
                if (carry_len > 0) {
                    @memcpy(line_buf[0..carry_len], carry[0..carry_len]);
                    carry_len = 0;
                }
                if (std.mem.indexOfScalar(u8, data, '\n')) |nl| {
                    const chunk = data[0..nl];
                    const copy = @min(chunk.len, line_buf.len - line_len);
                    @memcpy(line_buf[line_len..][0..copy], chunk[0..copy]);
                    line_len += copy;
                    data = data[nl + 1 ..];
                } else {
                    // No newline - save remainder for next read
                    const copy = @min(data.len, carry.len);
                    @memcpy(carry[0..copy], data[0..copy]);
                    carry_len = copy;
                    break;
                }
                if (first_line) {
                    first_line = false;
                    continue;
                }
                if (self.socket_count >= max_sockets) return;
                if (parseProcNetLine(line_buf[0..line_len], proto)) |entry| {
                    self.sockets[self.socket_count] = entry;
                    self.socket_count += 1;
                }
            }
            if (n == 0) break;
        }
    }

    fn scanProcFds(self: *ProcTable) void {
        var proc_dir = std.fs.openDirAbsolute("/proc", .{ .iterate = true }) catch return;
        defer proc_dir.close();
        var iter = proc_dir.iterate();
        while (iter.next() catch null) |entry| {
            if (entry.kind != .directory) continue;
            const pid = std.fmt.parseInt(u32, entry.name, 10) catch continue;
            self.scanOnePid(pid, entry.name);
        }
    }

    fn scanOnePid(self: *ProcTable, pid: u32, pid_str: []const u8) void {
        // Read /proc/<pid>/comm for the process name
        var comm_path: [32]u8 = undefined;
        const comm_s = std.fmt.bufPrint(&comm_path, "/proc/{s}/comm", .{pid_str}) catch return;
        comm_path[comm_s.len] = 0;
        var name_buf: [16]u8 = .{0} ** 16;
        var name_len: u8 = 0;
        {
            const f = std.fs.openFileAbsoluteZ(comm_path[0..comm_s.len :0], .{}) catch return;
            defer f.close();
            const n = f.read(&name_buf) catch return;
            // Strip trailing newline
            name_len = @intCast(if (n > 0 and name_buf[n - 1] == '\n') n - 1 else n);
        }
        if (name_len == 0) return;

        // Scan /proc/<pid>/fd/ for socket inodes
        var fd_path: [32]u8 = undefined;
        const fd_s = std.fmt.bufPrint(&fd_path, "/proc/{s}/fd", .{pid_str}) catch return;
        fd_path[fd_s.len] = 0;
        var fd_dir = std.fs.openDirAbsoluteZ(fd_path[0..fd_s.len :0], .{ .iterate = true }) catch return;
        defer fd_dir.close();
        var fd_iter = fd_dir.iterate();
        while (fd_iter.next() catch null) |fd_entry| {
            if (fd_entry.kind != .sym_link) continue;
            var link_buf: [64]u8 = undefined;
            const link = fd_dir.readLink(fd_entry.name, &link_buf) catch continue;
            // Format: "socket:[12345]"
            if (link.len < 9) continue;
            if (!std.mem.eql(u8, link[0..8], "socket:[")) continue;
            if (link[link.len - 1] != ']') continue;
            const inode = std.fmt.parseInt(u64, link[8 .. link.len - 1], 10) catch continue;
            if (self.proc_count >= max_procs) return;
            self.procs[self.proc_count] = .{
                .inode = inode,
                .pid = pid,
                .name = name_buf,
                .name_len = name_len,
            };
            self.proc_count += 1;
        }
    }
};

/// Parse one line from /proc/net/{tcp,tcp6,udp,udp6}.
/// Format: "  sl  local_address rem_address   st ..."
/// Addresses are hex IP:PORT. We only need the ports and inode.
fn parseProcNetLine(line: []const u8, proto: packet.Protocol) ?SocketEntry {
    // Tokenize by whitespace. We need fields:
    //   [0] sl, [1] local_address, [2] rem_address, [3] st, ...
    //   inode is field [9]
    var fields: [12][]const u8 = undefined;
    var fc: usize = 0;
    var i: usize = 0;
    while (i < line.len and fc < 12) {
        while (i < line.len and line[i] == ' ') : (i += 1) {}
        if (i >= line.len) break;
        const start = i;
        while (i < line.len and line[i] != ' ') : (i += 1) {}
        fields[fc] = line[start..i];
        fc += 1;
    }
    if (fc < 10) return null;

    const local_port = parseHexPort(fields[1]) orelse return null;
    const remote_port = parseHexPort(fields[2]) orelse return null;
    const inode = std.fmt.parseInt(u64, fields[9], 10) catch return null;
    if (inode == 0) return null;

    return .{
        .local_port = local_port,
        .remote_port = remote_port,
        .proto = proto,
        .inode = inode,
    };
}

/// Extract port from "HEXADDR:HEXPORT" format.
fn parseHexPort(field: []const u8) ?u16 {
    const colon = std.mem.lastIndexOfScalar(u8, field, ':') orelse return null;
    if (colon + 1 >= field.len) return null;
    return std.fmt.parseInt(u16, field[colon + 1 ..], 16) catch null;
}

// -- Tests --

test "parseHexPort extracts port" {
    try std.testing.expectEqual(@as(?u16, 80), parseHexPort("0100007F:0050"));
    try std.testing.expectEqual(@as(?u16, 443), parseHexPort("0100007F:01BB"));
    try std.testing.expectEqual(@as(?u16, 0), parseHexPort("00000000:0000"));
    try std.testing.expect(parseHexPort("noport") == null);
}

test "parseProcNetLine parses tcp line" {
    const line = "   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0";
    const entry = parseProcNetLine(line, .tcp) orelse {
        return error.TestUnexpectedResult;
    };
    try std.testing.expectEqual(@as(u16, 53), entry.local_port);
    try std.testing.expectEqual(@as(u16, 0), entry.remote_port);
    try std.testing.expectEqual(@as(u64, 12345), entry.inode);
    try std.testing.expectEqual(packet.Protocol.tcp, entry.proto);
}

test "parseProcNetLine skips zero inode" {
    const line = "   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 0 1 0000000000000000 100 0 0 10 0";
    try std.testing.expect(parseProcNetLine(line, .tcp) == null);
}

test "parseProcNetLine parses tcp6 line" {
    const line = "   0: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 67890 1 0000000000000000 100 0 0 10 0";
    const entry = parseProcNetLine(line, .tcp) orelse {
        return error.TestUnexpectedResult;
    };
    try std.testing.expectEqual(@as(u16, 80), entry.local_port);
    try std.testing.expectEqual(@as(u64, 67890), entry.inode);
}

test "parseProcNetLine rejects short line" {
    try std.testing.expect(parseProcNetLine("too short", .tcp) == null);
}

test "ProcTable lookup returns null on empty table" {
    const table = ProcTable{};
    var pkt: packet.PacketInfo = .{ .protocol = .tcp, .src_port = 443, .dst_port = 54321 };
    try std.testing.expect(table.lookup(&pkt) == null);
}

test "ProcTable lookup matches by port" {
    var table = ProcTable{};
    table.sockets[0] = .{ .local_port = 443, .remote_port = 0, .proto = .tcp, .inode = 100 };
    table.socket_count = 1;
    var name: [16]u8 = .{0} ** 16;
    @memcpy(name[0..5], "nginx");
    table.procs[0] = .{ .inode = 100, .pid = 1234, .name = name, .name_len = 5 };
    table.proc_count = 1;

    var pkt: packet.PacketInfo = .{ .protocol = .tcp, .src_port = 443, .dst_port = 54321 };
    const result = table.lookup(&pkt) orelse {
        return error.TestUnexpectedResult;
    };
    try std.testing.expectEqual(@as(u32, 1234), result.pid);
    try std.testing.expectEqualStrings("nginx", result.name);
}

test "ProcTable lookup tries both directions" {
    var table = ProcTable{};
    table.sockets[0] = .{ .local_port = 8080, .remote_port = 0, .proto = .tcp, .inode = 200 };
    table.socket_count = 1;
    var name: [16]u8 = .{0} ** 16;
    @memcpy(name[0..4], "node");
    table.procs[0] = .{ .inode = 200, .pid = 5678, .name = name, .name_len = 4 };
    table.proc_count = 1;

    // Packet where dst_port is the local port
    var pkt: packet.PacketInfo = .{ .protocol = .tcp, .src_port = 54321, .dst_port = 8080 };
    const result = table.lookup(&pkt) orelse {
        return error.TestUnexpectedResult;
    };
    try std.testing.expectEqual(@as(u32, 5678), result.pid);
    try std.testing.expectEqualStrings("node", result.name);
}

test "ProcTable lookup does not cross protocols" {
    var table = ProcTable{};
    table.sockets[0] = .{ .local_port = 53, .remote_port = 0, .proto = .udp, .inode = 300 };
    table.socket_count = 1;
    var name: [16]u8 = .{0} ** 16;
    @memcpy(name[0..8], "dnsmasq\x00");
    table.procs[0] = .{ .inode = 300, .pid = 999, .name = name, .name_len = 7 };
    table.proc_count = 1;

    // TCP on port 53 should not match UDP socket
    var pkt: packet.PacketInfo = .{ .protocol = .tcp, .src_port = 53, .dst_port = 12345 };
    try std.testing.expect(table.lookup(&pkt) == null);

    // UDP on port 53 should match
    var pkt2: packet.PacketInfo = .{ .protocol = .udp, .src_port = 53, .dst_port = 12345 };
    try std.testing.expect(table.lookup(&pkt2) != null);
}
