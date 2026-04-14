// Pcap file writer.
//
// Standard pcap format (little-endian, microsecond timestamps,
// LINKTYPE_ETHERNET). Compatible with Wireshark and tcpdump.

const std = @import("std");
const packet = @import("packet.zig");

/// Pcap global header (24 bytes).
const GlobalHeader = extern struct {
    magic: u32 = 0xa1b2c3d4,
    version_major: u16 = 2,
    version_minor: u16 = 4,
    thiszone: i32 = 0,
    sigfigs: u32 = 0,
    snaplen: u32 = packet.snap_len,
    network: u32 = 1, // LINKTYPE_ETHERNET
};

/// Pcap per-packet header (16 bytes).
const PacketHeader = extern struct {
    ts_sec: u32,
    ts_usec: u32,
    incl_len: u32,
    orig_len: u32,
};

pub const ExportError = error{
    CreateFailed,
    WriteFailed,
};

/// Write visible packets to a pcap file. Returns the number of packets written.
pub fn exportPackets(
    path: []const u8,
    packets: []const packet.PacketInfo,
    filter_fn: ?*const fn (*const packet.PacketInfo) bool,
) ExportError!usize {
    var path_buf: [256]u8 = undefined;
    if (path.len >= path_buf.len) return error.CreateFailed;
    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;

    const file = std.fs.cwd().createFile(
        path_buf[0..path.len :0],
        .{},
    ) catch return error.CreateFailed;
    defer file.close();

    const ghdr: GlobalHeader = .{};
    file.writeAll(std.mem.asBytes(&ghdr)) catch return error.WriteFailed;

    var count: usize = 0;
    for (packets) |*pkt| {
        if (filter_fn) |matches| {
            if (!matches(pkt)) continue;
        }
        if (pkt.raw_len == 0) continue;

        const ts_ms: u64 = @intCast(pkt.timestamp_ms);
        const phdr: PacketHeader = .{
            .ts_sec = @intCast(ts_ms / 1000),
            .ts_usec = @intCast((ts_ms % 1000) * 1000),
            .incl_len = pkt.raw_len,
            .orig_len = pkt.length,
        };
        file.writeAll(std.mem.asBytes(&phdr)) catch return error.WriteFailed;
        file.writeAll(pkt.raw[0..pkt.raw_len]) catch return error.WriteFailed;
        count += 1;
    }

    return count;
}

/// Write pcap global header to an open file (for streaming capture).
pub fn writeGlobalHeader(file: std.fs.File) std.fs.File.WriteError!void {
    const ghdr: GlobalHeader = .{};
    try file.writeAll(std.mem.asBytes(&ghdr));
}

/// Append a single packet record to an open pcap file.
pub fn writePacketRecord(file: std.fs.File, pkt: *const packet.PacketInfo) std.fs.File.WriteError!void {
    if (pkt.raw_len == 0) return;
    const ts_ms: u64 = @intCast(pkt.timestamp_ms);
    const phdr: PacketHeader = .{
        .ts_sec = @intCast(ts_ms / 1000),
        .ts_usec = @intCast((ts_ms % 1000) * 1000),
        .incl_len = pkt.raw_len,
        .orig_len = pkt.length,
    };
    try file.writeAll(std.mem.asBytes(&phdr));
    try file.writeAll(pkt.raw[0..pkt.raw_len]);
}
