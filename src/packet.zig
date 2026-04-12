// Network packet header parser.
//
// Parses Ethernet frames containing IPv4, IPv6, or ARP payloads
// and extracts addresses, ports, protocol, and basic metadata.

const std = @import("std");

pub const Protocol = enum(u8) {
    tcp = 6,
    udp = 17,
    icmp = 1,
    icmp6 = 58,
    arp = 0,
    other = 255,

    /// Human-readable protocol label.
    pub fn name(self: Protocol) []const u8 {
        return switch (self) {
            .tcp => "TCP",
            .udp => "UDP",
            .icmp => "ICMP",
            .icmp6 => "ICMPv6",
            .arp => "ARP",
            .other => "OTHER",
        };
    }
};

pub const snap_len = 256;

pub const PacketInfo = struct {
    timestamp_ms: i64 = 0,
    src_addr: [46]u8 = .{0} ** 46,
    src_addr_len: u8 = 0,
    dst_addr: [46]u8 = .{0} ** 46,
    dst_addr_len: u8 = 0,
    src_port: u16 = 0,
    dst_port: u16 = 0,
    protocol: Protocol = .other,
    length: u32 = 0,
    ip_ttl: u8 = 0,
    tcp_flags: u8 = 0,
    dns_name: [128]u8 = .{0} ** 128,
    dns_name_len: u8 = 0,
    dns_is_response: bool = false,
    raw: [snap_len]u8 = .{0} ** snap_len,
    raw_len: u16 = 0,

    /// Source address as a readable string slice.
    pub fn srcAddr(self: *const PacketInfo) []const u8 {
        return self.src_addr[0..self.src_addr_len];
    }

    /// Destination address as a readable string slice.
    pub fn dstAddr(self: *const PacketInfo) []const u8 {
        return self.dst_addr[0..self.dst_addr_len];
    }

    /// DNS queried domain name, if this is a DNS packet.
    pub fn dnsName(self: *const PacketInfo) []const u8 {
        return self.dns_name[0..self.dns_name_len];
    }

    /// Format TCP flags into a human-readable string.
    pub fn tcpFlagsStr(self: *const PacketInfo, buf: *[40]u8) []const u8 {
        var pos: usize = 0;
        const entries = [_]struct { mask: u8, label: []const u8 }{
            .{ .mask = 0x02, .label = "SYN" },
            .{ .mask = 0x10, .label = "ACK" },
            .{ .mask = 0x01, .label = "FIN" },
            .{ .mask = 0x04, .label = "RST" },
            .{ .mask = 0x08, .label = "PSH" },
            .{ .mask = 0x20, .label = "URG" },
        };
        for (entries) |e| {
            if (self.tcp_flags & e.mask != 0) {
                if (pos > 0) {
                    buf[pos] = ',';
                    pos += 1;
                }
                @memcpy(buf[pos..][0..e.label.len], e.label);
                pos += e.label.len;
            }
        }
        return buf[0..pos];
    }
};

/// Parse a raw Ethernet frame into packet metadata.
/// Returns null if the frame is too short or unrecognized.
pub fn parse(raw: []const u8) ?PacketInfo {
    if (raw.len < 14) return null;

    var info: PacketInfo = .{};
    info.length = @intCast(raw.len);

    const ethertype = readU16(raw, 12);
    switch (ethertype) {
        0x0800 => parseIpv4(raw[14..], &info),
        0x86DD => parseIpv6(raw[14..], &info),
        0x0806 => parseArp(raw[14..], &info),
        else => {},
    }

    return info;
}

fn parseIpv4(data: []const u8, info: *PacketInfo) void {
    if (data.len < 20) return;

    const ihl: usize = @as(usize, data[0] & 0x0F) * 4;
    if (ihl < 20 or data.len < ihl) return;

    info.ip_ttl = data[8];
    info.src_addr_len = fmtIpv4(data[12..], &info.src_addr);
    info.dst_addr_len = fmtIpv4(data[16..], &info.dst_addr);

    parseTransport(data[9], if (data.len > ihl) data[ihl..] else &.{}, info);
}

fn parseIpv6(data: []const u8, info: *PacketInfo) void {
    if (data.len < 40) return;

    info.ip_ttl = data[7];
    info.src_addr_len = fmtIpv6(data[8..], &info.src_addr);
    info.dst_addr_len = fmtIpv6(data[24..], &info.dst_addr);

    parseTransport(data[6], if (data.len > 40) data[40..] else &.{}, info);
}

fn parseTransport(proto: u8, data: []const u8, info: *PacketInfo) void {
    switch (proto) {
        6 => {
            info.protocol = .tcp;
            if (data.len >= 14) {
                info.src_port = readU16(data, 0);
                info.dst_port = readU16(data, 2);
                info.tcp_flags = data[13];
            }
        },
        17 => {
            info.protocol = .udp;
            if (data.len >= 4) {
                info.src_port = readU16(data, 0);
                info.dst_port = readU16(data, 2);
                // DNS runs on port 53 - parse the query name
                if ((info.src_port == 53 or info.dst_port == 53) and data.len > 20) {
                    parseDns(data[8..], info);
                }
            }
        },
        1 => info.protocol = .icmp,
        58 => info.protocol = .icmp6,
        else => info.protocol = .other,
    }
}

fn parseDns(data: []const u8, info: *PacketInfo) void {
    // DNS header: 12 bytes minimum
    // Bytes 0-1: Transaction ID
    // Bytes 2-3: Flags (bit 15 = QR: 0=query, 1=response)
    // Bytes 4-5: Question count
    // Bytes 6-7: Answer count
    // Byte 12+: Question section (QNAME + QTYPE + QCLASS)
    if (data.len < 13) return;

    const flags = readU16(data, 2);
    info.dns_is_response = (flags & 0x8000) != 0;
    const qcount = readU16(data, 4);
    if (qcount == 0) return;

    // Decode QNAME: sequence of length-prefixed labels, ending with 0
    var pos: usize = 12;
    var out_pos: u8 = 0;
    while (pos < data.len) {
        const label_len = data[pos];
        if (label_len == 0) break;
        // Pointer compression (top 2 bits set) - stop here
        if (label_len & 0xC0 == 0xC0) break;
        pos += 1;
        if (pos + label_len > data.len) break;

        // Add dot separator between labels
        if (out_pos > 0 and out_pos < 127) {
            info.dns_name[out_pos] = '.';
            out_pos += 1;
        }

        const copy_len = @min(@as(u8, @intCast(label_len)), 127 - out_pos);
        if (copy_len == 0) break;
        @memcpy(info.dns_name[out_pos..][0..copy_len], data[pos..][0..copy_len]);
        out_pos += copy_len;
        pos += label_len;
    }
    info.dns_name_len = out_pos;
}

fn parseArp(data: []const u8, info: *PacketInfo) void {
    info.protocol = .arp;
    if (data.len < 28) return;
    info.src_addr_len = fmtIpv4(data[14..], &info.src_addr);
    info.dst_addr_len = fmtIpv4(data[24..], &info.dst_addr);
}

// -- Helpers --

fn readU16(data: []const u8, offset: usize) u16 {
    return @as(u16, data[offset]) << 8 | data[offset + 1];
}

fn fmtIpv4(bytes: []const u8, out: *[46]u8) u8 {
    if (bytes.len < 4) return 0;
    const s = std.fmt.bufPrint(out, "{d}.{d}.{d}.{d}", .{
        bytes[0], bytes[1], bytes[2], bytes[3],
    }) catch return 0;
    return @intCast(s.len);
}

fn fmtIpv6(bytes: []const u8, out: *[46]u8) u8 {
    if (bytes.len < 16) return 0;
    const s = std.fmt.bufPrint(out, "{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}", .{
        readU16(bytes, 0),  readU16(bytes, 2),
        readU16(bytes, 4),  readU16(bytes, 6),
        readU16(bytes, 8),  readU16(bytes, 10),
        readU16(bytes, 12), readU16(bytes, 14),
    }) catch return 0;
    return @intCast(s.len);
}

// -- Tests --

test "parse minimal IPv4 TCP packet" {
    // Ethernet header (14) + IPv4 header (20) + TCP header (20)
    var frame: [54]u8 = .{0} ** 54;
    // Ethertype: IPv4
    frame[12] = 0x08;
    frame[13] = 0x00;
    // IPv4: version 4, ihl 5
    frame[14] = 0x45;
    // Protocol: TCP
    frame[23] = 6;
    // TTL
    frame[22] = 64;
    // Source IP: 10.0.0.1
    frame[26] = 10;
    frame[27] = 0;
    frame[28] = 0;
    frame[29] = 1;
    // Dest IP: 10.0.0.2
    frame[30] = 10;
    frame[31] = 0;
    frame[32] = 0;
    frame[33] = 2;
    // TCP source port: 12345
    frame[34] = 0x30;
    frame[35] = 0x39;
    // TCP dest port: 80
    frame[36] = 0x00;
    frame[37] = 0x50;
    // TCP flags (offset 13 from TCP start = 47): SYN
    frame[47] = 0x02;

    const info = parse(&frame).?;
    try std.testing.expectEqualStrings("10.0.0.1", info.srcAddr());
    try std.testing.expectEqualStrings("10.0.0.2", info.dstAddr());
    try std.testing.expectEqual(Protocol.tcp, info.protocol);
    try std.testing.expectEqual(@as(u16, 12345), info.src_port);
    try std.testing.expectEqual(@as(u16, 80), info.dst_port);
    try std.testing.expectEqual(@as(u8, 64), info.ip_ttl);
    try std.testing.expectEqual(@as(u8, 0x02), info.tcp_flags);
}

test "parse UDP packet" {
    var frame: [42]u8 = .{0} ** 42;
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[14] = 0x45;
    frame[23] = 17; // UDP
    frame[26] = 192;
    frame[27] = 168;
    frame[28] = 1;
    frame[29] = 1;
    frame[30] = 8;
    frame[31] = 8;
    frame[32] = 8;
    frame[33] = 8;
    // UDP ports: 5353 -> 53
    frame[34] = 0x14;
    frame[35] = 0xE9;
    frame[36] = 0x00;
    frame[37] = 0x35;

    const info = parse(&frame).?;
    try std.testing.expectEqualStrings("192.168.1.1", info.srcAddr());
    try std.testing.expectEqualStrings("8.8.8.8", info.dstAddr());
    try std.testing.expectEqual(Protocol.udp, info.protocol);
    try std.testing.expectEqual(@as(u16, 5353), info.src_port);
    try std.testing.expectEqual(@as(u16, 53), info.dst_port);
}

test "parse ARP packet" {
    var frame: [42]u8 = .{0} ** 42;
    frame[12] = 0x08;
    frame[13] = 0x06;
    // Sender IP at ARP offset 14: 10.0.0.1
    frame[28] = 10;
    frame[29] = 0;
    frame[30] = 0;
    frame[31] = 1;
    // Target IP at ARP offset 24: 10.0.0.254
    frame[38] = 10;
    frame[39] = 0;
    frame[40] = 0;
    frame[41] = 254;

    const info = parse(&frame).?;
    try std.testing.expectEqual(Protocol.arp, info.protocol);
    try std.testing.expectEqualStrings("10.0.0.1", info.srcAddr());
    try std.testing.expectEqualStrings("10.0.0.254", info.dstAddr());
}

test "parse returns null for short frame" {
    const frame = [_]u8{0} ** 10;
    try std.testing.expect(parse(&frame) == null);
}

test "tcp flags formatting" {
    var info: PacketInfo = .{};
    info.tcp_flags = 0x12; // SYN + ACK
    var buf: [40]u8 = undefined;
    try std.testing.expectEqualStrings("SYN,ACK", info.tcpFlagsStr(&buf));
}

test "parse DNS query extracts domain name" {
    // Ethernet(14) + IPv4(20, ihl=5, proto=17) + UDP(8, sport=1234 dport=53) + DNS
    var frame: [80]u8 = .{0} ** 80;
    // Ethertype IPv4
    frame[12] = 0x08;
    frame[13] = 0x00;
    // IPv4 header
    frame[14] = 0x45; // version 4, ihl 5
    frame[23] = 17; // UDP
    frame[26] = 10;
    frame[27] = 0;
    frame[28] = 0;
    frame[29] = 1; // src
    frame[30] = 8;
    frame[31] = 8;
    frame[32] = 8;
    frame[33] = 8; // dst
    // UDP header (offset 34)
    frame[34] = 0x04;
    frame[35] = 0xD2; // src port 1234
    frame[36] = 0x00;
    frame[37] = 0x35; // dst port 53
    // DNS header (offset 42): txid=0, flags=0 (query), qcount=1
    frame[46] = 0x00;
    frame[47] = 0x01; // 1 question
    // QNAME at offset 54: \x03www\x06google\x03com\x00
    frame[54] = 3;
    frame[55] = 'w';
    frame[56] = 'w';
    frame[57] = 'w';
    frame[58] = 6;
    frame[59] = 'g';
    frame[60] = 'o';
    frame[61] = 'o';
    frame[62] = 'g';
    frame[63] = 'l';
    frame[64] = 'e';
    frame[65] = 3;
    frame[66] = 'c';
    frame[67] = 'o';
    frame[68] = 'm';
    frame[69] = 0; // end of QNAME

    const info = parse(&frame).?;
    try std.testing.expectEqual(Protocol.udp, info.protocol);
    try std.testing.expectEqual(@as(u16, 53), info.dst_port);
    try std.testing.expectEqualStrings("www.google.com", info.dnsName());
    try std.testing.expect(!info.dns_is_response);
}
