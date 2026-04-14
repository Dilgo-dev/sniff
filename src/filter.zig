// Packet filter expression parser and matcher.
//
// Supports simple BPF-style expressions evaluated against parsed
// PacketInfo fields. Multiple clauses are AND-ed together.
//
// Examples:
//   tcp                   protocol is TCP
//   udp port 53           protocol is UDP and either port is 53
//   host 192.168.1.1      source or destination is 192.168.1.1
//   src port 443          source port is 443
//   dst host 10.0.0.1     destination address is 10.0.0.1
//   tcp dst port 80       TCP and destination port is 80

const std = @import("std");
const packet = @import("packet.zig");

pub const Filter = struct {
    proto: ?packet.Protocol = null,
    port: ?u16 = null,
    src_port: ?u16 = null,
    dst_port: ?u16 = null,
    host: Host = .{},
    src_host: Host = .{},
    dst_host: Host = .{},
    dns_only: bool = false,
    http_only: bool = false,
    active: bool = false,
    qf_sni: QfStr = .{},
    qf_proto: QfStr = .{},
    qf_state: QfStr = .{},
    qf_port: ?u16 = null,

    const Host = struct {
        buf: [46]u8 = .{0} ** 46,
        len: u8 = 0,

        fn set(self: *Host, s: []const u8) void {
            const n = @min(s.len, 46);
            @memcpy(self.buf[0..n], s[0..n]);
            self.len = @intCast(n);
        }

        fn slice(self: *const Host) []const u8 {
            return self.buf[0..self.len];
        }

        fn isSet(self: *const Host) bool {
            return self.len > 0;
        }
    };

    const QfStr = struct {
        buf: [64]u8 = .{0} ** 64,
        len: u8 = 0,

        fn set(self: *QfStr, s: []const u8) void {
            const n: u8 = @intCast(@min(s.len, 64));
            @memcpy(self.buf[0..n], s[0..n]);
            self.len = n;
        }

        fn slice(self: *const QfStr) []const u8 {
            return self.buf[0..self.len];
        }

        fn isSet(self: *const QfStr) bool {
            return self.len > 0;
        }
    };

    /// Check if a packet matches all active filter clauses.
    pub fn matches(self: *const Filter, pkt: *const packet.PacketInfo) bool {
        if (!self.active) return true;

        if (self.proto) |p| {
            if (pkt.protocol != p) return false;
        }
        if (self.port) |p| {
            if (pkt.src_port != p and pkt.dst_port != p) return false;
        }
        if (self.src_port) |p| {
            if (pkt.src_port != p) return false;
        }
        if (self.dst_port) |p| {
            if (pkt.dst_port != p) return false;
        }
        if (self.host.isSet()) {
            const h = self.host.slice();
            if (!std.mem.eql(u8, pkt.srcAddr(), h) and !std.mem.eql(u8, pkt.dstAddr(), h))
                return false;
        }
        if (self.src_host.isSet()) {
            if (!std.mem.eql(u8, pkt.srcAddr(), self.src_host.slice()))
                return false;
        }
        if (self.dst_host.isSet()) {
            if (!std.mem.eql(u8, pkt.dstAddr(), self.dst_host.slice()))
                return false;
        }
        if (self.dns_only) {
            if (pkt.dns_name_len == 0) return false;
        }
        if (self.http_only) {
            if (pkt.http_info_len == 0) return false;
        }
        if (self.qf_sni.isSet()) {
            if (!substringMatch(pkt.sniName(), self.qf_sni.slice()))
                return false;
        }
        if (self.qf_port) |p| {
            if (pkt.src_port != p and pkt.dst_port != p) return false;
        }
        if (self.qf_proto.isSet()) {
            if (!eqlLowerAscii(pkt.protoLabel(), self.qf_proto.slice()))
                return false;
        }
        if (self.qf_state.isSet()) {
            if (!matchState(pkt, self.qf_state.slice()))
                return false;
        }
        return true;
    }
};

fn substringMatch(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (haystack.len < needle.len) return false;
    const end = haystack.len - needle.len + 1;
    for (0..end) |i| {
        if (eqlLowerAscii(haystack[i..][0..needle.len], needle)) return true;
    }
    return false;
}

fn eqlLowerAscii(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (std.ascii.toLower(ca) != std.ascii.toLower(cb)) return false;
    }
    return true;
}

fn matchState(pkt: *const packet.PacketInfo, val: []const u8) bool {
    if (pkt.quic_state != .none) {
        if (eqlLowerAscii(pkt.quic_state.label(), val)) return true;
    }
    if (pkt.app_proto != .none) {
        if (eqlLowerAscii(pkt.app_proto.label(), val)) return true;
    }
    // TCP flag states
    if (pkt.protocol == .tcp) {
        if (pkt.tcp_flags & 0x02 != 0 and eqlLowerAscii("syn", val)) return true;
        if (pkt.tcp_flags & 0x10 != 0 and eqlLowerAscii("ack", val)) return true;
        if (pkt.tcp_flags & 0x01 != 0 and eqlLowerAscii("fin", val)) return true;
        if (pkt.tcp_flags & 0x04 != 0 and eqlLowerAscii("rst", val)) return true;
    }
    if (pkt.tls_sni_len > 0 and eqlLowerAscii("tls", val)) return true;
    if (pkt.dns_name_len > 0 and eqlLowerAscii("dns", val)) return true;
    if (pkt.http_info_len > 0 and eqlLowerAscii("http", val)) return true;
    return false;
}

fn parseQuickFilter(tok: []const u8, f: *Filter) bool {
    if (splitQuickFilter(tok, "sni:")) |val| {
        f.qf_sni.set(val);
        return true;
    }
    if (splitQuickFilter(tok, "port:")) |val| {
        f.qf_port = std.fmt.parseInt(u16, val, 10) catch return false;
        return true;
    }
    if (splitQuickFilter(tok, "proto:")) |val| {
        f.qf_proto.set(val);
        return true;
    }
    if (splitQuickFilter(tok, "state:")) |val| {
        f.qf_state.set(val);
        return true;
    }
    return false;
}

fn splitQuickFilter(tok: []const u8, prefix: []const u8) ?[]const u8 {
    if (tok.len > prefix.len and eqlLowerAscii(tok[0..prefix.len], prefix)) {
        return tok[prefix.len..];
    }
    return null;
}

/// Parse a filter expression string into a Filter.
/// Returns null if the expression is invalid.
pub fn parse(expr: []const u8) ?Filter {
    if (expr.len == 0) return Filter{};

    var f: Filter = .{ .active = true };
    var tokens: [32][]const u8 = undefined;
    var count: usize = 0;

    var i: usize = 0;
    while (i < expr.len and count < 32) {
        while (i < expr.len and expr[i] == ' ') : (i += 1) {}
        if (i >= expr.len) break;
        const start = i;
        while (i < expr.len and expr[i] != ' ') : (i += 1) {}
        tokens[count] = expr[start..i];
        count += 1;
    }
    if (count == 0) return Filter{};

    var ti: usize = 0;
    while (ti < count) {
        const tok = tokens[ti];

        if (std.mem.eql(u8, tok, "and") or std.mem.eql(u8, tok, "&&")) {
            ti += 1;
            continue;
        }

        if (parseQuickFilter(tok, &f)) {
            ti += 1;
            continue;
        }

        if (std.mem.eql(u8, tok, "dns")) {
            f.dns_only = true;
            ti += 1;
            continue;
        }
        if (std.mem.eql(u8, tok, "http")) {
            f.http_only = true;
            ti += 1;
            continue;
        }

        if (std.mem.eql(u8, tok, "tcp")) {
            f.proto = .tcp;
            ti += 1;
            continue;
        }
        if (std.mem.eql(u8, tok, "udp")) {
            f.proto = .udp;
            ti += 1;
            continue;
        }
        if (std.mem.eql(u8, tok, "icmp")) {
            f.proto = .icmp;
            ti += 1;
            continue;
        }
        if (std.mem.eql(u8, tok, "arp")) {
            f.proto = .arp;
            ti += 1;
            continue;
        }

        if (std.mem.eql(u8, tok, "port")) {
            ti += 1;
            if (ti >= count) return null;
            f.port = std.fmt.parseInt(u16, tokens[ti], 10) catch return null;
            ti += 1;
            continue;
        }

        if (std.mem.eql(u8, tok, "host")) {
            ti += 1;
            if (ti >= count) return null;
            f.host.set(tokens[ti]);
            ti += 1;
            continue;
        }

        if (std.mem.eql(u8, tok, "src") or std.mem.eql(u8, tok, "dst")) {
            const is_src = tok[0] == 's';
            ti += 1;
            if (ti >= count) return null;
            const next = tokens[ti];

            if (std.mem.eql(u8, next, "port")) {
                ti += 1;
                if (ti >= count) return null;
                const port = std.fmt.parseInt(u16, tokens[ti], 10) catch return null;
                if (is_src) {
                    f.src_port = port;
                } else {
                    f.dst_port = port;
                }
            } else if (std.mem.eql(u8, next, "host")) {
                ti += 1;
                if (ti >= count) return null;
                if (is_src) {
                    f.src_host.set(tokens[ti]);
                } else {
                    f.dst_host.set(tokens[ti]);
                }
            } else {
                if (is_src) {
                    f.src_host.set(next);
                } else {
                    f.dst_host.set(next);
                }
            }
            ti += 1;
            continue;
        }

        if (std.mem.eql(u8, tok, "sport")) {
            ti += 1;
            if (ti >= count) return null;
            f.src_port = std.fmt.parseInt(u16, tokens[ti], 10) catch return null;
            ti += 1;
            continue;
        }
        if (std.mem.eql(u8, tok, "dport")) {
            ti += 1;
            if (ti >= count) return null;
            f.dst_port = std.fmt.parseInt(u16, tokens[ti], 10) catch return null;
            ti += 1;
            continue;
        }

        return null;
    }

    return f;
}

test "empty expression matches everything" {
    const f = parse("").?;
    try std.testing.expect(!f.active);
}

test "tcp filter" {
    const f = parse("tcp").?;
    var pkt: packet.PacketInfo = .{};
    pkt.protocol = .tcp;
    try std.testing.expect(f.matches(&pkt));
    pkt.protocol = .udp;
    try std.testing.expect(!f.matches(&pkt));
}

test "port filter matches either direction" {
    const f = parse("port 80").?;
    var pkt: packet.PacketInfo = .{ .src_port = 80 };
    try std.testing.expect(f.matches(&pkt));
    pkt.src_port = 0;
    pkt.dst_port = 80;
    try std.testing.expect(f.matches(&pkt));
    pkt.dst_port = 443;
    try std.testing.expect(!f.matches(&pkt));
}

test "tcp port combined" {
    const f = parse("tcp port 443").?;
    var pkt: packet.PacketInfo = .{ .protocol = .tcp, .dst_port = 443 };
    try std.testing.expect(f.matches(&pkt));
    pkt.protocol = .udp;
    try std.testing.expect(!f.matches(&pkt));
}

test "src/dst port" {
    const f = parse("dst port 53").?;
    var pkt: packet.PacketInfo = .{ .dst_port = 53 };
    try std.testing.expect(f.matches(&pkt));
    pkt.dst_port = 0;
    pkt.src_port = 53;
    try std.testing.expect(!f.matches(&pkt));
}

test "host filter" {
    const f = parse("host 10.0.0.1").?;
    var pkt: packet.PacketInfo = .{};
    const addr = "10.0.0.1";
    @memcpy(pkt.src_addr[0..addr.len], addr);
    pkt.src_addr_len = addr.len;
    try std.testing.expect(f.matches(&pkt));
}

test "invalid expression returns null" {
    try std.testing.expect(parse("port") == null);
    try std.testing.expect(parse("port abc") == null);
    try std.testing.expect(parse("src") == null);
}

test "and conjunction" {
    const f = parse("tcp and port 80").?;
    try std.testing.expect(f.proto.? == .tcp);
    try std.testing.expect(f.port.? == 80);
}

test "quick filter sni: matches SNI substring" {
    const f = parse("sni:example").?;
    try std.testing.expect(f.active);
    try std.testing.expect(f.qf_sni.isSet());

    var pkt: packet.PacketInfo = .{};
    const sni = "www.example.com";
    @memcpy(pkt.tls_sni[0..sni.len], sni);
    pkt.tls_sni_len = sni.len;
    try std.testing.expect(f.matches(&pkt));

    var pkt2: packet.PacketInfo = .{};
    const sni2 = "other.org";
    @memcpy(pkt2.tls_sni[0..sni2.len], sni2);
    pkt2.tls_sni_len = sni2.len;
    try std.testing.expect(!f.matches(&pkt2));

    var pkt3: packet.PacketInfo = .{};
    try std.testing.expect(!f.matches(&pkt3));
}

test "quick filter port: matches either direction" {
    const f = parse("port:443").?;
    try std.testing.expect(f.qf_port.? == 443);

    var pkt: packet.PacketInfo = .{ .dst_port = 443 };
    try std.testing.expect(f.matches(&pkt));
    var pkt2: packet.PacketInfo = .{ .src_port = 443 };
    try std.testing.expect(f.matches(&pkt2));
    var pkt3: packet.PacketInfo = .{ .src_port = 80 };
    try std.testing.expect(!f.matches(&pkt3));
}

test "quick filter proto: matches protocol label" {
    const f = parse("proto:tcp").?;
    var pkt: packet.PacketInfo = .{ .protocol = .tcp };
    try std.testing.expect(f.matches(&pkt));
    var pkt2: packet.PacketInfo = .{ .protocol = .udp };
    try std.testing.expect(!f.matches(&pkt2));
}

test "quick filter proto: case insensitive" {
    const f = parse("proto:TCP").?;
    var pkt: packet.PacketInfo = .{ .protocol = .tcp };
    try std.testing.expect(f.matches(&pkt));
}

test "quick filter state: matches QUIC state" {
    const f = parse("state:initial").?;
    var pkt: packet.PacketInfo = .{ .protocol = .udp, .quic_state = .initial };
    try std.testing.expect(f.matches(&pkt));
    var pkt2: packet.PacketInfo = .{ .protocol = .udp, .quic_state = .connected };
    try std.testing.expect(!f.matches(&pkt2));
}

test "quick filter state: matches TCP flags" {
    const f = parse("state:syn").?;
    var pkt: packet.PacketInfo = .{ .protocol = .tcp, .tcp_flags = 0x02 };
    try std.testing.expect(f.matches(&pkt));
    var pkt2: packet.PacketInfo = .{ .protocol = .tcp, .tcp_flags = 0x10 };
    try std.testing.expect(!f.matches(&pkt2));
}

test "quick filter state: matches tls/dns/http" {
    const f = parse("state:tls").?;
    var pkt: packet.PacketInfo = .{};
    const sni = "example.com";
    @memcpy(pkt.tls_sni[0..sni.len], sni);
    pkt.tls_sni_len = sni.len;
    try std.testing.expect(f.matches(&pkt));

    var pkt2: packet.PacketInfo = .{};
    try std.testing.expect(!f.matches(&pkt2));
}

test "quick filter combined with BPF tokens" {
    const f = parse("tcp sni:google").?;
    try std.testing.expect(f.proto.? == .tcp);
    try std.testing.expect(f.qf_sni.isSet());

    var pkt: packet.PacketInfo = .{ .protocol = .tcp };
    const sni = "www.google.com";
    @memcpy(pkt.tls_sni[0..sni.len], sni);
    pkt.tls_sni_len = sni.len;
    try std.testing.expect(f.matches(&pkt));

    var pkt2: packet.PacketInfo = .{ .protocol = .udp };
    @memcpy(pkt2.tls_sni[0..sni.len], sni);
    pkt2.tls_sni_len = sni.len;
    try std.testing.expect(!f.matches(&pkt2));
}

test "quick filter port: with invalid value returns null" {
    try std.testing.expect(parse("port:abc") == null);
}

test "multiple quick filters AND together" {
    const f = parse("sni:example port:443").?;
    var pkt: packet.PacketInfo = .{ .dst_port = 443 };
    const sni = "example.com";
    @memcpy(pkt.tls_sni[0..sni.len], sni);
    pkt.tls_sni_len = sni.len;
    try std.testing.expect(f.matches(&pkt));

    var pkt2: packet.PacketInfo = .{ .dst_port = 80 };
    @memcpy(pkt2.tls_sni[0..sni.len], sni);
    pkt2.tls_sni_len = sni.len;
    try std.testing.expect(!f.matches(&pkt2));
}
