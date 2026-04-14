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

pub const QuicState = enum(u8) {
    none = 0,
    initial = 1,
    zero_rtt = 2,
    handshake = 3,
    retry = 4,
    connected = 5,

    /// Short label for the Protocol column (fits in 8 chars).
    pub fn columnLabel(self: QuicState) []const u8 {
        return switch (self) {
            .none => "UDP",
            .initial => "QUIC-I",
            .zero_rtt => "QUIC-0R",
            .handshake => "QUIC-HS",
            .retry => "QUIC-R",
            .connected => "QUIC",
        };
    }

    /// Full label for the detail pane.
    pub fn label(self: QuicState) []const u8 {
        return switch (self) {
            .none => "",
            .initial => "Initial",
            .zero_rtt => "0-RTT",
            .handshake => "Handshake",
            .retry => "Retry",
            .connected => "Connected",
        };
    }
};

pub const AppProto = enum(u8) {
    none = 0,
    mdns = 1,
    dhcp = 2,
    ntp = 3,
    ssh = 4,

    pub fn label(self: AppProto) []const u8 {
        return switch (self) {
            .none => "",
            .mdns => "mDNS",
            .dhcp => "DHCP",
            .ntp => "NTP",
            .ssh => "SSH",
        };
    }
};

pub const snap_len = 1500;

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
    http_info: [128]u8 = .{0} ** 128,
    http_info_len: u8 = 0,
    tls_sni: [253]u8 = .{0} ** 253,
    tls_sni_len: u8 = 0,
    tls_cert_cn: [128]u8 = .{0} ** 128,
    tls_cert_cn_len: u8 = 0,
    tls_cert_san: [256]u8 = .{0} ** 256,
    tls_cert_san_len: u16 = 0,
    tls_cert_expiry: [20]u8 = .{0} ** 20,
    tls_cert_expiry_len: u8 = 0,
    quic_state: QuicState = .none,
    app_proto: AppProto = .none,
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

    /// HTTP request/response summary, if detected.
    pub fn httpInfo(self: *const PacketInfo) []const u8 {
        return self.http_info[0..self.http_info_len];
    }

    /// Protocol label for display, accounting for app-layer detection.
    pub fn protoLabel(self: *const PacketInfo) []const u8 {
        if (self.app_proto != .none) return self.app_proto.label();
        if (self.quic_state != .none) return self.quic_state.columnLabel();
        return self.protocol.name();
    }

    /// TLS SNI hostname, if this is a TLS ClientHello with server_name.
    pub fn sniName(self: *const PacketInfo) []const u8 {
        return self.tls_sni[0..self.tls_sni_len];
    }

    /// Subject CN from the first certificate in a TLS Certificate message.
    pub fn certCn(self: *const PacketInfo) []const u8 {
        return self.tls_cert_cn[0..self.tls_cert_cn_len];
    }

    /// Comma-separated SAN dNSName entries from the server certificate.
    pub fn certSan(self: *const PacketInfo) []const u8 {
        return self.tls_cert_san[0..self.tls_cert_san_len];
    }

    /// Expiration date (notAfter) from the server certificate.
    pub fn certExpiry(self: *const PacketInfo) []const u8 {
        return self.tls_cert_expiry[0..self.tls_cert_expiry_len];
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
                const data_off: usize = @as(usize, data[12] >> 4) * 4;
                if (data_off >= 20 and data.len > data_off) {
                    const payload = data[data_off..];
                    if (payload.len >= 4 and std.mem.eql(u8, payload[0..4], "SSH-")) {
                        info.app_proto = .ssh;
                        setHttpInfo(info, firstLine(payload));
                    } else {
                        parseHttp(payload, info);
                        if (info.http_info_len == 0) {
                            parseTls(payload, info);
                        }
                    }
                }
            }
        },
        17 => {
            info.protocol = .udp;
            if (data.len >= 4) {
                info.src_port = readU16(data, 0);
                info.dst_port = readU16(data, 2);
                if (info.src_port == 5353 or info.dst_port == 5353) {
                    info.app_proto = .mdns;
                    if (data.len > 20) parseDns(data[8..], info);
                } else if ((info.src_port == 53 or info.dst_port == 53) and data.len > 20) {
                    parseDns(data[8..], info);
                } else if (info.src_port == 67 or info.dst_port == 67 or
                    info.src_port == 68 or info.dst_port == 68)
                {
                    info.app_proto = .dhcp;
                } else if (info.src_port == 123 or info.dst_port == 123) {
                    info.app_proto = .ntp;
                } else if (data.len > 8) {
                    parseQuic(data[8..], info);
                }
            }
        },
        1 => info.protocol = .icmp,
        58 => info.protocol = .icmp6,
        else => info.protocol = .other,
    }
}

fn parseHttp(payload: []const u8, info: *PacketInfo) void {
    if (payload.len < 10) return;

    // Request: "GET /path HTTP/1.x" or "POST /path HTTP/1.x" etc.
    // Response: "HTTP/1.x 200 OK"
    const methods = [_][]const u8{ "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "PATCH ", "OPTIONS " };
    for (methods) |m| {
        if (payload.len > m.len and std.ascii.eqlIgnoreCase(payload[0..m.len], m)) {
            const first_line = firstLine(payload);
            setHttpInfo(info, first_line);
            return;
        }
    }
    if (payload.len > 5 and std.mem.eql(u8, payload[0..5], "HTTP/")) {
        const first_line = firstLine(payload);
        setHttpInfo(info, first_line);
    }
}

fn firstLine(data: []const u8) []const u8 {
    for (data, 0..) |b, i| {
        if (b == '\r' or b == '\n') return data[0..i];
    }
    return data[0..@min(data.len, 127)];
}

fn setHttpInfo(info: *PacketInfo, line: []const u8) void {
    const n = @min(line.len, 127);
    @memcpy(info.http_info[0..n], line[0..n]);
    info.http_info_len = @intCast(n);
}

fn parseDns(data: []const u8, info: *PacketInfo) void {
    if (data.len < 13) return;

    const flags = readU16(data, 2);
    info.dns_is_response = (flags & 0x8000) != 0;
    const qcount = readU16(data, 4);
    if (qcount == 0) return;

    // QNAME starts at byte 12: length-prefixed labels terminated by 0
    var pos: usize = 12;
    var out_pos: u8 = 0;
    while (pos < data.len) {
        const label_len = data[pos];
        if (label_len == 0) break;
        // Pointer compression - can't follow without the full message
        if (label_len & 0xC0 == 0xC0) break;
        pos += 1;
        if (pos + label_len > data.len) break;

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

fn parseTls(payload: []const u8, info: *PacketInfo) void {
    var offset: usize = 0;
    while (offset + 5 <= payload.len) {
        if (payload[offset] != 0x16) break;
        const rec_len = @as(usize, readU16(payload, offset + 3));
        const rec_start = offset + 5;
        const rec_end = @min(rec_start + rec_len, payload.len);
        if (rec_start >= rec_end) break;
        parseTlsHandshakes(payload[rec_start..rec_end], info);
        offset = rec_end;
    }
}

fn parseTlsHandshakes(data: []const u8, info: *PacketInfo) void {
    var pos: usize = 0;
    while (pos + 4 <= data.len) {
        const hs_type = data[pos];
        const hs_len = @as(usize, data[pos + 1]) << 16 | @as(usize, data[pos + 2]) << 8 | @as(usize, data[pos + 3]);
        const body_start = pos + 4;
        const body_end = @min(body_start + hs_len, data.len);
        if (body_start > body_end) break;
        const body = data[body_start..body_end];

        switch (hs_type) {
            0x01 => parseClientHello(body, info),
            0x0B => parseCertificateMsg(body, info),
            else => {},
        }
        pos = body_end;
    }
}

fn parseClientHello(body: []const u8, info: *PacketInfo) void {
    if (body.len < 35) return;
    var pos: usize = 34;
    const sid_len = body[pos];
    pos += 1 + sid_len;
    if (pos + 2 > body.len) return;

    const cs_len = @as(usize, readU16(body, pos));
    pos += 2 + cs_len;
    if (pos + 1 > body.len) return;

    const cm_len = @as(usize, body[pos]);
    pos += 1 + cm_len;
    if (pos + 2 > body.len) return;

    const ext_total = @as(usize, readU16(body, pos));
    pos += 2;
    const ext_end = @min(pos + ext_total, body.len);

    while (pos + 4 <= ext_end) {
        const ext_type = readU16(body, pos);
        const ext_len = @as(usize, readU16(body, pos + 2));
        pos += 4;
        if (pos + ext_len > ext_end) break;

        if (ext_type == 0x0000) {
            extractSni(body[pos .. pos + ext_len], info);
            return;
        }
        pos += ext_len;
    }
}

fn extractSni(data: []const u8, info: *PacketInfo) void {
    if (data.len < 5) return;
    var pos: usize = 2;
    const list_end = @min(@as(usize, readU16(data, 0)) + 2, data.len);

    while (pos + 3 <= list_end) {
        const name_type = data[pos];
        const name_len = @as(usize, readU16(data, pos + 1));
        pos += 3;
        if (pos + name_len > list_end) break;

        if (name_type == 0x00) {
            const n = @min(name_len, 253);
            @memcpy(info.tls_sni[0..n], data[pos..][0..n]);
            info.tls_sni_len = @intCast(n);
            return;
        }
        pos += name_len;
    }
}

fn parseCertificateMsg(body: []const u8, info: *PacketInfo) void {
    if (body.len < 3) return;
    const certs_len = @as(usize, body[0]) << 16 | @as(usize, body[1]) << 8 | @as(usize, body[2]);
    var pos: usize = 3;
    const certs_end = @min(pos + certs_len, body.len);

    // Only parse the first certificate (server's own cert)
    if (pos + 3 > certs_end) return;
    const cert_len = @as(usize, body[pos]) << 16 | @as(usize, body[pos + 1]) << 8 | @as(usize, body[pos + 2]);
    pos += 3;
    if (pos + cert_len > certs_end) return;
    parseX509(body[pos .. pos + cert_len], info);
}

// -- Minimal X.509 DER parser --

const DerElement = struct {
    tag: u8,
    value: []const u8,
    header_len: usize,
};

fn readDer(data: []const u8) ?DerElement {
    if (data.len < 2) return null;
    const tag = data[0];
    var len: usize = undefined;
    var hdr: usize = undefined;
    if (data[1] & 0x80 == 0) {
        len = data[1];
        hdr = 2;
    } else {
        const n = data[1] & 0x7F;
        if (n == 0 or n > 4 or 2 + n > data.len) return null;
        len = 0;
        for (0..n) |i| {
            len = (len << 8) | data[2 + i];
        }
        hdr = 2 + n;
    }
    if (hdr + len > data.len) return null;
    return .{ .tag = tag, .value = data[hdr .. hdr + len], .header_len = hdr };
}

fn skipDer(data: []const u8) usize {
    const e = readDer(data) orelse return data.len;
    return e.header_len + e.value.len;
}

fn parseX509(cert: []const u8, info: *PacketInfo) void {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    const outer = readDer(cert) orelse return;
    if (outer.tag != 0x30) return;
    const tbs_elem = readDer(outer.value) orelse return;
    if (tbs_elem.tag != 0x30) return;
    parseTbsCertificate(tbs_elem.value, info);
}

fn parseTbsCertificate(tbs: []const u8, info: *PacketInfo) void {
    var pos: usize = 0;

    // version [0] EXPLICIT - optional, skip if present
    if (pos < tbs.len and tbs[pos] == 0xA0) {
        pos += skipDer(tbs[pos..]);
    }
    // serialNumber INTEGER
    pos += skipDer(tbs[pos..]);
    // signature AlgorithmIdentifier SEQUENCE
    pos += skipDer(tbs[pos..]);
    // issuer Name SEQUENCE
    pos += skipDer(tbs[pos..]);

    // validity SEQUENCE { notBefore, notAfter }
    if (pos >= tbs.len) return;
    const validity = readDer(tbs[pos..]) orelse return;
    if (validity.tag == 0x30) {
        parseValidity(validity.value, info);
    }
    pos += validity.header_len + validity.value.len;

    // subject Name SEQUENCE
    if (pos >= tbs.len) return;
    const subject = readDer(tbs[pos..]) orelse return;
    if (subject.tag == 0x30) {
        extractCn(subject.value, info);
    }
    pos += subject.header_len + subject.value.len;

    // subjectPublicKeyInfo SEQUENCE
    pos += skipDer(tbs[pos..]);

    // Optional: issuerUniqueID [1], subjectUniqueID [2], extensions [3]
    while (pos < tbs.len) {
        if (tbs[pos] == 0xA3) {
            const ext_wrapper = readDer(tbs[pos..]) orelse return;
            parseExtensions(ext_wrapper.value, info);
            return;
        }
        pos += skipDer(tbs[pos..]);
    }
}

fn parseValidity(data: []const u8, info: *PacketInfo) void {
    // Validity ::= SEQUENCE { notBefore Time, notAfter Time }
    const not_before_size = skipDer(data);
    if (not_before_size >= data.len) return;
    const not_after = readDer(data[not_before_size..]) orelse return;
    // UTCTime (0x17) or GeneralizedTime (0x18)
    if (not_after.tag == 0x17) {
        formatUtcTime(not_after.value, info);
    } else if (not_after.tag == 0x18) {
        formatGenTime(not_after.value, info);
    }
}

fn formatUtcTime(data: []const u8, info: *PacketInfo) void {
    // UTCTime: YYMMDDHHMMSSZ (13 bytes)
    if (data.len < 13) return;
    var buf: [20]u8 = undefined;
    // Year: 00-49 -> 2000-2049, 50-99 -> 1950-1999
    const y0 = data[0] -| '0';
    const y1 = data[1] -| '0';
    const year = @as(u16, y0) * 10 + y1;
    const century: []const u8 = if (year < 50) "20" else "19";
    const s = std.fmt.bufPrint(&buf, "{s}{c}{c}-{c}{c}-{c}{c} {c}{c}:{c}{c}:{c}{c}", .{
        century,
        data[0],
        data[1],
        data[2],
        data[3],
        data[4],
        data[5],
        data[6],
        data[7],
        data[8],
        data[9],
        data[10],
        data[11],
    }) catch return;
    const n = @min(s.len, 20);
    @memcpy(info.tls_cert_expiry[0..n], s[0..n]);
    info.tls_cert_expiry_len = @intCast(n);
}

fn formatGenTime(data: []const u8, info: *PacketInfo) void {
    // GeneralizedTime: YYYYMMDDHHMMSSZ (15 bytes)
    if (data.len < 15) return;
    var buf: [20]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "{c}{c}{c}{c}-{c}{c}-{c}{c} {c}{c}:{c}{c}:{c}{c}", .{
        data[0],
        data[1],
        data[2],
        data[3],
        data[4],
        data[5],
        data[6],
        data[7],
        data[8],
        data[9],
        data[10],
        data[11],
        data[12],
        data[13],
    }) catch return;
    const n = @min(s.len, 20);
    @memcpy(info.tls_cert_expiry[0..n], s[0..n]);
    info.tls_cert_expiry_len = @intCast(n);
}

// OID 2.5.4.3 (id-at-commonName) encoded as DER: 55 04 03
const oid_cn = [_]u8{ 0x55, 0x04, 0x03 };

fn extractCn(subject: []const u8, info: *PacketInfo) void {
    // Name ::= SEQUENCE OF RelativeDistinguishedName
    // RDN  ::= SET OF AttributeTypeAndValue
    // ATAV ::= SEQUENCE { type OID, value ANY }
    var pos: usize = 0;
    while (pos < subject.len) {
        const rdn = readDer(subject[pos..]) orelse return;
        if (rdn.tag == 0x31) {
            searchRdnForCn(rdn.value, info);
            if (info.tls_cert_cn_len > 0) return;
        }
        pos += rdn.header_len + rdn.value.len;
    }
}

fn searchRdnForCn(rdn: []const u8, info: *PacketInfo) void {
    var pos: usize = 0;
    while (pos < rdn.len) {
        const atav = readDer(rdn[pos..]) orelse return;
        if (atav.tag == 0x30) {
            const oid_elem = readDer(atav.value) orelse {
                pos += atav.header_len + atav.value.len;
                continue;
            };
            if (oid_elem.tag == 0x06 and oid_elem.value.len == 3 and
                std.mem.eql(u8, oid_elem.value, &oid_cn))
            {
                const val_off = oid_elem.header_len + oid_elem.value.len;
                if (val_off < atav.value.len) {
                    const val = readDer(atav.value[val_off..]) orelse {
                        pos += atav.header_len + atav.value.len;
                        continue;
                    };
                    const n = @min(val.value.len, 128);
                    @memcpy(info.tls_cert_cn[0..n], val.value[0..n]);
                    info.tls_cert_cn_len = @intCast(n);
                    return;
                }
            }
        }
        pos += atav.header_len + atav.value.len;
    }
}

// OID 2.5.29.17 (id-ce-subjectAltName) encoded as DER: 55 1D 11
const oid_san = [_]u8{ 0x55, 0x1D, 0x11 };

fn parseExtensions(data: []const u8, info: *PacketInfo) void {
    // Extensions is wrapped in a SEQUENCE
    const seq = readDer(data) orelse return;
    if (seq.tag != 0x30) return;
    var pos: usize = 0;
    while (pos < seq.value.len) {
        const ext = readDer(seq.value[pos..]) orelse return;
        if (ext.tag == 0x30) {
            parseSingleExtension(ext.value, info);
            if (info.tls_cert_san_len > 0) return;
        }
        pos += ext.header_len + ext.value.len;
    }
}

fn parseSingleExtension(ext_val: []const u8, info: *PacketInfo) void {
    // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN OPTIONAL, extnValue OCTET STRING }
    const oid_elem = readDer(ext_val) orelse return;
    if (oid_elem.tag != 0x06) return;
    if (oid_elem.value.len != 3 or !std.mem.eql(u8, oid_elem.value, &oid_san)) return;

    var off = oid_elem.header_len + oid_elem.value.len;
    // Skip optional BOOLEAN (critical)
    if (off < ext_val.len and ext_val[off] == 0x01) {
        off += skipDer(ext_val[off..]);
    }
    if (off >= ext_val.len) return;
    const octet = readDer(ext_val[off..]) orelse return;
    if (octet.tag != 0x04) return;
    extractSanNames(octet.value, info);
}

fn extractSanNames(data: []const u8, info: *PacketInfo) void {
    // SubjectAltName ::= GeneralNames ::= SEQUENCE OF GeneralName
    const seq = readDer(data) orelse return;
    if (seq.tag != 0x30) return;
    var pos: usize = 0;
    var out_pos: u16 = 0;
    while (pos < seq.value.len) {
        const gn = readDer(seq.value[pos..]) orelse break;
        // context tag [2] = dNSName (tag 0x82)
        if (gn.tag == 0x82 and gn.value.len > 0) {
            if (out_pos > 0 and out_pos + 1 < 256) {
                info.tls_cert_san[out_pos] = ',';
                out_pos += 1;
            }
            const n: u16 = @intCast(@min(gn.value.len, @as(usize, 256) -| out_pos));
            if (n == 0) break;
            @memcpy(info.tls_cert_san[out_pos..][0..n], gn.value[0..n]);
            out_pos += n;
        }
        pos += gn.header_len + gn.value.len;
    }
    info.tls_cert_san_len = out_pos;
}

fn parseQuic(payload: []const u8, info: *PacketInfo) void {
    if (payload.len < 5) return;
    const first = payload[0];

    if (first & 0x80 != 0) {
        // Long header: fixed bit (0x40) must be set for QUIC v1/v2
        if (first & 0x40 == 0) return;
        if (payload.len < 6) return;
        const version = @as(u32, payload[1]) << 24 | @as(u32, payload[2]) << 16 |
            @as(u32, payload[3]) << 8 | @as(u32, payload[4]);
        // QUIC v1 (RFC 9000) or v2 (RFC 9369)
        if (version != 0x00000001 and version != 0x6B3343CF) return;
        const ptype = (first & 0x30) >> 4;
        info.quic_state = switch (ptype) {
            0x00 => .initial,
            0x01 => .zero_rtt,
            0x02 => .handshake,
            0x03 => .retry,
            else => return,
        };
    } else {
        // Short header (1-RTT): fixed bit must be set, common QUIC port
        if (first & 0x40 == 0) return;
        if (info.src_port != 443 and info.dst_port != 443) return;
        info.quic_state = .connected;
    }
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

    var groups: [8]u16 = undefined;
    for (0..8) |i| {
        groups[i] = readU16(bytes, i * 2);
    }

    // RFC 5952: find the longest run of consecutive zero groups.
    // On tie, first run wins.
    var best_start: usize = 8;
    var best_len: usize = 0;
    var run_start: usize = 0;
    var run_len: usize = 0;
    for (0..8) |i| {
        if (groups[i] == 0) {
            if (run_len == 0) run_start = i;
            run_len += 1;
        } else {
            if (run_len > best_len) {
                best_start = run_start;
                best_len = run_len;
            }
            run_len = 0;
        }
    }
    if (run_len > best_len) {
        best_start = run_start;
        best_len = run_len;
    }
    // RFC 5952: do not compress a single zero group
    if (best_len <= 1) {
        best_start = 8;
        best_len = 0;
    }

    var pos: usize = 0;
    var i: usize = 0;
    while (i < 8) {
        if (i == best_start) {
            out[pos] = ':';
            out[pos + 1] = ':';
            pos += 2;
            i += best_len;
            continue;
        }
        if (i > 0 and pos > 0 and out[pos - 1] != ':') {
            out[pos] = ':';
            pos += 1;
        }
        const s = std.fmt.bufPrint(out[pos..], "{x}", .{groups[i]}) catch return 0;
        pos += s.len;
        i += 1;
    }
    return @intCast(pos);
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

test "parse HTTP GET request in TCP payload" {
    // Ethernet(14) + IPv4(20, ihl=5, proto=6) + TCP(20, data_off=5) + HTTP
    const http_payload = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n";
    const header_len = 14 + 20 + 20;
    var frame: [header_len + http_payload.len]u8 = .{0} ** (header_len + http_payload.len);
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[14] = 0x45;
    frame[23] = 6; // TCP
    frame[26] = 10;
    frame[29] = 1;
    frame[30] = 10;
    frame[33] = 2;
    // TCP: src port 54321, dst port 80, data offset = 5 (20 bytes)
    frame[34] = 0xD4;
    frame[35] = 0x31;
    frame[36] = 0x00;
    frame[37] = 0x50;
    frame[46] = 0x50; // data offset 5 << 4
    @memcpy(frame[header_len..], http_payload);

    const info = parse(&frame).?;
    try std.testing.expectEqualStrings("GET /index.html HTTP/1.1", info.httpInfo());
}

test "parse HTTP response" {
    const http_payload = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n";
    const header_len = 14 + 20 + 20;
    var frame: [header_len + http_payload.len]u8 = .{0} ** (header_len + http_payload.len);
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[14] = 0x45;
    frame[23] = 6;
    frame[26] = 10;
    frame[29] = 2;
    frame[30] = 10;
    frame[33] = 1;
    frame[34] = 0x00;
    frame[35] = 0x50;
    frame[36] = 0xD4;
    frame[37] = 0x31;
    frame[46] = 0x50;
    @memcpy(frame[header_len..], http_payload);

    const info = parse(&frame).?;
    try std.testing.expectEqualStrings("HTTP/1.1 200 OK", info.httpInfo());
}

test "parse TLS ClientHello extracts SNI" {
    // Build a minimal TLS ClientHello with SNI extension for "example.com"
    const hostname = "example.com";

    // SNI extension payload: list_len(2) + type(1) + name_len(2) + name
    const sni_payload_len = 2 + 1 + 2 + hostname.len;
    // Extension: type(2) + length(2) + payload
    const ext_block_len = 4 + sni_payload_len;
    // Extensions header: total_length(2) + ext_block
    const extensions_len = 2 + ext_block_len;

    // ClientHello body: version(2) + random(32) + session_id_len(1)
    //   + cipher_suites_len(2) + one suite(2) + comp_len(1) + comp(1) + extensions
    const ch_body_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + extensions_len;
    // Handshake: type(1) + length(3) + body
    const hs_len = 4 + ch_body_len;
    // TLS record: type(1) + version(2) + length(2) + handshake
    const tls_len = 5 + hs_len;

    const header_len = 14 + 20 + 20; // Ethernet + IPv4 + TCP
    var frame: [header_len + tls_len]u8 = .{0} ** (header_len + tls_len);

    // Ethernet: IPv4
    frame[12] = 0x08;
    frame[13] = 0x00;
    // IPv4
    frame[14] = 0x45;
    frame[23] = 6; // TCP
    frame[26] = 10;
    frame[29] = 1;
    frame[30] = 10;
    frame[33] = 2;
    // TCP: src 54321, dst 443, data offset 5
    frame[34] = 0xD4;
    frame[35] = 0x31;
    frame[36] = 0x01;
    frame[37] = 0xBB; // 443
    frame[46] = 0x50;

    // TLS record header
    var pos: usize = header_len;
    frame[pos] = 0x16; // Handshake
    frame[pos + 1] = 0x03;
    frame[pos + 2] = 0x01; // TLS 1.0
    frame[pos + 3] = @intCast(hs_len >> 8);
    frame[pos + 4] = @intCast(hs_len & 0xFF);
    pos += 5;

    // Handshake header
    frame[pos] = 0x01; // ClientHello
    frame[pos + 1] = @intCast(ch_body_len >> 16);
    frame[pos + 2] = @intCast((ch_body_len >> 8) & 0xFF);
    frame[pos + 3] = @intCast(ch_body_len & 0xFF);
    pos += 4;

    // ClientHello version
    frame[pos] = 0x03;
    frame[pos + 1] = 0x03; // TLS 1.2
    pos += 2;

    // Random (32 bytes of zeros)
    pos += 32;

    // Session ID length = 0
    frame[pos] = 0;
    pos += 1;

    // Cipher suites: length 2, one suite
    frame[pos] = 0x00;
    frame[pos + 1] = 0x02;
    frame[pos + 2] = 0xC0;
    frame[pos + 3] = 0x2F;
    pos += 4;

    // Compression methods: length 1, null
    frame[pos] = 0x01;
    frame[pos + 1] = 0x00;
    pos += 2;

    // Extensions total length
    frame[pos] = @intCast(ext_block_len >> 8);
    frame[pos + 1] = @intCast(ext_block_len & 0xFF);
    pos += 2;

    // SNI extension type = 0x0000
    frame[pos] = 0x00;
    frame[pos + 1] = 0x00;
    // Extension length
    frame[pos + 2] = @intCast(sni_payload_len >> 8);
    frame[pos + 3] = @intCast(sni_payload_len & 0xFF);
    pos += 4;

    // Server name list length
    const name_entry_len = 1 + 2 + hostname.len;
    frame[pos] = @intCast(name_entry_len >> 8);
    frame[pos + 1] = @intCast(name_entry_len & 0xFF);
    pos += 2;

    // Host name type = 0
    frame[pos] = 0x00;
    // Host name length
    frame[pos + 1] = @intCast(hostname.len >> 8);
    frame[pos + 2] = @intCast(hostname.len & 0xFF);
    pos += 3;

    // Host name
    @memcpy(frame[pos..][0..hostname.len], hostname);

    const info = parse(&frame).?;
    try std.testing.expectEqual(Protocol.tcp, info.protocol);
    try std.testing.expectEqual(@as(u16, 443), info.dst_port);
    try std.testing.expectEqualStrings("example.com", info.sniName());
    try std.testing.expectEqual(@as(u8, 0), info.http_info_len);
}

test "non-TLS TCP payload does not set SNI" {
    const payload = "some random data that is not TLS";
    const header_len = 14 + 20 + 20;
    var frame: [header_len + payload.len]u8 = .{0} ** (header_len + payload.len);
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[14] = 0x45;
    frame[23] = 6;
    frame[26] = 10;
    frame[29] = 1;
    frame[30] = 10;
    frame[33] = 2;
    frame[34] = 0xD4;
    frame[35] = 0x31;
    frame[36] = 0x01;
    frame[37] = 0xBB;
    frame[46] = 0x50;
    @memcpy(frame[header_len..], payload);

    const info = parse(&frame).?;
    try std.testing.expectEqual(@as(u8, 0), info.tls_sni_len);
}

test "fmtIpv6 compresses longest zero run" {
    var out: [46]u8 = undefined;
    // 2001:db8:0:0:0:0:0:1 -> 2001:db8::1
    var bytes = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    var len = fmtIpv6(&bytes, &out);
    try std.testing.expectEqualStrings("2001:db8::1", out[0..len]);

    // ::1 (loopback)
    bytes = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    len = fmtIpv6(&bytes, &out);
    try std.testing.expectEqualStrings("::1", out[0..len]);

    // :: (all zeros)
    bytes = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    len = fmtIpv6(&bytes, &out);
    try std.testing.expectEqualStrings("::", out[0..len]);

    // fe80::1 (link-local)
    bytes = [16]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    len = fmtIpv6(&bytes, &out);
    try std.testing.expectEqualStrings("fe80::1", out[0..len]);

    // No compression for single zero group: 2001:db8:0:1:0:0:0:1
    bytes = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1 };
    len = fmtIpv6(&bytes, &out);
    try std.testing.expectEqualStrings("2001:db8:0:1::1", out[0..len]);

    // No zero runs: all groups non-zero
    bytes = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6 };
    len = fmtIpv6(&bytes, &out);
    try std.testing.expectEqualStrings("2001:db8:1:2:3:4:5:6", out[0..len]);

    // Trailing zeros: 2001:db8:1:0:0:0:0:0 -> 2001:db8:1::
    bytes = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    len = fmtIpv6(&bytes, &out);
    try std.testing.expectEqualStrings("2001:db8:1::", out[0..len]);
}

test "detect QUIC Initial packet (v1 long header)" {
    // Ethernet(14) + IPv4(20, proto=17) + UDP(8) + QUIC long header
    const quic_payload = [_]u8{
        0xC0, // Long header: 1 1 00 .... (Initial)
        0x00, 0x00, 0x00, 0x01, // Version: QUIC v1
        0x08, // DCID length
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
        0x00, // SCID length
    };
    const header_len = 14 + 20 + 8;
    var frame: [header_len + quic_payload.len]u8 = .{0} ** (header_len + quic_payload.len);
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[14] = 0x45;
    frame[23] = 17; // UDP
    frame[26] = 10;
    frame[29] = 1;
    frame[30] = 10;
    frame[33] = 2;
    frame[34] = 0xD4;
    frame[35] = 0x31; // src port 54321
    frame[36] = 0x01;
    frame[37] = 0xBB; // dst port 443
    @memcpy(frame[header_len..][0..quic_payload.len], &quic_payload);

    const info = parse(&frame).?;
    try std.testing.expectEqual(Protocol.udp, info.protocol);
    try std.testing.expectEqual(QuicState.initial, info.quic_state);
    try std.testing.expectEqualStrings("QUIC-I", info.protoLabel());
}

test "detect QUIC Handshake packet (v1 long header)" {
    const quic_payload = [_]u8{
        0xE0, // Long header: 1 1 10 .... (Handshake)
        0x00, 0x00, 0x00, 0x01, // Version: QUIC v1
        0x04, // DCID length
        0xAA, 0xBB, 0xCC, 0xDD, // DCID
        0x00, // SCID length
    };
    const header_len = 14 + 20 + 8;
    var frame: [header_len + quic_payload.len]u8 = .{0} ** (header_len + quic_payload.len);
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[14] = 0x45;
    frame[23] = 17;
    frame[26] = 10;
    frame[29] = 1;
    frame[30] = 10;
    frame[33] = 2;
    frame[34] = 0x04;
    frame[35] = 0xD2; // src port 1234
    frame[36] = 0x01;
    frame[37] = 0xBB; // dst port 443
    @memcpy(frame[header_len..][0..quic_payload.len], &quic_payload);

    const info = parse(&frame).?;
    try std.testing.expectEqual(QuicState.handshake, info.quic_state);
    try std.testing.expectEqualStrings("QUIC-HS", info.protoLabel());
}

test "detect QUIC short header as Connected on port 443" {
    const quic_payload = [_]u8{
        0x40, // Short header: 0 1 ...... (fixed bit set)
        0x01, 0x02, 0x03, 0x04, // Packet data
    };
    const header_len = 14 + 20 + 8;
    var frame: [header_len + quic_payload.len]u8 = .{0} ** (header_len + quic_payload.len);
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[14] = 0x45;
    frame[23] = 17;
    frame[26] = 10;
    frame[29] = 1;
    frame[30] = 10;
    frame[33] = 2;
    frame[34] = 0xD4;
    frame[35] = 0x31; // src port 54321
    frame[36] = 0x01;
    frame[37] = 0xBB; // dst port 443
    @memcpy(frame[header_len..][0..quic_payload.len], &quic_payload);

    const info = parse(&frame).?;
    try std.testing.expectEqual(QuicState.connected, info.quic_state);
    try std.testing.expectEqualStrings("QUIC", info.protoLabel());
}

test "non-QUIC UDP does not set quic_state" {
    var frame: [50]u8 = .{0} ** 50;
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[14] = 0x45;
    frame[23] = 17;
    frame[26] = 10;
    frame[29] = 1;
    frame[30] = 10;
    frame[33] = 2;
    frame[34] = 0x04;
    frame[35] = 0xD2; // src port 1234
    frame[36] = 0x13;
    frame[37] = 0x88; // dst port 5000
    // Random payload, not QUIC
    frame[42] = 0x00;
    frame[43] = 0x01;
    frame[44] = 0x02;

    const info = parse(&frame).?;
    try std.testing.expectEqual(QuicState.none, info.quic_state);
    try std.testing.expectEqualStrings("UDP", info.protoLabel());
}

test "detect mDNS on UDP port 5353" {
    var frame: [60]u8 = .{0} ** 60;
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[14] = 0x45;
    frame[23] = 17; // UDP
    frame[26] = 10;
    frame[29] = 1;
    frame[30] = 224;
    frame[33] = 251; // 224.0.0.251
    frame[34] = 0x14;
    frame[35] = 0xE9; // src port 5353
    frame[36] = 0x14;
    frame[37] = 0xE9; // dst port 5353

    const info = parse(&frame).?;
    try std.testing.expectEqual(AppProto.mdns, info.app_proto);
    try std.testing.expectEqualStrings("mDNS", info.protoLabel());
}

test "detect DHCP on UDP port 67" {
    var frame: [50]u8 = .{0} ** 50;
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[14] = 0x45;
    frame[23] = 17;
    frame[26] = 0;
    frame[29] = 0; // 0.0.0.0
    frame[30] = 255;
    frame[31] = 255;
    frame[32] = 255;
    frame[33] = 255; // 255.255.255.255
    frame[34] = 0x00;
    frame[35] = 0x44; // src port 68
    frame[36] = 0x00;
    frame[37] = 0x43; // dst port 67

    const info = parse(&frame).?;
    try std.testing.expectEqual(AppProto.dhcp, info.app_proto);
    try std.testing.expectEqualStrings("DHCP", info.protoLabel());
}

test "detect NTP on UDP port 123" {
    var frame: [50]u8 = .{0} ** 50;
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[14] = 0x45;
    frame[23] = 17;
    frame[26] = 10;
    frame[29] = 1;
    frame[30] = 10;
    frame[33] = 2;
    frame[34] = 0xC0;
    frame[35] = 0x00; // src port 49152
    frame[36] = 0x00;
    frame[37] = 0x7B; // dst port 123

    const info = parse(&frame).?;
    try std.testing.expectEqual(AppProto.ntp, info.app_proto);
    try std.testing.expectEqualStrings("NTP", info.protoLabel());
}

test "detect SSH banner in TCP payload" {
    const ssh_payload = "SSH-2.0-OpenSSH_9.6\r\n";
    const header_len = 14 + 20 + 20;
    var frame: [header_len + ssh_payload.len]u8 = .{0} ** (header_len + ssh_payload.len);
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[14] = 0x45;
    frame[23] = 6; // TCP
    frame[26] = 10;
    frame[29] = 1;
    frame[30] = 10;
    frame[33] = 2;
    frame[34] = 0x00;
    frame[35] = 0x16; // src port 22
    frame[36] = 0xD4;
    frame[37] = 0x31; // dst port 54321
    frame[46] = 0x50; // data offset 5
    @memcpy(frame[header_len..], ssh_payload);

    const info = parse(&frame).?;
    try std.testing.expectEqual(AppProto.ssh, info.app_proto);
    try std.testing.expectEqualStrings("SSH", info.protoLabel());
    try std.testing.expectEqualStrings("SSH-2.0-OpenSSH_9.6", info.httpInfo());
}

fn buildDerLen(buf: []u8, length: usize) usize {
    if (length < 128) {
        buf[0] = @intCast(length);
        return 1;
    } else if (length < 256) {
        buf[0] = 0x81;
        buf[1] = @intCast(length);
        return 2;
    } else {
        buf[0] = 0x82;
        buf[1] = @intCast(length >> 8);
        buf[2] = @intCast(length & 0xFF);
        return 3;
    }
}

fn wrapDer(buf: []u8, tag: u8, content: []const u8) usize {
    buf[0] = tag;
    var len_buf: [3]u8 = undefined;
    const len_size = buildDerLen(&len_buf, content.len);
    @memcpy(buf[1..][0..len_size], len_buf[0..len_size]);
    @memcpy(buf[1 + len_size ..][0..content.len], content);
    return 1 + len_size + content.len;
}

fn buildMinimalCert(buf: []u8) usize {
    // Build a minimal X.509 cert with:
    //   CN=example.com, SAN=example.com,www.example.com, notAfter=2027-06-15 12:00:00

    // -- Subject CN --
    const cn_value = "example.com";
    // OID 2.5.4.3 for CN
    const cn_oid = [_]u8{ 0x06, 0x03, 0x55, 0x04, 0x03 };
    // CN value as UTF8String
    var cn_str: [32]u8 = undefined;
    const cn_str_len = wrapDer(&cn_str, 0x0C, cn_value);
    // ATAV: SEQUENCE { OID, value }
    var atav: [64]u8 = undefined;
    @memcpy(atav[0..cn_oid.len], &cn_oid);
    @memcpy(atav[cn_oid.len..][0..cn_str_len], cn_str[0..cn_str_len]);
    var atav_seq: [70]u8 = undefined;
    const atav_seq_len = wrapDer(&atav_seq, 0x30, atav[0 .. cn_oid.len + cn_str_len]);
    // RDN: SET { ATAV }
    var rdn: [76]u8 = undefined;
    const rdn_len = wrapDer(&rdn, 0x31, atav_seq[0..atav_seq_len]);
    // Subject: SEQUENCE { RDN }
    var subject: [80]u8 = undefined;
    const subject_len = wrapDer(&subject, 0x30, rdn[0..rdn_len]);

    // -- Validity --
    // notBefore: UTCTime "220101120000Z"
    const not_before_val = "220101120000Z";
    var not_before: [20]u8 = undefined;
    const not_before_len = wrapDer(&not_before, 0x17, not_before_val);
    // notAfter: UTCTime "270615120000Z"
    const not_after_val = "270615120000Z";
    var not_after: [20]u8 = undefined;
    const not_after_len = wrapDer(&not_after, 0x17, not_after_val);
    var validity_inner: [40]u8 = undefined;
    @memcpy(validity_inner[0..not_before_len], not_before[0..not_before_len]);
    @memcpy(validity_inner[not_before_len..][0..not_after_len], not_after[0..not_after_len]);
    var validity: [48]u8 = undefined;
    const validity_len = wrapDer(&validity, 0x30, validity_inner[0 .. not_before_len + not_after_len]);

    // -- SAN extension --
    const san1 = "example.com";
    const san2 = "www.example.com";
    var san_names_inner: [64]u8 = undefined;
    var sp: usize = 0;
    // dNSName [2] for san1
    sp += wrapDer(san_names_inner[sp..], 0x82, san1);
    // dNSName [2] for san2
    sp += wrapDer(san_names_inner[sp..], 0x82, san2);
    var san_seq: [70]u8 = undefined;
    const san_seq_len = wrapDer(&san_seq, 0x30, san_names_inner[0..sp]);
    // Wrap in OCTET STRING
    var san_octet: [76]u8 = undefined;
    const san_octet_len = wrapDer(&san_octet, 0x04, san_seq[0..san_seq_len]);
    // Extension: SEQUENCE { OID 2.5.29.17, OCTET STRING }
    const san_oid = [_]u8{ 0x06, 0x03, 0x55, 0x1D, 0x11 };
    var ext_inner: [90]u8 = undefined;
    @memcpy(ext_inner[0..san_oid.len], &san_oid);
    @memcpy(ext_inner[san_oid.len..][0..san_octet_len], san_octet[0..san_octet_len]);
    var ext_seq: [96]u8 = undefined;
    const ext_seq_len = wrapDer(&ext_seq, 0x30, ext_inner[0 .. san_oid.len + san_octet_len]);
    // Extensions: SEQUENCE { extension }
    var exts_seq: [100]u8 = undefined;
    const exts_seq_len = wrapDer(&exts_seq, 0x30, ext_seq[0..ext_seq_len]);
    // Wrap in context [3]
    var exts_wrapper: [106]u8 = undefined;
    const exts_wrapper_len = wrapDer(&exts_wrapper, 0xA3, exts_seq[0..exts_seq_len]);

    // -- TBSCertificate --
    // version [0] EXPLICIT INTEGER 2 (v3)
    const version_int = [_]u8{ 0x02, 0x01, 0x02 }; // INTEGER 2
    var version: [8]u8 = undefined;
    const version_len = wrapDer(&version, 0xA0, &version_int);
    // serialNumber: INTEGER 1
    const serial = [_]u8{ 0x02, 0x01, 0x01 };
    // signature AlgorithmIdentifier: SEQUENCE { OID sha256WithRSA }
    const sig_alg = [_]u8{ 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00 };
    // issuer: empty SEQUENCE
    const issuer = [_]u8{ 0x30, 0x00 };
    // subjectPublicKeyInfo: minimal SEQUENCE
    const spki = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x00 };

    var tbs_inner: [512]u8 = undefined;
    var tp: usize = 0;
    @memcpy(tbs_inner[tp..][0..version_len], version[0..version_len]);
    tp += version_len;
    @memcpy(tbs_inner[tp..][0..serial.len], &serial);
    tp += serial.len;
    @memcpy(tbs_inner[tp..][0..sig_alg.len], &sig_alg);
    tp += sig_alg.len;
    @memcpy(tbs_inner[tp..][0..issuer.len], &issuer);
    tp += issuer.len;
    @memcpy(tbs_inner[tp..][0..validity_len], validity[0..validity_len]);
    tp += validity_len;
    @memcpy(tbs_inner[tp..][0..subject_len], subject[0..subject_len]);
    tp += subject_len;
    @memcpy(tbs_inner[tp..][0..spki.len], &spki);
    tp += spki.len;
    @memcpy(tbs_inner[tp..][0..exts_wrapper_len], exts_wrapper[0..exts_wrapper_len]);
    tp += exts_wrapper_len;

    var tbs_seq: [520]u8 = undefined;
    const tbs_seq_len = wrapDer(&tbs_seq, 0x30, tbs_inner[0..tp]);

    // Certificate outer: SEQUENCE { tbs, sigAlg, sigValue }
    var cert_inner: [560]u8 = undefined;
    @memcpy(cert_inner[0..tbs_seq_len], tbs_seq[0..tbs_seq_len]);
    @memcpy(cert_inner[tbs_seq_len..][0..sig_alg.len], &sig_alg);
    const sig_val = [_]u8{ 0x03, 0x02, 0x00, 0x00 }; // BIT STRING, empty
    @memcpy(cert_inner[tbs_seq_len + sig_alg.len ..][0..sig_val.len], &sig_val);
    const cert_inner_len = tbs_seq_len + sig_alg.len + sig_val.len;
    const cert_len = wrapDer(buf, 0x30, cert_inner[0..cert_inner_len]);
    return cert_len;
}

test "parse TLS Certificate extracts CN, SAN and expiry" {
    var cert_buf: [600]u8 = undefined;
    const cert_len = buildMinimalCert(&cert_buf);

    // TLS Certificate message: cert_list_length(3) + cert_length(3) + cert
    const cert_list_len = 3 + cert_len;
    const cert_msg_body_len = 3 + cert_list_len;
    // Handshake: type(1) + length(3) + body
    const hs_len = 4 + cert_msg_body_len;
    const header_len = 14 + 20 + 20;

    var frame: [header_len + 700]u8 = .{0} ** (header_len + 700);

    // Ethernet + IPv4 + TCP headers
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[14] = 0x45;
    frame[23] = 6;
    frame[26] = 10;
    frame[29] = 2;
    frame[30] = 10;
    frame[33] = 1;
    frame[34] = 0x01;
    frame[35] = 0xBB; // src port 443
    frame[36] = 0xD4;
    frame[37] = 0x31;
    frame[46] = 0x50;

    var pos: usize = header_len;

    // TLS record header
    frame[pos] = 0x16; // Handshake
    frame[pos + 1] = 0x03;
    frame[pos + 2] = 0x03;
    frame[pos + 3] = @intCast(hs_len >> 8);
    frame[pos + 4] = @intCast(hs_len & 0xFF);
    pos += 5;

    // Handshake: Certificate (0x0B)
    frame[pos] = 0x0B;
    frame[pos + 1] = @intCast(cert_msg_body_len >> 16);
    frame[pos + 2] = @intCast((cert_msg_body_len >> 8) & 0xFF);
    frame[pos + 3] = @intCast(cert_msg_body_len & 0xFF);
    pos += 4;

    // Certificate list length
    frame[pos] = @intCast(cert_list_len >> 16);
    frame[pos + 1] = @intCast((cert_list_len >> 8) & 0xFF);
    frame[pos + 2] = @intCast(cert_list_len & 0xFF);
    pos += 3;

    // First cert length
    frame[pos] = @intCast(cert_len >> 16);
    frame[pos + 1] = @intCast((cert_len >> 8) & 0xFF);
    frame[pos + 2] = @intCast(cert_len & 0xFF);
    pos += 3;

    // Cert data
    @memcpy(frame[pos..][0..cert_len], cert_buf[0..cert_len]);

    const info = parse(&frame).?;
    try std.testing.expectEqualStrings("example.com", info.certCn());
    try std.testing.expectEqualStrings("example.com,www.example.com", info.certSan());
    try std.testing.expectEqualStrings("2027-06-15 12:00:00", info.certExpiry());
}

test "TLS Certificate with no SAN extension only extracts CN and expiry" {
    // Build a cert without SAN extension manually
    const cn_value = "test.local";
    const cn_oid = [_]u8{ 0x06, 0x03, 0x55, 0x04, 0x03 };
    var cn_str: [32]u8 = undefined;
    const cn_str_len = wrapDer(&cn_str, 0x0C, cn_value);
    var atav: [64]u8 = undefined;
    @memcpy(atav[0..cn_oid.len], &cn_oid);
    @memcpy(atav[cn_oid.len..][0..cn_str_len], cn_str[0..cn_str_len]);
    var atav_seq: [70]u8 = undefined;
    const atav_seq_len = wrapDer(&atav_seq, 0x30, atav[0 .. cn_oid.len + cn_str_len]);
    var rdn: [76]u8 = undefined;
    const rdn_len = wrapDer(&rdn, 0x31, atav_seq[0..atav_seq_len]);
    var subject: [80]u8 = undefined;
    const subject_len = wrapDer(&subject, 0x30, rdn[0..rdn_len]);

    const not_before_val = "220101000000Z";
    var not_before: [20]u8 = undefined;
    const not_before_len = wrapDer(&not_before, 0x17, not_before_val);
    const not_after_val = "301231235959Z";
    var not_after: [20]u8 = undefined;
    const not_after_len = wrapDer(&not_after, 0x17, not_after_val);
    var validity_inner: [40]u8 = undefined;
    @memcpy(validity_inner[0..not_before_len], not_before[0..not_before_len]);
    @memcpy(validity_inner[not_before_len..][0..not_after_len], not_after[0..not_after_len]);
    var validity: [48]u8 = undefined;
    const validity_len = wrapDer(&validity, 0x30, validity_inner[0 .. not_before_len + not_after_len]);

    const version_int = [_]u8{ 0x02, 0x01, 0x02 };
    var version: [8]u8 = undefined;
    const version_len = wrapDer(&version, 0xA0, &version_int);
    const serial = [_]u8{ 0x02, 0x01, 0x01 };
    const sig_alg = [_]u8{ 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00 };
    const issuer = [_]u8{ 0x30, 0x00 };
    const spki = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x00 };

    var tbs_inner: [300]u8 = undefined;
    var tp: usize = 0;
    @memcpy(tbs_inner[tp..][0..version_len], version[0..version_len]);
    tp += version_len;
    @memcpy(tbs_inner[tp..][0..serial.len], &serial);
    tp += serial.len;
    @memcpy(tbs_inner[tp..][0..sig_alg.len], &sig_alg);
    tp += sig_alg.len;
    @memcpy(tbs_inner[tp..][0..issuer.len], &issuer);
    tp += issuer.len;
    @memcpy(tbs_inner[tp..][0..validity_len], validity[0..validity_len]);
    tp += validity_len;
    @memcpy(tbs_inner[tp..][0..subject_len], subject[0..subject_len]);
    tp += subject_len;
    @memcpy(tbs_inner[tp..][0..spki.len], &spki);
    tp += spki.len;
    // No extensions

    var tbs_seq: [320]u8 = undefined;
    const tbs_seq_len = wrapDer(&tbs_seq, 0x30, tbs_inner[0..tp]);

    var cert_inner: [360]u8 = undefined;
    @memcpy(cert_inner[0..tbs_seq_len], tbs_seq[0..tbs_seq_len]);
    @memcpy(cert_inner[tbs_seq_len..][0..sig_alg.len], &sig_alg);
    const sig_val = [_]u8{ 0x03, 0x02, 0x00, 0x00 };
    @memcpy(cert_inner[tbs_seq_len + sig_alg.len ..][0..sig_val.len], &sig_val);
    const cert_inner_len = tbs_seq_len + sig_alg.len + sig_val.len;
    var cert_buf: [400]u8 = undefined;
    const cert_len = wrapDer(&cert_buf, 0x30, cert_inner[0..cert_inner_len]);

    // Now wrap in TLS Certificate message
    const cert_list_len = 3 + cert_len;
    const cert_msg_body_len = 3 + cert_list_len;
    const hs_len = 4 + cert_msg_body_len;
    const hdr_len = 14 + 20 + 20;

    var frame: [hdr_len + 500]u8 = .{0} ** (hdr_len + 500);
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[14] = 0x45;
    frame[23] = 6;
    frame[26] = 10;
    frame[29] = 2;
    frame[30] = 10;
    frame[33] = 1;
    frame[34] = 0x01;
    frame[35] = 0xBB;
    frame[36] = 0xD4;
    frame[37] = 0x31;
    frame[46] = 0x50;

    var pos: usize = hdr_len;
    frame[pos] = 0x16;
    frame[pos + 1] = 0x03;
    frame[pos + 2] = 0x03;
    frame[pos + 3] = @intCast(hs_len >> 8);
    frame[pos + 4] = @intCast(hs_len & 0xFF);
    pos += 5;
    frame[pos] = 0x0B;
    frame[pos + 1] = @intCast(cert_msg_body_len >> 16);
    frame[pos + 2] = @intCast((cert_msg_body_len >> 8) & 0xFF);
    frame[pos + 3] = @intCast(cert_msg_body_len & 0xFF);
    pos += 4;
    frame[pos] = @intCast(cert_list_len >> 16);
    frame[pos + 1] = @intCast((cert_list_len >> 8) & 0xFF);
    frame[pos + 2] = @intCast(cert_list_len & 0xFF);
    pos += 3;
    frame[pos] = @intCast(cert_len >> 16);
    frame[pos + 1] = @intCast((cert_len >> 8) & 0xFF);
    frame[pos + 2] = @intCast(cert_len & 0xFF);
    pos += 3;
    @memcpy(frame[pos..][0..cert_len], cert_buf[0..cert_len]);

    const info = parse(&frame).?;
    try std.testing.expectEqualStrings("test.local", info.certCn());
    try std.testing.expectEqualStrings("2030-12-31 23:59:59", info.certExpiry());
    try std.testing.expectEqual(@as(u16, 0), info.tls_cert_san_len);
}

test "non-Certificate TLS handshake does not set cert fields" {
    // A ServerHello (type 0x02) should not populate cert fields
    const header_len = 14 + 20 + 20;
    const sh_body_len: usize = 38; // version(2) + random(32) + session_id_len(1) + cipher(2) + comp(1)
    const hs_len = 4 + sh_body_len;
    const tls_len = 5 + hs_len;

    var frame: [header_len + tls_len]u8 = .{0} ** (header_len + tls_len);
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[14] = 0x45;
    frame[23] = 6;
    frame[26] = 10;
    frame[29] = 2;
    frame[30] = 10;
    frame[33] = 1;
    frame[34] = 0x01;
    frame[35] = 0xBB;
    frame[36] = 0xD4;
    frame[37] = 0x31;
    frame[46] = 0x50;

    var pos: usize = header_len;
    frame[pos] = 0x16;
    frame[pos + 1] = 0x03;
    frame[pos + 2] = 0x03;
    frame[pos + 3] = @intCast(hs_len >> 8);
    frame[pos + 4] = @intCast(hs_len & 0xFF);
    pos += 5;
    frame[pos] = 0x02; // ServerHello
    frame[pos + 1] = 0x00;
    frame[pos + 2] = @intCast((sh_body_len >> 8) & 0xFF);
    frame[pos + 3] = @intCast(sh_body_len & 0xFF);

    const info = parse(&frame).?;
    try std.testing.expectEqual(@as(u8, 0), info.tls_cert_cn_len);
    try std.testing.expectEqual(@as(u16, 0), info.tls_cert_san_len);
    try std.testing.expectEqual(@as(u8, 0), info.tls_cert_expiry_len);
}
