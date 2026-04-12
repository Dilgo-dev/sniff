// Cross-platform packet capture.
//
// Linux: AF_PACKET raw socket (all interfaces, or bind to one).
// macOS: BPF device (/dev/bpfN, bound to a named interface).
// Windows: raw socket with SIO_RCVALL (no extra install needed).

const std = @import("std");
const builtin = @import("builtin");

pub const CaptureHandle = switch (builtin.os.tag) {
    .linux => std.posix.fd_t,
    .macos => std.posix.fd_t,
    .windows => usize, // SOCKET
    else => @compileError("unsupported OS for packet capture"),
};

pub const CaptureError = error{
    PermissionDenied,
    NoDevice,
    OpenFailed,
    ReadFailed,
};

/// Fixed-size interface name (max 15 chars + NUL, like IFNAMSIZ).
pub const IfName = struct {
    buf: [16]u8 = .{0} ** 16,
    len: u8 = 0,

    pub fn slice(self: *const IfName) []const u8 {
        return self.buf[0..self.len];
    }
};

pub const max_interfaces = 32;

/// List available network interfaces. Returns the count written to out.
pub fn listInterfaces(out: []IfName) usize {
    switch (builtin.os.tag) {
        .linux => return listLinuxIfaces(out),
        .macos => return listMacIfaces(out),
        .windows => return listWinIfaces(out),
        else => return 0,
    }
}

/// Open a capture device, optionally bound to a specific interface.
/// Pass null to capture on all interfaces (Linux) or the default (macOS/Win).
pub fn openOn(iface: ?[]const u8) CaptureError!CaptureHandle {
    switch (builtin.os.tag) {
        .linux => return openLinuxOn(iface),
        .macos => return openBpfOn(iface),
        .windows => return openWinOn(iface),
        else => comptime unreachable,
    }
}

/// Read one Ethernet frame into buf and return the valid slice.
pub fn readOne(handle: CaptureHandle, buf: []u8) CaptureError![]const u8 {
    switch (builtin.os.tag) {
        .linux => return readLinux(handle, buf),
        .macos => return readBpf(handle, buf),
        .windows => return readWin(handle, buf),
        else => comptime unreachable,
    }
}

/// Close the capture device.
pub fn close(handle: CaptureHandle) void {
    switch (builtin.os.tag) {
        .linux, .macos => std.posix.close(handle),
        .windows => closeWin(handle),
        else => comptime unreachable,
    }
}

/// Human-readable error string for display at startup.
pub fn errorMessage(err: CaptureError) []const u8 {
    return switch (err) {
        error.PermissionDenied => switch (builtin.os.tag) {
            .linux => "Permission denied. Run with sudo or set CAP_NET_RAW.",
            .macos => "Permission denied. Run with sudo.",
            .windows => "Permission denied. Run as Administrator.",
            else => "Permission denied.",
        },
        error.NoDevice => "No capture device found.",
        error.OpenFailed => "Failed to open capture device.",
        error.ReadFailed => "Failed to read from capture device.",
    };
}

// Linux: AF_PACKET raw socket

const linux = if (builtin.os.tag == .linux) struct {
    const AF_PACKET: u32 = 17;
    const SOCK_RAW: u32 = 3;
    const ETH_P_ALL: u16 = 0x0003;
    const SOL_SOCKET: u32 = 1;
    const SO_BINDTODEVICE: u32 = 25;

    fn openSocket() CaptureError!std.posix.fd_t {
        const rc = std.os.linux.socket(AF_PACKET, SOCK_RAW, std.mem.nativeToBig(u16, ETH_P_ALL));
        const signed: isize = @bitCast(rc);
        if (signed < 0) {
            const errno: std.posix.E = @enumFromInt(-signed);
            return switch (errno) {
                .PERM, .ACCES => error.PermissionDenied,
                else => error.OpenFailed,
            };
        }
        return @intCast(rc);
    }

    fn bindDevice(fd: std.posix.fd_t, iface: []const u8) CaptureError!void {
        var name: [16]u8 = .{0} ** 16;
        const len = @min(iface.len, 15);
        @memcpy(name[0..len], iface[0..len]);
        const rc = std.os.linux.setsockopt(@intCast(fd), SOL_SOCKET, SO_BINDTODEVICE, &name, 16);
        const signed: isize = @bitCast(rc);
        if (signed < 0) return error.OpenFailed;
    }

    fn read(fd: std.posix.fd_t, buf: []u8) CaptureError![]const u8 {
        const n = std.posix.read(fd, buf) catch return error.ReadFailed;
        if (n < 14) return error.ReadFailed;
        return buf[0..n];
    }
} else struct {};

fn openLinuxOn(iface: ?[]const u8) CaptureError!CaptureHandle {
    const fd = try linux.openSocket();
    if (iface) |name| {
        linux.bindDevice(fd, name) catch {
            std.posix.close(fd);
            return error.OpenFailed;
        };
    }
    return fd;
}

fn readLinux(handle: CaptureHandle, buf: []u8) CaptureError![]const u8 {
    return linux.read(handle, buf);
}

fn listLinuxIfaces(out: []IfName) usize {
    var dir = std.fs.openDirAbsolute("/sys/class/net", .{ .iterate = true }) catch return 0;
    defer dir.close();
    var iter = dir.iterate();
    var count: usize = 0;
    while (count < out.len) {
        const entry = (iter.next() catch null) orelse break;
        if (entry.name.len == 0 or entry.name.len > 15) continue;
        var ifn: IfName = .{};
        @memcpy(ifn.buf[0..entry.name.len], entry.name);
        ifn.len = @intCast(entry.name.len);
        out[count] = ifn;
        count += 1;
    }
    return count;
}

// macOS: BPF (Berkeley Packet Filter)

const bpf = if (builtin.os.tag == .macos) struct {
    // macOS ioctl takes c_int, not c_ulong
    const BIOCSBLEN: c_int = @bitCast(@as(c_uint, 0xc0044266));
    const BIOCSETIF: c_int = @bitCast(@as(c_uint, 0x8020426c));
    const BIOCIMMEDIATE: c_int = @bitCast(@as(c_uint, 0x80044270));
    const BIOCPROMISC: c_int = @bitCast(@as(c_uint, 0x20004269));

    const BPF_BUF_SIZE: u32 = 65536;

    const BpfHeader = extern struct {
        tv_sec: i32,
        tv_usec: i32,
        bh_caplen: u32,
        bh_datalen: u32,
        bh_hdrlen: u16,
    };

    var read_buf: [BPF_BUF_SIZE]u8 = undefined;
    var read_len: usize = 0;
    var read_pos: usize = 0;

    const Ifreq = extern struct {
        ifr_name: [16]u8,
        ifr_data: [16]u8,
    };

    const Ifaddrs = extern struct {
        ifa_next: ?*Ifaddrs,
        ifa_name: [*:0]const u8,
        ifa_flags: c_uint,
        ifa_addr: ?*anyopaque,
        ifa_netmask: ?*anyopaque,
        ifa_broadaddr: ?*anyopaque,
        ifa_data: ?*anyopaque,
    };

    extern "c" fn getifaddrs(ifap: *?*Ifaddrs) c_int;
    extern "c" fn freeifaddrs(ifa: *Ifaddrs) void;

    const IFF_UP: c_uint = 0x1;
    const IFF_LOOPBACK: c_uint = 0x8;

    fn openDevice() CaptureError!std.posix.fd_t {
        var path_buf: [16]u8 = undefined;
        var i: u32 = 0;
        while (i < 256) : (i += 1) {
            const path = std.fmt.bufPrint(&path_buf, "/dev/bpf{d}", .{i}) catch continue;
            if (path.len < path_buf.len) path_buf[path.len] = 0;
            const fd = std.posix.open(
                path_buf[0..path.len :0],
                .{ .ACCMODE = .RDONLY },
                @as(std.posix.mode_t, 0),
            ) catch |err| switch (err) {
                error.DeviceBusy => continue,
                error.AccessDenied => return error.PermissionDenied,
                else => continue,
            };
            return fd;
        }
        return error.NoDevice;
    }

    fn configureOn(fd: std.posix.fd_t, iface: []const u8) CaptureError!void {
        var buf_len: u32 = BPF_BUF_SIZE;
        _ = ioctl(fd, BIOCSBLEN, @intFromPtr(&buf_len)) catch return error.OpenFailed;

        var ifr: Ifreq = std.mem.zeroes(Ifreq);
        const len = @min(iface.len, 15);
        @memcpy(ifr.ifr_name[0..len], iface[0..len]);
        _ = ioctl(fd, BIOCSETIF, @intFromPtr(&ifr)) catch return error.OpenFailed;

        var imm: u32 = 1;
        _ = ioctl(fd, BIOCIMMEDIATE, @intFromPtr(&imm)) catch return error.OpenFailed;

        _ = ioctl(fd, BIOCPROMISC, 0) catch {};
    }

    fn ioctl(fd: std.posix.fd_t, request: c_int, arg: usize) !usize {
        const rc = std.c.ioctl(fd, request, arg);
        if (rc < 0) return error.IoctlFailed;
        return @intCast(rc);
    }

    fn readPacket(fd: std.posix.fd_t, out: []u8) CaptureError![]const u8 {
        if (read_pos < read_len) {
            if (extractPacket(out)) |frame| return frame;
        }

        const n = std.posix.read(fd, &read_buf) catch return error.ReadFailed;
        if (n == 0) return error.ReadFailed;
        read_len = n;
        read_pos = 0;

        return extractPacket(out) orelse error.ReadFailed;
    }

    fn extractPacket(out: []u8) ?[]const u8 {
        if (read_pos + @sizeOf(BpfHeader) > read_len) return null;

        const hdr: *const BpfHeader = @ptrCast(@alignCast(&read_buf[read_pos]));
        const data_start = read_pos + hdr.bh_hdrlen;
        const caplen: usize = hdr.bh_caplen;

        if (data_start + caplen > read_len) return null;

        const copy_len = @min(caplen, out.len);
        @memcpy(out[0..copy_len], read_buf[data_start..][0..copy_len]);

        const total = hdr.bh_hdrlen + hdr.bh_caplen;
        read_pos += std.mem.alignForward(usize, total, 4);

        return out[0..copy_len];
    }

    fn listIfaces(out: []IfName) usize {
        var ifap: ?*Ifaddrs = null;
        if (getifaddrs(&ifap) != 0) return 0;
        defer if (ifap) |p| freeifaddrs(p);

        var count: usize = 0;
        var cur = ifap;
        while (cur) |ifa| : (cur = ifa.ifa_next) {
            if (count >= out.len) break;
            if (ifa.ifa_flags & IFF_UP == 0) continue;
            if (ifa.ifa_flags & IFF_LOOPBACK != 0) continue;

            const name = std.mem.span(ifa.ifa_name);
            if (name.len == 0 or name.len > 15) continue;

            // getifaddrs returns one entry per address, not per interface
            var dup = false;
            for (out[0..count]) |existing| {
                if (std.mem.eql(u8, existing.slice(), name)) {
                    dup = true;
                    break;
                }
            }
            if (dup) continue;

            var ifn: IfName = .{};
            @memcpy(ifn.buf[0..name.len], name);
            ifn.len = @intCast(name.len);
            out[count] = ifn;
            count += 1;
        }
        return count;
    }

    var default_iface_buf: IfName = .{};

    fn defaultIface() []const u8 {
        var buf: [1]IfName = undefined;
        const n = listIfaces(&buf);
        if (n > 0) {
            default_iface_buf = buf[0];
            return default_iface_buf.buf[0..default_iface_buf.len];
        }
        return "en0";
    }
} else struct {};

fn openBpfOn(iface: ?[]const u8) CaptureError!CaptureHandle {
    const fd = try bpf.openDevice();
    const name = iface orelse bpf.defaultIface();
    bpf.configureOn(fd, name) catch |err| {
        std.posix.close(fd);
        return err;
    };
    return fd;
}

fn readBpf(handle: CaptureHandle, buf: []u8) CaptureError![]const u8 {
    return bpf.readPacket(handle, buf);
}

fn listMacIfaces(out: []IfName) usize {
    return bpf.listIfaces(out);
}

// Windows: raw socket with SIO_RCVALL.
// Packets arrive without Ethernet headers; readOne prepends a
// synthetic header to keep the parser uniform across platforms.

const win = if (builtin.os.tag == .windows) struct {
    const SOCKET = usize;
    const INVALID_SOCKET: SOCKET = ~@as(SOCKET, 0);
    const SIO_RCVALL: u32 = 0x98000001;
    const RCVALL_ON: u32 = 1;
    const FIONBIO: c_long = @bitCast(@as(u32, 0x8004667E));

    const WSADATA = extern struct { data: [512]u8 };

    const sockaddr_in = extern struct {
        family: u16 = 2,
        port: u16 = 0,
        addr: u32 = 0,
        zero: [8]u8 = .{0} ** 8,
    };

    const Hostent = extern struct {
        h_name: ?[*:0]u8,
        h_aliases: ?*?[*:0]u8,
        h_addrtype: c_short,
        h_length: c_short,
        h_addr_list: [*]?[*]u8,
    };

    extern "ws2_32" fn WSAStartup(ver: u16, data: *WSADATA) callconv(.winapi) c_int;
    extern "ws2_32" fn WSACleanup() callconv(.winapi) c_int;
    extern "ws2_32" fn socket(af: c_int, sock_type: c_int, protocol: c_int) callconv(.winapi) SOCKET;
    extern "ws2_32" fn bind(s: SOCKET, addr: *const sockaddr_in, len: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn recv(s: SOCKET, buf_ptr: [*]u8, len: c_int, flags: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn closesocket(s: SOCKET) callconv(.winapi) c_int;
    extern "ws2_32" fn ioctlsocket(s: SOCKET, cmd: c_long, argp: *u32) callconv(.winapi) c_int;
    extern "ws2_32" fn gethostname(name: [*]u8, len: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn gethostbyname(name: [*:0]const u8) callconv(.winapi) ?*Hostent;
    extern "ws2_32" fn inet_ntoa(addr: u32) callconv(.winapi) ?[*:0]const u8;

    extern "ws2_32" fn WSAIoctl(
        s: SOCKET,
        code: u32,
        in_buf: ?*const anyopaque,
        in_size: u32,
        out_buf: ?*anyopaque,
        out_size: u32,
        bytes_ret: *u32,
        overlap: ?*anyopaque,
        completion: ?*anyopaque,
    ) callconv(.winapi) c_int;

    fn initWsa() bool {
        var wsa: WSADATA = undefined;
        return WSAStartup(0x0202, &wsa) == 0;
    }

    fn resolveHost() ?*Hostent {
        var hostname: [256]u8 = .{0} ** 256;
        if (gethostname(&hostname, 256) != 0) return null;
        return gethostbyname(@ptrCast(&hostname));
    }

    /// Parse a dotted-decimal IPv4 string into a network-order u32.
    fn parseIp(s: []const u8) ?u32 {
        var octets: [4]u8 = undefined;
        var idx: usize = 0;
        var start: usize = 0;
        for (s, 0..) |c, i| {
            if (c == '.' or i == s.len - 1) {
                const end = if (c == '.') i else i + 1;
                const val = std.fmt.parseInt(u8, s[start..end], 10) catch return null;
                if (idx >= 4) return null;
                octets[idx] = val;
                idx += 1;
                start = i + 1;
            }
        }
        if (idx != 4) return null;
        return @as(u32, octets[0]) | (@as(u32, octets[1]) << 8) | (@as(u32, octets[2]) << 16) | (@as(u32, octets[3]) << 24);
    }

    fn openDeviceOn(iface: ?[]const u8) CaptureError!SOCKET {
        if (!initWsa()) return error.OpenFailed;

        const s = socket(2, 3, 0);
        if (s == INVALID_SOCKET) return error.PermissionDenied;

        const ip: u32 = blk: {
            if (iface) |name| {
                if (parseIp(name)) |addr| break :blk addr;
                // Numeric index selects the nth host address
                const idx = std.fmt.parseInt(usize, name, 10) catch {
                    _ = closesocket(s);
                    return error.NoDevice;
                };
                const host = resolveHost() orelse {
                    _ = closesocket(s);
                    return error.NoDevice;
                };
                var i: usize = 0;
                while (host.h_addr_list[i]) |addr_ptr| : (i += 1) {
                    if (i == idx) break :blk @as(*align(1) const u32, @ptrCast(addr_ptr)).*;
                }
                _ = closesocket(s);
                return error.NoDevice;
            } else {
                const host = resolveHost() orelse {
                    _ = closesocket(s);
                    return error.NoDevice;
                };
                const addr_ptr = host.h_addr_list[0] orelse {
                    _ = closesocket(s);
                    return error.NoDevice;
                };
                break :blk @as(*align(1) const u32, @ptrCast(addr_ptr)).*;
            }
        };

        var bind_addr: sockaddr_in = .{ .addr = ip };
        if (bind(s, &bind_addr, @sizeOf(sockaddr_in)) != 0) {
            _ = closesocket(s);
            return error.OpenFailed;
        }

        var rcvall: u32 = RCVALL_ON;
        var bytes_ret: u32 = 0;
        if (WSAIoctl(s, SIO_RCVALL, &rcvall, @sizeOf(u32), null, 0, &bytes_ret, null, null) != 0) {
            _ = closesocket(s);
            return error.PermissionDenied;
        }

        var mode: u32 = 1;
        _ = ioctlsocket(s, FIONBIO, &mode);

        return s;
    }

    fn readPacket(s: SOCKET, buf: []u8) CaptureError![]const u8 {
        if (buf.len < 34) return error.ReadFailed;

        const n = recv(s, @ptrCast(buf.ptr + 14), @intCast(buf.len - 14), 0);
        if (n <= 0) return error.ReadFailed;

        @memset(buf[0..12], 0);
        const version = buf[14] >> 4;
        if (version == 4) {
            buf[12] = 0x08;
            buf[13] = 0x00;
        } else if (version == 6) {
            buf[12] = 0x86;
            buf[13] = 0xDD;
        } else {
            return error.ReadFailed;
        }

        return buf[0 .. 14 + @as(usize, @intCast(n))];
    }

    fn closeDevice(s: SOCKET) void {
        _ = closesocket(s);
        _ = WSACleanup();
    }

    fn listIfaces(out: []IfName) usize {
        if (!initWsa()) return 0;
        defer _ = WSACleanup();
        const host = resolveHost() orelse return 0;

        var count: usize = 0;
        var i: usize = 0;
        while (count < out.len) : (i += 1) {
            const addr_ptr = host.h_addr_list[i] orelse break;
            const ip: u32 = @as(*align(1) const u32, @ptrCast(addr_ptr)).*;
            const a: u8 = @truncate(ip);
            const b: u8 = @truncate(ip >> 8);
            const c: u8 = @truncate(ip >> 16);
            const d: u8 = @truncate(ip >> 24);
            var ifn: IfName = .{};
            const s = std.fmt.bufPrint(&ifn.buf, "{d}.{d}.{d}.{d}", .{ a, b, c, d }) catch continue;
            ifn.len = @intCast(s.len);
            out[count] = ifn;
            count += 1;
        }
        return count;
    }
} else struct {};

fn openWinOn(iface: ?[]const u8) CaptureError!CaptureHandle {
    return win.openDeviceOn(iface);
}

fn readWin(handle: CaptureHandle, buf: []u8) CaptureError![]const u8 {
    return win.readPacket(handle, buf);
}

fn closeWin(handle: CaptureHandle) void {
    win.closeDevice(handle);
}

fn listWinIfaces(out: []IfName) usize {
    return win.listIfaces(out);
}
