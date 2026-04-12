// Cross-platform packet capture.
//
// Linux: AF_PACKET raw socket (captures all interfaces).
// macOS: BPF device (/dev/bpfN, bound to en0 by default).
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

/// Open a capture device on the current platform.
pub fn open() CaptureError!CaptureHandle {
    switch (builtin.os.tag) {
        .linux => return openLinux(),
        .macos => return openBpf(),
        .windows => return openWin(),
        else => comptime unreachable,
    }
}

/// Read one Ethernet frame into buf and return the valid slice.
/// On Linux/macOS: blocks until a packet arrives.
/// On Windows: non-blocking, returns ReadFailed when no data.
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

// ---------------------------------------------------------------------------
// Linux: AF_PACKET raw socket
// ---------------------------------------------------------------------------

const linux = if (builtin.os.tag == .linux) struct {
    const AF_PACKET: u32 = 17;
    const SOCK_RAW: u32 = 3;
    const ETH_P_ALL: u16 = 0x0003;

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

    fn read(fd: std.posix.fd_t, buf: []u8) CaptureError![]const u8 {
        const n = std.posix.read(fd, buf) catch return error.ReadFailed;
        if (n < 14) return error.ReadFailed;
        return buf[0..n];
    }
} else struct {};

fn openLinux() CaptureError!CaptureHandle {
    return linux.openSocket();
}

fn readLinux(handle: CaptureHandle, buf: []u8) CaptureError![]const u8 {
    return linux.read(handle, buf);
}

// ---------------------------------------------------------------------------
// macOS: BPF (Berkeley Packet Filter)
// ---------------------------------------------------------------------------

const bpf = if (builtin.os.tag == .macos) struct {
    const BIOCSBLEN: c_ulong = 0xc0044266;
    const BIOCSETIF: c_ulong = 0x8020426c;
    const BIOCIMMEDIATE: c_ulong = 0x80044270;
    const BIOCPROMISC: c_ulong = 0x20004269;

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

    fn openDevice() CaptureError!std.posix.fd_t {
        var path_buf: [16]u8 = undefined;
        var i: u32 = 0;
        while (i < 256) : (i += 1) {
            const path = std.fmt.bufPrint(&path_buf, "/dev/bpf{d}", .{i}) catch continue;
            if (path.len < path_buf.len) path_buf[path.len] = 0;
            const fd = std.posix.open(
                path_buf[0..path.len :0],
                .{ .ACCMODE = .RDONLY },
                .{},
            ) catch |err| switch (err) {
                error.DeviceBusy => continue,
                error.AccessDenied => return error.PermissionDenied,
                else => continue,
            };
            return fd;
        }
        return error.NoDevice;
    }

    fn configure(fd: std.posix.fd_t) CaptureError!void {
        var buf_len: u32 = BPF_BUF_SIZE;
        _ = ioctl(fd, BIOCSBLEN, @intFromPtr(&buf_len)) catch return error.OpenFailed;

        var ifr: Ifreq = std.mem.zeroes(Ifreq);
        const iface = "en0";
        @memcpy(ifr.ifr_name[0..iface.len], iface);
        _ = ioctl(fd, BIOCSETIF, @intFromPtr(&ifr)) catch return error.OpenFailed;

        var imm: u32 = 1;
        _ = ioctl(fd, BIOCIMMEDIATE, @intFromPtr(&imm)) catch return error.OpenFailed;

        _ = ioctl(fd, BIOCPROMISC, 0) catch {};
    }

    fn ioctl(fd: std.posix.fd_t, request: c_ulong, arg: usize) !usize {
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
} else struct {};

fn openBpf() CaptureError!CaptureHandle {
    const fd = try bpf.openDevice();
    bpf.configure(fd) catch |err| {
        std.posix.close(fd);
        return err;
    };
    return fd;
}

fn readBpf(handle: CaptureHandle, buf: []u8) CaptureError![]const u8 {
    return bpf.readPacket(handle, buf);
}

// ---------------------------------------------------------------------------
// Windows: raw socket with SIO_RCVALL (zero dependencies)
// ---------------------------------------------------------------------------
//
// Captures all IP traffic on the primary network interface using a raw
// socket in non-blocking mode. Packets arrive without Ethernet headers,
// so readOne prepends a synthetic 14-byte header to keep the parser
// uniform across platforms. ARP is not visible through this method.

const win = if (builtin.os.tag == .windows) struct {
    const SOCKET = usize;
    const INVALID_SOCKET: SOCKET = ~@as(SOCKET, 0);
    const SIO_RCVALL: u32 = 0x98000001;
    const RCVALL_ON: u32 = 1;
    const FIONBIO: c_long = @bitCast(@as(u32, 0x8004667E));

    const WSADATA = extern struct { data: [512]u8 };

    const sockaddr_in = extern struct {
        family: u16 = 2, // AF_INET
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
    extern "ws2_32" fn recv(s: SOCKET, buf: [*]u8, len: c_int, flags: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn closesocket(s: SOCKET) callconv(.winapi) c_int;
    extern "ws2_32" fn ioctlsocket(s: SOCKET, cmd: c_long, argp: *u32) callconv(.winapi) c_int;
    extern "ws2_32" fn gethostname(name: [*]u8, len: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn gethostbyname(name: [*:0]const u8) callconv(.winapi) ?*Hostent;

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

    fn openDevice() CaptureError!SOCKET {
        var wsa: WSADATA = undefined;
        if (WSAStartup(0x0202, &wsa) != 0) return error.OpenFailed;

        // SOCK_RAW(3) + IPPROTO_IP(0)
        const s = socket(2, 3, 0);
        if (s == INVALID_SOCKET) return error.PermissionDenied;

        // Resolve local IP for binding
        var hostname: [256]u8 = .{0} ** 256;
        if (gethostname(&hostname, 256) != 0) {
            _ = closesocket(s);
            return error.NoDevice;
        }
        const host = gethostbyname(@ptrCast(&hostname)) orelse {
            _ = closesocket(s);
            return error.NoDevice;
        };
        const addr_ptr = host.h_addr_list[0] orelse {
            _ = closesocket(s);
            return error.NoDevice;
        };
        const ip: u32 = @as(*align(1) const u32, @ptrCast(addr_ptr)).*;

        var bind_addr: sockaddr_in = .{ .addr = ip };
        if (bind(s, &bind_addr, @sizeOf(sockaddr_in)) != 0) {
            _ = closesocket(s);
            return error.OpenFailed;
        }

        // Enable promiscuous receive-all mode
        var rcvall: u32 = RCVALL_ON;
        var bytes_ret: u32 = 0;
        if (WSAIoctl(s, SIO_RCVALL, &rcvall, @sizeOf(u32), null, 0, &bytes_ret, null, null) != 0) {
            _ = closesocket(s);
            return error.PermissionDenied;
        }

        // Non-blocking so inline async_task returns immediately when idle
        var mode: u32 = 1;
        _ = ioctlsocket(s, FIONBIO, &mode);

        return s;
    }

    fn readPacket(s: SOCKET, buf: []u8) CaptureError![]const u8 {
        if (buf.len < 34) return error.ReadFailed; // 14 eth + 20 ip min

        // Receive raw IP into buf[14..], leaving room for Ethernet header
        const n = recv(s, @ptrCast(buf.ptr + 14), @intCast(buf.len - 14), 0);
        if (n <= 0) return error.ReadFailed;

        // Prepend synthetic Ethernet header (zeroed MACs + correct EtherType)
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
} else struct {};

fn openWin() CaptureError!CaptureHandle {
    return win.openDevice();
}

fn readWin(handle: CaptureHandle, buf: []u8) CaptureError![]const u8 {
    return win.readPacket(handle, buf);
}

fn closeWin(handle: CaptureHandle) void {
    win.closeDevice(handle);
}
