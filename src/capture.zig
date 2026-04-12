// Cross-platform packet capture.
//
// Linux: AF_PACKET raw socket (captures all interfaces).
// macOS: BPF device (/dev/bpfN, bound to en0 by default).
// Windows: Npcap wpcap.dll (first available device).

const std = @import("std");
const builtin = @import("builtin");

pub const CaptureHandle = switch (builtin.os.tag) {
    .linux => std.posix.fd_t,
    .macos => std.posix.fd_t,
    .windows => *anyopaque,
    else => @compileError("unsupported OS for packet capture"),
};

pub const CaptureError = error{
    PermissionDenied,
    NoDevice,
    OpenFailed,
    ReadFailed,
    NpcapNotFound,
};

/// Open a capture device on the current platform.
pub fn open() CaptureError!CaptureHandle {
    switch (builtin.os.tag) {
        .linux => return openLinux(),
        .macos => return openBpf(),
        .windows => return openNpcap(),
        else => comptime unreachable,
    }
}

/// Read one Ethernet frame. Returns the slice of valid data within buf.
/// Blocks until a packet is available.
pub fn readOne(handle: CaptureHandle, buf: []u8) CaptureError![]const u8 {
    switch (builtin.os.tag) {
        .linux => return readLinux(handle, buf),
        .macos => return readBpf(handle, buf),
        .windows => return readNpcap(handle, buf),
        else => comptime unreachable,
    }
}

/// Close the capture device.
pub fn close(handle: CaptureHandle) void {
    switch (builtin.os.tag) {
        .linux, .macos => std.posix.close(handle),
        .windows => closeNpcap(handle),
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
        error.NpcapNotFound => "Npcap not found. Install from https://npcap.com",
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
    // BPF ioctl constants (BSD _IOW/_IOR encoding)
    const BIOCSBLEN: c_ulong = 0xc0044266;
    const BIOCSETIF: c_ulong = 0x8020426c;
    const BIOCIMMEDIATE: c_ulong = 0x80044270;
    const BIOCPROMISC: c_ulong = 0x20004269;
    const BIOCGBLEN: c_ulong = 0x40044266;

    const BPF_BUF_SIZE: u32 = 65536;

    const BpfHeader = extern struct {
        tv_sec: i32,
        tv_usec: i32,
        bh_caplen: u32,
        bh_datalen: u32,
        bh_hdrlen: u16,
    };

    // Module-level buffer for BPF multi-packet reads
    var read_buf: [BPF_BUF_SIZE]u8 = undefined;
    var read_len: usize = 0;
    var read_pos: usize = 0;

    const IfreqName = [16]u8;
    const Ifreq = extern struct {
        ifr_name: IfreqName,
        ifr_data: [16]u8,
    };

    fn openDevice() CaptureError!std.posix.fd_t {
        var path_buf: [16]u8 = undefined;
        var i: u32 = 0;
        while (i < 256) : (i += 1) {
            const path = std.fmt.bufPrint(&path_buf, "/dev/bpf{d}", .{i}) catch continue;
            // Null-terminate for the syscall
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
        // Set buffer length
        var buf_len: u32 = BPF_BUF_SIZE;
        _ = ioctl(fd, BIOCSBLEN, @intFromPtr(&buf_len)) catch return error.OpenFailed;

        // Bind to en0
        var ifr: Ifreq = std.mem.zeroes(Ifreq);
        const iface = "en0";
        @memcpy(ifr.ifr_name[0..iface.len], iface);
        _ = ioctl(fd, BIOCSETIF, @intFromPtr(&ifr)) catch return error.OpenFailed;

        // Immediate mode (return packets as they arrive)
        var imm: u32 = 1;
        _ = ioctl(fd, BIOCIMMEDIATE, @intFromPtr(&imm)) catch return error.OpenFailed;

        // Promiscuous mode
        _ = ioctl(fd, BIOCPROMISC, 0) catch {};
    }

    fn ioctl(fd: std.posix.fd_t, request: c_ulong, arg: usize) !usize {
        const rc = std.c.ioctl(fd, request, arg);
        if (rc < 0) return error.IoctlFailed;
        return @intCast(rc);
    }

    fn readPacket(fd: std.posix.fd_t, out: []u8) CaptureError![]const u8 {
        // Try to return next packet from existing buffer
        if (read_pos < read_len) {
            if (extractPacket(out)) |frame| return frame;
        }

        // Fresh read from BPF
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

        // Advance to next packet (4-byte aligned)
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
// Windows: Npcap (wpcap.dll)
// ---------------------------------------------------------------------------

const npcap = if (builtin.os.tag == .windows) struct {
    const PcapPktHdr = extern struct {
        tv_sec: c_long,
        tv_usec: c_long,
        caplen: u32,
        len: u32,
    };

    const PcapIf = extern struct {
        next: ?*PcapIf,
        name: [*:0]const u8,
        description: ?[*:0]const u8,
        addresses: ?*anyopaque,
        flags: u32,
    };

    extern "wpcap" fn pcap_open_live(
        device: [*:0]const u8,
        snaplen: c_int,
        promisc: c_int,
        to_ms: c_int,
        errbuf: [*]u8,
    ) callconv(.c) ?*anyopaque;

    extern "wpcap" fn pcap_next_ex(
        p: *anyopaque,
        header: *?*const PcapPktHdr,
        data: *?[*]const u8,
    ) callconv(.c) c_int;

    extern "wpcap" fn pcap_close(p: *anyopaque) callconv(.c) void;
    extern "wpcap" fn pcap_findalldevs(alldevsp: *?*PcapIf, errbuf: [*]u8) callconv(.c) c_int;
    extern "wpcap" fn pcap_freealldevs(alldevs: *PcapIf) callconv(.c) void;

    fn openDevice() CaptureError!*anyopaque {
        var errbuf: [256]u8 = .{0} ** 256;

        // Find first available device
        var alldevs: ?*PcapIf = null;
        if (pcap_findalldevs(&alldevs, &errbuf) != 0 or alldevs == null) {
            return error.NoDevice;
        }
        const dev_name = alldevs.?.name;
        defer pcap_freealldevs(alldevs.?);

        const handle = pcap_open_live(dev_name, 65536, 1, 1, &errbuf) orelse {
            return error.OpenFailed;
        };
        return handle;
    }

    fn readPacket(handle: *anyopaque, buf: []u8) CaptureError![]const u8 {
        var header: ?*const PcapPktHdr = null;
        var data: ?[*]const u8 = null;

        const rc = pcap_next_ex(handle, &header, &data);
        if (rc != 1) return error.ReadFailed;

        const hdr = header orelse return error.ReadFailed;
        const pkt_data = data orelse return error.ReadFailed;
        const caplen: usize = hdr.caplen;
        const copy_len = @min(caplen, buf.len);
        @memcpy(buf[0..copy_len], pkt_data[0..copy_len]);

        return buf[0..copy_len];
    }
} else struct {};

fn openNpcap() CaptureError!CaptureHandle {
    return npcap.openDevice();
}

fn readNpcap(handle: CaptureHandle, buf: []u8) CaptureError![]const u8 {
    return npcap.readPacket(handle, buf);
}

fn closeNpcap(handle: CaptureHandle) void {
    npcap.pcap_close(handle);
}
