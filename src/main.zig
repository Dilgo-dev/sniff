// sniff - terminal packet sniffer.
//
// Captures network traffic via Linux raw sockets (AF_PACKET) and
// displays it in a scrollable TUI powered by glym.

const std = @import("std");
const glym = @import("glym");
const packet = @import("packet.zig");

const Style = glym.style.Style;
const Rgb = glym.style.Rgb;

// -- Capture state (module-level for async_task compatibility) --

var capture_fd: std.posix.fd_t = -1;

fn captureOne(_: std.mem.Allocator) anyerror!?App {
    if (capture_fd < 0) return null;
    var buf: [65536]u8 = undefined;
    const n = std.posix.read(capture_fd, &buf) catch return null;
    if (n < 14) return null;
    var info = packet.parse(buf[0..n]) orelse return null;
    info.timestamp_ms = std.time.milliTimestamp();
    return .{ .captured = info };
}

// -- MVU types --

const App = union(enum) {
    captured: packet.PacketInfo,
};

const P = glym.Program(Model, App);

const Model = struct {
    packets: std.ArrayList(packet.PacketInfo) = .{},
    selected: usize = 0,
    scroll: usize = 0,
    paused: bool = false,
    started: bool = false,
    rows: u16 = 24,
    cols: u16 = 80,
    start_time: i64 = 0,
    filter_proto: ?packet.Protocol = null,
};

const max_packets = 50000;

// -- MVU functions --

fn init(_: std.mem.Allocator) anyerror!Model {
    return .{ .start_time = std.time.milliTimestamp() };
}

fn deinit(model: *Model, allocator: std.mem.Allocator) void {
    model.packets.deinit(allocator);
}

fn update(model: *Model, m: P.Msg) P.Cmd {
    switch (m) {
        .resize => |sz| {
            model.rows = sz.rows;
            model.cols = sz.cols;
        },
        .key => |k| {
            const c = handleKey(model, k);
            if (!model.started) {
                model.started = true;
                return .{ .async_task = captureOne };
            }
            return c;
        },
        .app => |a| switch (a) {
            .captured => |pkt| {
                if (!model.paused) {
                    if (model.packets.items.len >= max_packets) {
                        const drop = max_packets / 10;
                        const remaining = model.packets.items.len - drop;
                        std.mem.copyForwards(
                            packet.PacketInfo,
                            model.packets.items[0..remaining],
                            model.packets.items[drop..],
                        );
                        model.packets.shrinkRetainingCapacity(remaining);
                        if (model.selected >= drop) {
                            model.selected -= drop;
                        } else {
                            model.selected = 0;
                        }
                        if (model.scroll >= drop) {
                            model.scroll -= drop;
                        } else {
                            model.scroll = 0;
                        }
                    }
                    model.packets.append(std.heap.page_allocator, pkt) catch {};
                }
                return .{ .async_task = captureOne };
            },
        },
        else => {},
    }

    if (!model.started) {
        model.started = true;
        return .{ .async_task = captureOne };
    }
    return .none;
}

fn handleKey(model: *Model, k: glym.input.Key) P.Cmd {
    switch (k.code) {
        .char => |c| {
            if (c == 'q' or (c == 'c' and k.modifiers.ctrl)) return .quit;
            if (c == 'p') model.paused = !model.paused;
            if (c == 'g') {
                model.selected = 0;
                model.scroll = 0;
            }
            if (c == 'G') {
                const count = visibleCount(model);
                if (count > 0) {
                    model.selected = count - 1;
                    adjustScroll(model);
                }
            }
            if (c == 'f') cycleFilter(model);
        },
        .arrow_up => {
            if (model.selected > 0) model.selected -= 1;
            adjustScroll(model);
        },
        .arrow_down => {
            const count = visibleCount(model);
            if (count > 0 and model.selected < count - 1) {
                model.selected += 1;
                adjustScroll(model);
            }
        },
        .page_up => {
            const h = listHeight(model.rows);
            if (model.selected > h) {
                model.selected -= h;
            } else {
                model.selected = 0;
            }
            adjustScroll(model);
        },
        .page_down => {
            const h = listHeight(model.rows);
            const count = visibleCount(model);
            if (count > 0) {
                model.selected = @min(model.selected + h, count - 1);
                adjustScroll(model);
            }
        },
        else => {},
    }
    return .none;
}

fn cycleFilter(model: *Model) void {
    model.filter_proto = if (model.filter_proto) |p| switch (p) {
        .tcp => .udp,
        .udp => .icmp,
        .icmp => .arp,
        else => null,
    } else .tcp;
    model.selected = 0;
    model.scroll = 0;
}

fn visibleCount(model: *const Model) usize {
    if (model.filter_proto == null) return model.packets.items.len;
    var n: usize = 0;
    for (model.packets.items) |p| {
        if (p.protocol == model.filter_proto.?) n += 1;
    }
    return n;
}

fn getVisible(model: *const Model, idx: usize) ?packet.PacketInfo {
    if (model.filter_proto == null) {
        return if (idx < model.packets.items.len) model.packets.items[idx] else null;
    }
    var n: usize = 0;
    for (model.packets.items) |p| {
        if (p.protocol == model.filter_proto.?) {
            if (n == idx) return p;
            n += 1;
        }
    }
    return null;
}

fn listHeight(rows: u16) usize {
    if (rows < 10) return 1;
    return @as(usize, rows) - 7;
}

fn adjustScroll(model: *Model) void {
    const h = listHeight(model.rows);
    if (model.selected < model.scroll) {
        model.scroll = model.selected;
    } else if (model.selected >= model.scroll + h) {
        model.scroll = model.selected - h + 1;
    }
}

// -- View --

const surface0: Rgb = .{ .r = 49, .g = 50, .b = 68 };
const surface1: Rgb = .{ .r = 69, .g = 71, .b = 90 };
const text_col: Rgb = .{ .r = 205, .g = 214, .b = 244 };
const subtext0: Rgb = .{ .r = 166, .g = 173, .b = 200 };
const overlay0: Rgb = .{ .r = 108, .g = 112, .b = 134 };
const c_green: Rgb = .{ .r = 166, .g = 227, .b = 161 };
const c_blue: Rgb = .{ .r = 137, .g = 180, .b = 250 };
const c_yellow: Rgb = .{ .r = 249, .g = 226, .b = 175 };
const c_mauve: Rgb = .{ .r = 203, .g = 166, .b = 247 };
const c_peach: Rgb = .{ .r = 250, .g = 179, .b = 135 };
const c_red: Rgb = .{ .r = 243, .g = 139, .b = 168 };

const title_style: Style = .{ .bg = .{ .rgb = surface0 }, .fg = .{ .rgb = text_col }, .bold = true };
const header_style: Style = .{ .fg = .{ .rgb = subtext0 }, .bold = true };
const sep_style: Style = .{ .fg = .{ .rgb = overlay0 } };
const normal_style: Style = .{ .fg = .{ .rgb = text_col } };
const selected_style: Style = .{ .bg = .{ .rgb = surface1 }, .fg = .{ .rgb = text_col } };
const help_style: Style = .{ .bg = .{ .rgb = surface0 }, .fg = .{ .rgb = subtext0 } };
const help_key_style: Style = .{ .bg = .{ .rgb = surface0 }, .fg = .{ .rgb = c_mauve }, .bold = true };
const detail_label_style: Style = .{ .fg = .{ .rgb = subtext0 } };
const detail_value_style: Style = .{ .fg = .{ .rgb = text_col }, .bold = true };

fn protoStyle(proto: packet.Protocol) Style {
    const fg: Rgb = switch (proto) {
        .tcp => c_green,
        .udp => c_blue,
        .icmp, .icmp6 => c_yellow,
        .arp => c_mauve,
        .other => subtext0,
    };
    return .{ .fg = .{ .rgb = fg } };
}

fn view(model: *Model, r: *P.Renderer) void {
    const rows = r.rows;
    const cols = r.cols;
    if (rows < 10 or cols < 40) {
        r.writeStyledText(0, 0, "Terminal too small", .{ .fg = .{ .rgb = c_red } });
        return;
    }

    // Title bar
    r.fillRect(0, 0, 1, cols, .{ .char = ' ', .style = title_style });
    r.writeStyledText(0, 1, "sniff", title_style);
    {
        var buf: [64]u8 = undefined;
        const s = std.fmt.bufPrint(&buf, " {d} packets", .{model.packets.items.len}) catch "";
        r.writeStyledText(0, 7, s, title_style);
    }
    if (model.paused) {
        r.writeStyledText(0, cols -| 10, " PAUSED ", .{ .bg = .{ .rgb = surface0 }, .fg = .{ .rgb = c_red }, .bold = true });
    }
    if (model.filter_proto) |fp| {
        var fbuf: [16]u8 = undefined;
        const fs = std.fmt.bufPrint(&fbuf, "[{s}]", .{fp.name()}) catch "";
        r.writeStyledText(0, cols / 2, fs, .{ .bg = .{ .rgb = surface0 }, .fg = .{ .rgb = c_peach }, .bold = true });
    }

    // Column headers
    writeColumns(r, 1, cols, "#", "Time", "Source", "Destination", "Proto", "Len", header_style);

    // Separator
    drawHLine(r, 2, cols);

    // Packet list
    const lh = listHeight(rows);
    var i: usize = 0;
    while (i < lh) : (i += 1) {
        const pkt_idx = model.scroll + i;
        const row: u16 = @intCast(3 + i);
        const is_selected = pkt_idx == model.selected;

        if (getVisible(model, pkt_idx)) |pkt| {
            const row_style = if (is_selected) selected_style else normal_style;
            if (is_selected) {
                r.fillRect(row, 0, 1, cols, .{ .char = ' ', .style = selected_style });
            }

            var num_buf: [8]u8 = undefined;
            const num_s = std.fmt.bufPrint(&num_buf, "{d}", .{pkt_idx + 1}) catch "";

            var time_buf: [12]u8 = undefined;
            const time_s = fmtTime(pkt.timestamp_ms, &time_buf);

            var len_buf: [8]u8 = undefined;
            const len_s = std.fmt.bufPrint(&len_buf, "{d}", .{pkt.length}) catch "";

            writeColumns(r, row, cols, num_s, time_s, pkt.srcAddr(), pkt.dstAddr(), pkt.protocol.name(), len_s, row_style);

            // Protocol column with color
            const pcol = protoCol(cols);
            const ps = protoStyle(pkt.protocol);
            const pstyle: Style = if (is_selected) .{ .bg = .{ .rgb = surface1 }, .fg = ps.fg, .bold = true } else .{ .fg = ps.fg };
            r.writeStyledText(row, pcol, pkt.protocol.name(), pstyle);
        } else {
            break;
        }
    }

    // Separator before detail
    const sep_row: u16 = @intCast(@as(usize, rows) -| 4);
    drawHLine(r, sep_row, cols);

    // Detail pane
    if (getVisible(model, model.selected)) |pkt| {
        const d1: u16 = sep_row + 1;
        const d2: u16 = sep_row + 2;

        r.writeStyledText(d1, 1, "Src: ", detail_label_style);
        r.writeStyledText(d1, 6, pkt.srcAddr(), detail_value_style);
        if (pkt.src_port > 0) {
            var pbuf: [8]u8 = undefined;
            const ps = std.fmt.bufPrint(&pbuf, ":{d}", .{pkt.src_port}) catch "";
            r.writeStyledText(d1, @intCast(6 + pkt.srcAddr().len), ps, detail_value_style);
        }

        const arrow_col: u16 = @intCast(@min(@as(usize, 30), @as(usize, cols) -| 1));
        r.writeStyledText(d1, arrow_col, " -> ", detail_label_style);
        const dst_col: u16 = arrow_col + 4;
        r.writeStyledText(d1, dst_col, "Dst: ", detail_label_style);
        r.writeStyledText(d1, dst_col + 5, pkt.dstAddr(), detail_value_style);
        if (pkt.dst_port > 0) {
            var pbuf2: [8]u8 = undefined;
            const ps2 = std.fmt.bufPrint(&pbuf2, ":{d}", .{pkt.dst_port}) catch "";
            r.writeStyledText(d1, @intCast(dst_col + 5 + pkt.dstAddr().len), ps2, detail_value_style);
        }

        r.writeStyledText(d2, 1, "Proto: ", detail_label_style);
        r.writeStyledText(d2, 8, pkt.protocol.name(), protoStyle(pkt.protocol));
        {
            var lbuf: [32]u8 = undefined;
            const ls = std.fmt.bufPrint(&lbuf, "  Len: {d}", .{pkt.length}) catch "";
            r.writeStyledText(d2, @intCast(8 + pkt.protocol.name().len), ls, detail_label_style);
        }
        if (pkt.ip_ttl > 0) {
            var tbuf: [16]u8 = undefined;
            const ts = std.fmt.bufPrint(&tbuf, "  TTL: {d}", .{pkt.ip_ttl}) catch "";
            r.writeStyledText(d2, 28, ts, detail_label_style);
        }
        if (pkt.protocol == .tcp and pkt.tcp_flags > 0) {
            var fbuf: [40]u8 = undefined;
            const flags = pkt.tcpFlagsStr(&fbuf);
            r.writeStyledText(d2, 42, "Flags: ", detail_label_style);
            r.writeStyledText(d2, 49, flags, .{ .fg = .{ .rgb = c_peach } });
        }
    }

    // Help bar
    const help_row: u16 = rows - 1;
    r.fillRect(help_row, 0, 1, cols, .{ .char = ' ', .style = help_style });
    var col: u16 = 1;
    col = writeHelpKey(r, help_row, col, "q", "quit");
    col = writeHelpKey(r, help_row, col, "p", "pause");
    col = writeHelpKey(r, help_row, col, "f", "filter");
    col = writeHelpKey(r, help_row, col, "g/G", "top/bottom");
    _ = writeHelpKey(r, help_row, col, "up/dn", "navigate");
}

fn writeHelpKey(r: *P.Renderer, row: u16, col: u16, key: []const u8, desc: []const u8) u16 {
    r.writeStyledText(row, col, key, help_key_style);
    const after_key: u16 = col + @as(u16, @intCast(key.len));
    r.writeStyledText(row, after_key, ":", help_style);
    r.writeStyledText(row, after_key + 1, desc, help_style);
    return after_key + @as(u16, @intCast(desc.len)) + 3;
}

fn protoCol(cols: u16) u16 {
    const num_w: u16 = 6;
    const time_w: u16 = 10;
    const aw: u16 = addrWidth(cols);
    return num_w + time_w + aw * 2;
}

fn addrWidth(cols: u16) u16 {
    if (cols >= 120) return 20;
    if (cols >= 80) return 16;
    return 12;
}

fn writeColumns(
    r: *P.Renderer,
    row: u16,
    cols: u16,
    num: []const u8,
    time_str: []const u8,
    src: []const u8,
    dst: []const u8,
    proto: []const u8,
    length: []const u8,
    sty: Style,
) void {
    const num_w: u16 = 6;
    const time_w: u16 = 10;
    const aw: u16 = addrWidth(cols);
    var c: u16 = 0;

    writeField(r, row, c, num_w, num, sty);
    c += num_w;
    writeField(r, row, c, time_w, time_str, sty);
    c += time_w;
    writeField(r, row, c, aw, src, sty);
    c += aw;
    writeField(r, row, c, aw, dst, sty);
    c += aw;
    writeField(r, row, c, 8, proto, sty);
    c += 8;
    writeField(r, row, c, 7, length, sty);
}

fn writeField(r: *P.Renderer, row: u16, col: u16, width: u16, text: []const u8, sty: Style) void {
    const max: usize = @min(text.len, @as(usize, width) -| 1);
    r.writeStyledText(row, col, text[0..max], sty);
}

fn drawHLine(r: *P.Renderer, row: u16, cols: u16) void {
    var c: u16 = 0;
    while (c < cols) : (c += 1) {
        r.applyCell(row, c, 0x2500, sep_style);
    }
}

fn fmtTime(timestamp_ms: i64, buf: *[12]u8) []const u8 {
    const secs: u64 = @intCast(@divFloor(timestamp_ms, 1000));
    const day_secs = secs % 86400;
    const hours = day_secs / 3600;
    const mins = (day_secs % 3600) / 60;
    const s = day_secs % 60;
    return std.fmt.bufPrint(buf, "{d:0>2}:{d:0>2}:{d:0>2}", .{
        @as(u32, @intCast(hours)),
        @as(u32, @intCast(mins)),
        @as(u32, @intCast(s)),
    }) catch "??:??:??";
}

// -- Entry point --

pub fn main() !void {
    const rc = std.os.linux.socket(17, 3, std.mem.nativeToBig(u16, 0x0003));
    const signed: isize = @bitCast(rc);
    if (signed < 0) {
        const err_str = switch (@as(std.posix.E, @enumFromInt(-signed))) {
            .PERM, .ACCES => "Permission denied. Run with sudo or set CAP_NET_RAW.",
            else => "Failed to open raw socket.",
        };
        std.debug.print("sniff: {s}\n", .{err_str});
        std.process.exit(1);
    }
    capture_fd = @intCast(rc);
    defer std.posix.close(capture_fd);

    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();

    const program: P = .{
        .allocator = gpa.allocator(),
        .init_fn = init,
        .update_fn = update,
        .view_fn = view,
        .deinit_fn = deinit,
    };
    try program.runSafely();
}
