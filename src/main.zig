// sniff - terminal packet sniffer.
//
// Captures network traffic via platform-specific raw capture and
// displays it in a scrollable TUI powered by glym.

const std = @import("std");
const builtin = @import("builtin");
const glym = @import("glym");
const packet = @import("packet.zig");
const capture = @import("capture.zig");
const filter_mod = @import("filter.zig");
const pcap = @import("pcap.zig");

const Style = glym.style.Style;
const Rgb = glym.style.Rgb;

// Module-level so async_task capture functions can access it.
var capture_handle: ?capture.CaptureHandle = null;

fn captureOne(_: std.mem.Allocator) anyerror!?App {
    const handle = capture_handle orelse return null;
    var buf: [65536]u8 = undefined;
    const frame = capture.readOne(handle, &buf) catch return null;
    if (frame.len < 14) return null;
    var info = packet.parse(frame) orelse return null;
    info.timestamp_ms = std.time.milliTimestamp();
    const snap = @min(frame.len, packet.snap_len);
    @memcpy(info.raw[0..snap], frame[0..snap]);
    info.raw_len = @intCast(snap);
    return .{ .captured = info };
}

const App = union(enum) {
    captured: packet.PacketInfo,
};

const P = glym.Program(Model, App);

const InputMode = enum { none, filter, search, save };

const Model = struct {
    packets: std.ArrayList(packet.PacketInfo) = .{},
    selected: usize = 0,
    scroll: usize = 0,
    paused: bool = false,
    follow: bool = true,
    started: bool = false,
    rows: u16 = 24,
    cols: u16 = 80,
    start_time: i64 = 0,
    filter: filter_mod.Filter = .{},
    filter_buf: [128]u8 = .{0} ** 128,
    filter_len: u8 = 0,
    search_buf: [128]u8 = .{0} ** 128,
    search_len: u8 = 0,
    search_active: bool = false,
    hex_view: bool = false,
    hex_scroll: usize = 0,
    stats_view: bool = false,
    stream_view: bool = false,
    stream_scroll: usize = 0,
    stream_src: [46]u8 = .{0} ** 46,
    stream_src_len: u8 = 0,
    stream_dst: [46]u8 = .{0} ** 46,
    stream_dst_len: u8 = 0,
    stream_sport: u16 = 0,
    stream_dport: u16 = 0,
    input_mode: InputMode = .none,
    input_buf: [128]u8 = .{0} ** 128,
    input_len: u8 = 0,
    input_cursor: u8 = 0,
    input_error: bool = false,
    status_buf: [64]u8 = .{0} ** 64,
    status_len: u8 = 0,
    status_time: i64 = 0,
};

const max_packets = 50000;

fn init(_: std.mem.Allocator) anyerror!Model {
    return .{ .start_time = std.time.milliTimestamp() };
}

fn deinit(model: *Model, _: std.mem.Allocator) void {
    model.packets.deinit(std.heap.page_allocator);
}

fn update(model: *Model, m: P.Msg) P.Cmd {
    switch (m) {
        .resize => |sz| {
            model.rows = sz.rows;
            model.cols = sz.cols;
        },
        .key => |k| {
            if (model.input_mode != .none) {
                handleTextInput(model, k);
            } else {
                switch (handleKey(model, k)) {
                    .quit => return .quit,
                    else => {},
                }
            }
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
                    if (model.follow) {
                        const count = visibleCount(model);
                        if (count > 0) {
                            model.selected = count - 1;
                            adjustScroll(model);
                        }
                    }
                }
                return .{ .async_task = captureOne };
            },
        },
        else => {},
    }

    if (!model.started) model.started = true;
    if (model.started and !model.paused) return .{ .async_task = captureOne };
    return .none;
}

fn handleKey(model: *Model, k: glym.input.Key) P.Cmd {
    switch (k.code) {
        .char => |c| {
            if (c == 'q' or (c == 'c' and k.modifiers.ctrl)) return .quit;
            if (c == 'p') model.paused = !model.paused;
            if (c == 'g') {
                model.follow = false;
                model.selected = 0;
                model.scroll = 0;
            }
            if (c == 'G') {
                model.follow = true;
                const count = visibleCount(model);
                if (count > 0) {
                    model.selected = count - 1;
                    adjustScroll(model);
                }
            }
            if (c == 'f') openInput(model, .filter);
            if (c == '/') openInput(model, .search);
            if (c == 'w') openInput(model, .save);
            if (c == 's') {
                model.stats_view = !model.stats_view;
                model.hex_view = false;
                model.stream_view = false;
            }
            if (c == 'x') {
                model.hex_view = !model.hex_view;
                model.hex_scroll = 0;
                model.stats_view = false;
                model.stream_view = false;
            }
            if (c == 't') {
                if (model.stream_view) {
                    model.stream_view = false;
                } else if (getVisible(model, model.selected)) |pkt| {
                    if (pkt.protocol == .tcp) {
                        model.stream_view = true;
                        model.hex_view = false;
                        model.stats_view = false;
                        model.stream_scroll = 0;
                        model.stream_src = pkt.src_addr;
                        model.stream_src_len = pkt.src_addr_len;
                        model.stream_dst = pkt.dst_addr;
                        model.stream_dst_len = pkt.dst_addr_len;
                        model.stream_sport = pkt.src_port;
                        model.stream_dport = pkt.dst_port;
                    }
                }
            }
            if (c == 'n') searchNext(model, true);
            if (c == 'N') searchNext(model, false);
            if (c == 'F') model.follow = !model.follow;
        },
        .arrow_up => {
            if (model.hex_view or model.stream_view) {
                if (model.hex_view and model.hex_scroll > 0) model.hex_scroll -= 1;
                if (model.stream_view and model.stream_scroll > 0) model.stream_scroll -= 1;
            } else {
                model.follow = false;
                if (model.selected > 0) model.selected -= 1;
                adjustScroll(model);
            }
        },
        .arrow_down => {
            if (model.hex_view or model.stream_view) {
                if (model.hex_view) model.hex_scroll += 1;
                if (model.stream_view) model.stream_scroll += 1;
            } else {
                model.follow = false;
                const count = visibleCount(model);
                if (count > 0 and model.selected < count - 1) {
                    model.selected += 1;
                    adjustScroll(model);
                }
            }
        },
        .page_up => {
            if (model.hex_view or model.stream_view) {
                const h = listHeight(model.rows);
                if (model.hex_view) {
                    if (model.hex_scroll > h) model.hex_scroll -= h else model.hex_scroll = 0;
                }
                if (model.stream_view) {
                    if (model.stream_scroll > h) model.stream_scroll -= h else model.stream_scroll = 0;
                }
            } else {
                model.follow = false;
                const h = listHeight(model.rows);
                if (model.selected > h) {
                    model.selected -= h;
                } else {
                    model.selected = 0;
                }
                adjustScroll(model);
            }
        },
        .page_down => {
            if (model.hex_view or model.stream_view) {
                const h = listHeight(model.rows);
                if (model.hex_view) model.hex_scroll += h;
                if (model.stream_view) model.stream_scroll += h;
            } else {
                model.follow = false;
                const h = listHeight(model.rows);
                const count = visibleCount(model);
                if (count > 0) {
                    model.selected = @min(model.selected + h, count - 1);
                    adjustScroll(model);
                }
            }
        },
        else => {},
    }
    return .none;
}

fn openInput(model: *Model, mode: InputMode) void {
    model.input_mode = mode;
    model.input_error = false;
    switch (mode) {
        .filter => {
            @memcpy(model.input_buf[0..model.filter_len], model.filter_buf[0..model.filter_len]);
            model.input_len = model.filter_len;
        },
        .search => {
            @memcpy(model.input_buf[0..model.search_len], model.search_buf[0..model.search_len]);
            model.input_len = model.search_len;
        },
        .save => {
            const default = "capture.pcap";
            @memcpy(model.input_buf[0..default.len], default);
            model.input_len = default.len;
        },
        .none => {},
    }
    model.input_cursor = model.input_len;
}

fn handleTextInput(model: *Model, k: glym.input.Key) void {
    switch (k.code) {
        .escape => {
            model.input_mode = .none;
            model.input_error = false;
        },
        .enter => {
            const mode = model.input_mode;
            model.input_mode = .none;
            switch (mode) {
                .filter => applyFilter(model),
                .search => applySearch(model),
                .save => applyExport(model),
                .none => {},
            }
        },
        .backspace => {
            if (model.input_cursor > 0) {
                model.input_cursor -= 1;
                var i: usize = model.input_cursor;
                while (i + 1 < model.input_len) : (i += 1) {
                    model.input_buf[i] = model.input_buf[i + 1];
                }
                model.input_len -= 1;
                model.input_error = false;
            }
        },
        .char => |c| {
            if (c > 0 and c < 128 and model.input_len < 127) {
                var i: usize = model.input_len;
                while (i > model.input_cursor) : (i -= 1) {
                    model.input_buf[i] = model.input_buf[i - 1];
                }
                model.input_buf[model.input_cursor] = @intCast(c);
                model.input_cursor += 1;
                model.input_len += 1;
                model.input_error = false;
            }
        },
        .arrow_left => {
            if (model.input_cursor > 0) model.input_cursor -= 1;
        },
        .arrow_right => {
            if (model.input_cursor < model.input_len) model.input_cursor += 1;
        },
        else => {},
    }
}

fn applyFilter(model: *Model) void {
    const expr = model.input_buf[0..model.input_len];
    @memcpy(model.filter_buf[0..model.input_len], expr);
    model.filter_len = model.input_len;
    if (expr.len == 0) {
        model.filter = .{};
        model.input_error = false;
    } else if (filter_mod.parse(expr)) |f| {
        model.filter = f;
        model.input_error = false;
    } else {
        model.input_error = true;
    }
    model.selected = 0;
    model.scroll = 0;
}

fn applyExport(model: *Model) void {
    const path = model.input_buf[0..model.input_len];
    if (path.len == 0) return;

    const filter_fn: ?*const fn (*const packet.PacketInfo) bool = if (model.filter.active)
        struct {
            fn matches(pkt: *const packet.PacketInfo) bool {
                return export_filter.matches(pkt);
            }
        }.matches
    else
        null;

    export_filter = model.filter;

    const count = pcap.exportPackets(path, model.packets.items, filter_fn) catch {
        setStatus(model, "Export failed!");
        return;
    };

    var sbuf: [64]u8 = undefined;
    const msg = std.fmt.bufPrint(&sbuf, "Exported {d} packets to {s}", .{ count, path }) catch "Exported";
    setStatus(model, msg);
}

var export_filter: filter_mod.Filter = .{};

fn setStatus(model: *Model, msg: []const u8) void {
    const len = @min(msg.len, model.status_buf.len);
    @memcpy(model.status_buf[0..len], msg[0..len]);
    model.status_len = @intCast(len);
    model.status_time = std.time.milliTimestamp();
}

fn applySearch(model: *Model) void {
    const term = model.input_buf[0..model.input_len];
    @memcpy(model.search_buf[0..model.input_len], term);
    model.search_len = model.input_len;
    model.search_active = model.input_len > 0;
    if (model.search_active) {
        searchNext(model, true);
    }
}

fn searchMatches(model: *const Model, pkt: *const packet.PacketInfo) bool {
    if (!model.search_active) return false;
    const term = model.search_buf[0..model.search_len];
    if (containsSubstring(pkt.srcAddr(), term)) return true;
    if (containsSubstring(pkt.dstAddr(), term)) return true;
    var pbuf: [8]u8 = undefined;
    if (pkt.src_port > 0) {
        const ps = std.fmt.bufPrint(&pbuf, "{d}", .{pkt.src_port}) catch "";
        if (containsSubstring(ps, term)) return true;
    }
    if (pkt.dst_port > 0) {
        const ps = std.fmt.bufPrint(&pbuf, "{d}", .{pkt.dst_port}) catch "";
        if (containsSubstring(ps, term)) return true;
    }
    if (containsSubstring(pkt.protocol.name(), term)) return true;
    if (pkt.dns_name_len > 0 and containsSubstring(pkt.dnsName(), term)) return true;
    if (pkt.http_info_len > 0 and containsSubstring(pkt.httpInfo(), term)) return true;
    return false;
}

fn containsSubstring(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or needle.len > haystack.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i..][0..needle.len], needle)) return true;
    }
    return false;
}

fn searchNext(model: *Model, forward: bool) void {
    if (!model.search_active) return;
    const count = visibleCount(model);
    if (count == 0) return;

    var i: usize = 0;
    while (i < count) : (i += 1) {
        const idx = if (forward)
            (model.selected + 1 + i) % count
        else
            (model.selected + count - 1 - i) % count;
        if (getVisible(model, idx)) |pkt| {
            if (searchMatches(model, &pkt)) {
                model.follow = false;
                model.selected = idx;
                adjustScroll(model);
                return;
            }
        }
    }
}

fn visibleCount(model: *const Model) usize {
    if (!model.filter.active) return model.packets.items.len;
    var n: usize = 0;
    for (model.packets.items) |*p| {
        if (model.filter.matches(p)) n += 1;
    }
    return n;
}

fn getVisible(model: *const Model, idx: usize) ?packet.PacketInfo {
    if (!model.filter.active) {
        return if (idx < model.packets.items.len) model.packets.items[idx] else null;
    }
    var n: usize = 0;
    for (model.packets.items) |*p| {
        if (model.filter.matches(p)) {
            if (n == idx) return p.*;
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
const search_bg: Rgb = .{ .r = 62, .g = 56, .b = 30 }; // dark warm tint for search matches

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

    r.fillRect(0, 0, 1, cols, .{ .char = ' ', .style = title_style });
    r.writeStyledText(0, 1, "sniff", title_style);
    {
        var buf: [80]u8 = undefined;
        const iface = activeIfaceSlice();
        const s = std.fmt.bufPrint(&buf, " [{s}] {d} packets", .{ iface, model.packets.items.len }) catch "";
        r.writeStyledText(0, 7, s, title_style);
    }
    // Status disappears after 3 seconds
    const now = std.time.milliTimestamp();
    if (model.status_len > 0 and now - model.status_time < 3000) {
        const smsg = model.status_buf[0..model.status_len];
        r.writeStyledText(0, cols -| @as(u16, @intCast(smsg.len + 2)), " ", .{ .bg = .{ .rgb = surface0 } });
        r.writeStyledText(0, cols -| @as(u16, @intCast(smsg.len + 1)), smsg, .{ .bg = .{ .rgb = surface0 }, .fg = .{ .rgb = c_green }, .bold = true });
        r.writeStyledText(0, cols -| 1, " ", .{ .bg = .{ .rgb = surface0 } });
    } else if (model.paused) {
        r.writeStyledText(0, cols -| 10, " PAUSED ", .{ .bg = .{ .rgb = surface0 }, .fg = .{ .rgb = c_red }, .bold = true });
    } else if (model.follow) {
        r.writeStyledText(0, cols -| 10, " FOLLOW ", .{ .bg = .{ .rgb = surface0 }, .fg = .{ .rgb = c_green }, .bold = true });
    }
    {
        var info_col: u16 = cols / 3;
        if (model.filter.active) {
            r.writeStyledText(0, info_col, "filter:", .{ .bg = .{ .rgb = surface0 }, .fg = .{ .rgb = overlay0 } });
            info_col += 7;
            const expr = model.filter_buf[0..model.filter_len];
            r.writeStyledText(0, info_col, expr, .{ .bg = .{ .rgb = surface0 }, .fg = .{ .rgb = c_peach }, .bold = true });
            info_col += @as(u16, @intCast(expr.len)) + 2;
        }
        if (model.search_active) {
            r.writeStyledText(0, info_col, "/", .{ .bg = .{ .rgb = surface0 }, .fg = .{ .rgb = overlay0 } });
            info_col += 1;
            const term = model.search_buf[0..model.search_len];
            r.writeStyledText(0, info_col, term, .{ .bg = .{ .rgb = surface0 }, .fg = .{ .rgb = c_yellow }, .bold = true });
        }
    }

    if (model.stream_view) {
        viewStream(model, r, rows, cols);
    } else if (model.stats_view) {
        viewStats(model, r, rows, cols);
    } else if (model.hex_view) {
        viewHexDump(model, r, rows, cols);
    } else {
        viewPacketList(model, r, rows, cols);
    }

    const help_row: u16 = rows - 1;
    r.fillRect(help_row, 0, 1, cols, .{ .char = ' ', .style = help_style });
    if (model.input_mode != .none) {
        const prompt: []const u8 = switch (model.input_mode) {
            .filter => "filter: ",
            .search => "search: ",
            .save => "export: ",
            .none => "",
        };
        const prompt_style: Style = if (model.input_error)
            .{ .bg = .{ .rgb = surface0 }, .fg = .{ .rgb = c_red }, .bold = true }
        else switch (model.input_mode) {
            .search => .{ .bg = .{ .rgb = surface0 }, .fg = .{ .rgb = c_yellow }, .bold = true },
            .save => .{ .bg = .{ .rgb = surface0 }, .fg = .{ .rgb = c_green }, .bold = true },
            else => .{ .bg = .{ .rgb = surface0 }, .fg = .{ .rgb = c_mauve }, .bold = true },
        };
        r.writeStyledText(help_row, 1, prompt, prompt_style);
        const plen: u16 = @intCast(prompt.len);
        const text = model.input_buf[0..model.input_len];
        r.writeStyledText(help_row, 1 + plen, text, .{ .bg = .{ .rgb = surface0 }, .fg = .{ .rgb = text_col } });
        const ccol: u16 = 1 + plen + @as(u16, model.input_cursor);
        const cch: u21 = if (model.input_cursor < model.input_len) model.input_buf[model.input_cursor] else ' ';
        r.applyCell(help_row, ccol, cch, .{ .bg = .{ .rgb = text_col }, .fg = .{ .rgb = surface0 } });
        r.writeStyledText(help_row, cols -| 22, "enter:apply esc:cancel", .{ .bg = .{ .rgb = surface0 }, .fg = .{ .rgb = overlay0 } });
    } else {
        var col: u16 = 1;
        col = writeHelpKey(r, help_row, col, "q", "quit");
        col = writeHelpKey(r, help_row, col, "p", "pause");
        col = writeHelpKey(r, help_row, col, "f", "filter");
        col = writeHelpKey(r, help_row, col, "/", "search");
        col = writeHelpKey(r, help_row, col, "n/N", "next/prev");
        col = writeHelpKey(r, help_row, col, "x", "hex");
        col = writeHelpKey(r, help_row, col, "t", "stream");
        col = writeHelpKey(r, help_row, col, "s", "stats");
        col = writeHelpKey(r, help_row, col, "w", "export");
        col = writeHelpKey(r, help_row, col, "F", "follow");
        _ = writeHelpKey(r, help_row, col, "up/dn", "navigate");
    }
}

fn viewPacketList(model: *Model, r: *P.Renderer, rows: u16, cols: u16) void {
    writeColumns(r, 1, cols, "#", "Time", "Source", "Destination", "Proto", "Len", header_style);
    drawHLine(r, 2, cols);

    const lh = listHeight(rows);
    var i: usize = 0;
    while (i < lh) : (i += 1) {
        const pkt_idx = model.scroll + i;
        const row: u16 = @intCast(3 + i);
        const is_selected = pkt_idx == model.selected;

        if (getVisible(model, pkt_idx)) |pkt| {
            const is_match = searchMatches(model, &pkt);
            const row_bg: Rgb = if (is_selected) surface1 else if (is_match) search_bg else surface0;
            const row_style: Style = if (is_selected or is_match)
                .{ .bg = .{ .rgb = row_bg }, .fg = .{ .rgb = text_col } }
            else
                normal_style;
            if (is_selected or is_match) {
                r.fillRect(row, 0, 1, cols, .{ .char = ' ', .style = .{ .bg = .{ .rgb = row_bg } } });
            }

            var num_buf: [8]u8 = undefined;
            const num_s = std.fmt.bufPrint(&num_buf, "{d}", .{pkt_idx + 1}) catch "";

            var time_buf: [12]u8 = undefined;
            const time_s = fmtTime(pkt.timestamp_ms, &time_buf);

            var len_buf: [8]u8 = undefined;
            const len_s = std.fmt.bufPrint(&len_buf, "{d}", .{pkt.length}) catch "";

            writeColumns(r, row, cols, num_s, time_s, pkt.srcAddr(), pkt.dstAddr(), pkt.protocol.name(), len_s, row_style);

            const pcol = protoCol(cols);
            const ps = protoStyle(pkt.protocol);
            const pstyle: Style = if (is_selected) .{ .bg = .{ .rgb = row_bg }, .fg = ps.fg, .bold = true } else if (is_match) .{ .bg = .{ .rgb = row_bg }, .fg = ps.fg } else .{ .fg = ps.fg };
            r.writeStyledText(row, pcol, pkt.protocol.name(), pstyle);
        } else {
            break;
        }
    }

    const sep_row: u16 = @intCast(@as(usize, rows) -| 4);
    drawHLine(r, sep_row, cols);

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
        if (pkt.dns_name_len > 0) {
            const label = if (pkt.dns_is_response) "DNS resp: " else "DNS: ";
            r.writeStyledText(d2, 42, label, detail_label_style);
            r.writeStyledText(d2, 42 + @as(u16, @intCast(label.len)), pkt.dnsName(), .{ .fg = .{ .rgb = c_yellow }, .bold = true });
        } else if (pkt.http_info_len > 0) {
            r.writeStyledText(d2, 42, pkt.httpInfo(), .{ .fg = .{ .rgb = c_peach }, .bold = true });
        }
    }
}

fn streamMatchesPkt(model: *const Model, pkt: *const packet.PacketInfo) bool {
    if (pkt.protocol != .tcp) return false;
    const sa = model.stream_src[0..model.stream_src_len];
    const da = model.stream_dst[0..model.stream_dst_len];
    const sp = model.stream_sport;
    const dp = model.stream_dport;
    // Match either direction
    const fwd = std.mem.eql(u8, pkt.srcAddr(), sa) and std.mem.eql(u8, pkt.dstAddr(), da) and pkt.src_port == sp and pkt.dst_port == dp;
    const rev = std.mem.eql(u8, pkt.srcAddr(), da) and std.mem.eql(u8, pkt.dstAddr(), sa) and pkt.src_port == dp and pkt.dst_port == sp;
    return fwd or rev;
}

fn extractTcpPayload(pkt: *const packet.PacketInfo) ?[]const u8 {
    const raw = pkt.raw[0..pkt.raw_len];
    if (raw.len < 14 + 20 + 20) return null;

    const ethertype = (@as(u16, raw[12]) << 8) | raw[13];
    const ip_hdr_len: usize = switch (ethertype) {
        0x0800 => @as(usize, raw[14] & 0x0F) * 4,
        0x86DD => 40,
        else => return null,
    };

    const tcp_start = 14 + ip_hdr_len;
    if (tcp_start + 20 > raw.len) return null;
    const tcp_hdr_len: usize = @as(usize, raw[tcp_start + 12] >> 4) * 4;
    const payload_start = tcp_start + tcp_hdr_len;
    if (payload_start >= raw.len) return null;
    return raw[payload_start..];
}

fn viewStream(model: *Model, r: *P.Renderer, rows: u16, cols: u16) void {
    const sa = model.stream_src[0..model.stream_src_len];
    const da = model.stream_dst[0..model.stream_dst_len];

    {
        var hbuf: [96]u8 = undefined;
        const hs = std.fmt.bufPrint(&hbuf, "TCP Stream: {s}:{d} <-> {s}:{d}", .{
            sa, model.stream_sport, da, model.stream_dport,
        }) catch "";
        r.writeStyledText(1, 1, hs, .{ .fg = .{ .rgb = text_col }, .bold = true });
    }
    drawHLine(r, 2, cols);

    // Collect output lines from stream packets
    const visible_h = @as(usize, rows) -| 4;

    // We render line by line: for each stream packet with payload,
    // show a direction arrow + payload as printable text (one line per packet).
    var line: usize = 0;
    var skipped: usize = 0;
    var total_lines: usize = 0;

    for (model.packets.items) |*pkt| {
        if (!streamMatchesPkt(model, pkt)) continue;
        const payload = extractTcpPayload(pkt) orelse continue;
        if (payload.len == 0) continue;

        // Count lines this payload produces (one per ~(cols-4) chars)
        const line_w = @as(usize, cols) -| 4;
        if (line_w == 0) continue;
        const pkt_lines = (payload.len + line_w - 1) / line_w;
        total_lines += pkt_lines;

        // Direction: is this from the "client" (stream_src) side?
        const is_client = std.mem.eql(u8, pkt.srcAddr(), sa) and pkt.src_port == model.stream_sport;
        const arrow: []const u8 = if (is_client) "> " else "< ";
        const arrow_style: Style = if (is_client) .{ .fg = .{ .rgb = c_green }, .bold = true } else .{ .fg = .{ .rgb = c_blue }, .bold = true };
        const text_style: Style = if (is_client) .{ .fg = .{ .rgb = c_green } } else .{ .fg = .{ .rgb = c_blue } };

        var off: usize = 0;
        while (off < payload.len) {
            const chunk_end = @min(off + line_w, payload.len);
            const chunk = payload[off..chunk_end];

            if (skipped < model.stream_scroll) {
                skipped += 1;
                off = chunk_end;
                continue;
            }
            if (line >= visible_h) {
                // Keep counting total_lines but stop rendering
                off = chunk_end;
                continue;
            }

            const row: u16 = @intCast(3 + line);
            r.writeStyledText(row, 1, if (off == 0) arrow else "  ", arrow_style);

            // Render printable chars, dots for non-printable
            var c: u16 = 3;
            for (chunk) |b| {
                if (c >= cols) break;
                const ch: u21 = if (b >= 0x20 and b < 0x7F) b else '.';
                r.applyCell(row, c, ch, text_style);
                c += 1;
            }

            line += 1;
            off = chunk_end;
        }
    }

    // Scroll clamp
    if (total_lines > visible_h) {
        if (model.stream_scroll > total_lines - visible_h) {
            model.stream_scroll = total_lines - visible_h;
        }
    } else {
        model.stream_scroll = 0;
    }

    if (total_lines > visible_h) {
        var sbuf: [32]u8 = undefined;
        const ss = std.fmt.bufPrint(&sbuf, "line {d}/{d}", .{ model.stream_scroll + 1, total_lines }) catch "";
        r.writeStyledText(rows -| 2, cols -| @as(u16, @intCast(ss.len + 1)), ss, .{ .fg = .{ .rgb = overlay0 } });
    }

    if (line == 0) {
        r.writeStyledText(4, 1, "No payload data in this stream", detail_label_style);
    }
}

fn viewStats(model: *Model, r: *P.Renderer, rows: u16, cols: u16) void {
    const pkts = model.packets.items;
    if (pkts.len == 0) {
        r.writeStyledText(2, 1, "No packets captured yet", detail_label_style);
        return;
    }

    // Protocol stats
    var proto_bytes: [6]u64 = .{0} ** 6;
    var proto_count: [6]u32 = .{0} ** 6;
    const proto_names = [_][]const u8{ "TCP", "UDP", "ICMP", "ICMPv6", "ARP", "OTHER" };
    const proto_colors = [_]Rgb{ c_green, c_blue, c_yellow, c_yellow, c_mauve, subtext0 };

    // Top IPs by bytes
    const max_top = 10;
    var top_ips: [max_top]IpEntry = undefined;
    for (&top_ips) |*e| e.* = .{};
    var total_bytes: u64 = 0;

    for (pkts) |*pkt| {
        const len: u64 = pkt.length;
        total_bytes += len;

        const pi: usize = switch (pkt.protocol) {
            .tcp => 0,
            .udp => 1,
            .icmp => 2,
            .icmp6 => 3,
            .arp => 4,
            .other => 5,
        };
        proto_bytes[pi] += len;
        proto_count[pi] += 1;

        // Track top source IPs
        if (pkt.src_addr_len > 0) {
            insertTopIp(&top_ips, pkt.src_addr, pkt.src_addr_len, len);
        }
    }

    var row: u16 = 1;
    r.writeStyledText(row, 1, "Protocol Breakdown", .{ .fg = .{ .rgb = text_col }, .bold = true });
    row += 1;
    drawHLine(r, row, cols);
    row += 1;

    // Bar chart per protocol
    const bar_max: u16 = if (cols > 60) cols - 40 else 20;
    for (0..6) |pi| {
        if (proto_count[pi] == 0) continue;
        if (row >= rows -| 2) break;

        r.writeStyledText(row, 1, proto_names[pi], .{ .fg = .{ .rgb = proto_colors[pi] }, .bold = true });

        var cbuf: [16]u8 = undefined;
        const cs = std.fmt.bufPrint(&cbuf, "{d}", .{proto_count[pi]}) catch "";
        r.writeStyledText(row, 10, cs, .{ .fg = .{ .rgb = subtext0 } });

        var bbuf: [16]u8 = undefined;
        const bs = fmtBytes(proto_bytes[pi], &bbuf);
        r.writeStyledText(row, 20, bs, .{ .fg = .{ .rgb = text_col } });

        // Bar
        const ratio: u16 = if (total_bytes > 0) @intCast(@min(@as(u64, bar_max), proto_bytes[pi] * bar_max / total_bytes)) else 0;
        var bc: u16 = 0;
        while (bc < ratio) : (bc += 1) {
            r.applyCell(row, 30 + bc, 0x2588, .{ .fg = .{ .rgb = proto_colors[pi] } });
        }

        row += 1;
    }

    row += 1;
    if (row < rows -| 2) {
        r.writeStyledText(row, 1, "Top Source IPs", .{ .fg = .{ .rgb = text_col }, .bold = true });
        row += 1;
        drawHLine(r, row, cols);
        row += 1;

        // Column positions adapt to terminal width
        const addr_col: u16 = 1;
        const addr_w: u16 = if (cols >= 120) 42 else 20;
        const bytes_col: u16 = addr_col + addr_w;
        const pct_col: u16 = bytes_col + 14;
        const bar_col: u16 = pct_col + 6;

        for (&top_ips) |*entry| {
            if (entry.bytes == 0) break;
            if (row >= rows -| 2) break;

            const addr = entry.addr[0..entry.len];
            const show_len = @min(addr.len, @as(usize, addr_w) -| 2);
            r.writeStyledText(row, addr_col, addr[0..show_len], .{ .fg = .{ .rgb = c_blue }, .bold = true });

            var bbuf2: [16]u8 = undefined;
            const bs2 = fmtBytes(entry.bytes, &bbuf2);
            r.writeStyledText(row, bytes_col, bs2, .{ .fg = .{ .rgb = text_col } });

            const pct = if (total_bytes > 0) entry.bytes * 100 / total_bytes else 0;
            var pbuf: [8]u8 = undefined;
            const ps = std.fmt.bufPrint(&pbuf, "{d}%", .{pct}) catch "";
            r.writeStyledText(row, pct_col, ps, .{ .fg = .{ .rgb = subtext0 } });

            const ratio: u16 = if (total_bytes > 0) @intCast(@min(@as(u64, bar_max), entry.bytes * bar_max / total_bytes)) else 0;
            var bc: u16 = 0;
            while (bc < ratio) : (bc += 1) {
                r.applyCell(row, bar_col + bc, 0x2588, .{ .fg = .{ .rgb = c_blue } });
            }

            row += 1;
        }
    }

    // Total
    if (row + 1 < rows -| 1) {
        row += 1;
        var tbuf: [32]u8 = undefined;
        var bbuf3: [16]u8 = undefined;
        const total_s = fmtBytes(total_bytes, &bbuf3);
        const ts = std.fmt.bufPrint(&tbuf, "Total: {d} packets  {s}", .{ pkts.len, total_s }) catch "";
        r.writeStyledText(row, 1, ts, .{ .fg = .{ .rgb = text_col }, .bold = true });
    }
}

const IpEntry = struct {
    addr: [46]u8 = .{0} ** 46,
    len: u8 = 0,
    bytes: u64 = 0,
};

fn insertTopIp(top: []IpEntry, addr: [46]u8, addr_len: u8, bytes: u64) void {
    // Find existing or insert
    for (top) |*entry| {
        if (entry.len == addr_len and std.mem.eql(u8, entry.addr[0..entry.len], addr[0..addr_len])) {
            entry.bytes += bytes;
            // Bubble up if needed
            sortTopIps(top);
            return;
        }
    }
    // Insert if larger than smallest
    const last = &top[top.len - 1];
    if (bytes > last.bytes or last.len == 0) {
        last.addr = addr;
        last.len = addr_len;
        last.bytes = bytes;
        sortTopIps(top);
    }
}

fn sortTopIps(top: []IpEntry) void {
    // Simple insertion sort descending by bytes
    var i: usize = 1;
    while (i < top.len) : (i += 1) {
        var j = i;
        while (j > 0 and top[j].bytes > top[j - 1].bytes) : (j -= 1) {
            const tmp = top[j];
            top[j] = top[j - 1];
            top[j - 1] = tmp;
        }
    }
}

fn fmtBytes(bytes: u64, buf: *[16]u8) []const u8 {
    if (bytes >= 1024 * 1024 * 1024) {
        return std.fmt.bufPrint(buf, "{d}.{d} GB", .{ bytes / (1024 * 1024 * 1024), (bytes / (1024 * 1024 * 100)) % 10 }) catch "";
    } else if (bytes >= 1024 * 1024) {
        return std.fmt.bufPrint(buf, "{d}.{d} MB", .{ bytes / (1024 * 1024), (bytes / (1024 * 100)) % 10 }) catch "";
    } else if (bytes >= 1024) {
        return std.fmt.bufPrint(buf, "{d}.{d} KB", .{ bytes / 1024, (bytes / 100) % 10 }) catch "";
    } else {
        return std.fmt.bufPrint(buf, "{d} B", .{bytes}) catch "";
    }
}

fn viewHexDump(model: *Model, r: *P.Renderer, rows: u16, cols: u16) void {
    const pkt = getVisible(model, model.selected) orelse {
        r.writeStyledText(2, 1, "No packet selected", detail_label_style);
        return;
    };

    {
        var hbuf: [80]u8 = undefined;
        const hs = std.fmt.bufPrint(&hbuf, "Packet #{d}  {s}:{d} -> {s}:{d}  {s}  {d} bytes", .{
            model.selected + 1,
            pkt.srcAddr(),
            pkt.src_port,
            pkt.dstAddr(),
            pkt.dst_port,
            pkt.protocol.name(),
            pkt.raw_len,
        }) catch "";
        r.writeStyledText(1, 1, hs, .{ .fg = .{ .rgb = text_col }, .bold = true });
    }
    drawHLine(r, 2, cols);

    const bytes_per_line: usize = 16;
    const raw = pkt.raw[0..pkt.raw_len];
    const total_lines = (raw.len + bytes_per_line - 1) / bytes_per_line;
    const visible = @as(usize, rows) -| 4; // rows 3..rows-2

    if (total_lines > visible) {
        if (model.hex_scroll > total_lines - visible) {
            model.hex_scroll = total_lines - visible;
        }
    } else {
        model.hex_scroll = 0;
    }

    const offset_style: Style = .{ .fg = .{ .rgb = overlay0 } };
    const hex_style: Style = .{ .fg = .{ .rgb = c_blue } };
    const ascii_style: Style = .{ .fg = .{ .rgb = c_green } };
    const dot_style: Style = .{ .fg = .{ .rgb = overlay0 } };

    var line_idx: usize = 0;
    while (line_idx < visible) : (line_idx += 1) {
        const data_line = model.hex_scroll + line_idx;
        const row: u16 = @intCast(3 + line_idx);
        const byte_offset = data_line * bytes_per_line;
        if (byte_offset >= raw.len) break;

        const line_end = @min(byte_offset + bytes_per_line, raw.len);
        const line_bytes = raw[byte_offset..line_end];

        var off_buf: [8]u8 = undefined;
        const off_s = std.fmt.bufPrint(&off_buf, "{X:0>4}", .{byte_offset}) catch "";
        r.writeStyledText(row, 1, off_s, offset_style);

        var hcol: u16 = 7;
        for (line_bytes, 0..) |b, bi| {
            var hb: [3]u8 = undefined;
            _ = std.fmt.bufPrint(&hb, "{X:0>2} ", .{b}) catch {};
            r.writeStyledText(row, hcol, hb[0..2], hex_style);
            hcol += 3;
            if (bi == 7) {
                r.writeStyledText(row, hcol, " ", offset_style);
                hcol += 1;
            }
        }

        const ascii_col: u16 = 7 + 3 * 16 + 2;
        r.writeStyledText(row, ascii_col, "|", offset_style);
        for (line_bytes, 0..) |b, bi| {
            const ch: u21 = if (b >= 0x20 and b < 0x7F) b else '.';
            const sty = if (b >= 0x20 and b < 0x7F) ascii_style else dot_style;
            r.applyCell(row, ascii_col + 1 + @as(u16, @intCast(bi)), ch, sty);
        }
        r.writeStyledText(row, ascii_col + 1 + @as(u16, @intCast(line_bytes.len)), "|", offset_style);
    }

    if (total_lines > visible) {
        var sbuf: [32]u8 = undefined;
        const ss = std.fmt.bufPrint(&sbuf, "line {d}/{d}", .{ model.hex_scroll + 1, total_lines }) catch "";
        r.writeStyledText(rows -| 2, cols -| @as(u16, @intCast(ss.len + 1)), ss, offset_style);
    }
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
    // ASCII dash on Windows (CMD lacks box-drawing glyphs), Unicode line elsewhere
    const ch: u21 = if (builtin.os.tag == .windows) '-' else 0x2500;
    var c: u16 = 0;
    while (c < cols) : (c += 1) {
        r.applyCell(row, c, ch, sep_style);
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

var active_iface: [32]u8 = .{0} ** 32;
var active_iface_len: u8 = 0;

fn activeIfaceSlice() []const u8 {
    return active_iface[0..active_iface_len];
}

pub fn main() !void {
    var iface_arg: ?[]const u8 = null;
    var list_mode = false;

    const argv = std.os.argv;
    var ai: usize = 1;
    while (ai < argv.len) : (ai += 1) {
        const arg = std.mem.span(argv[ai]);
        if (std.mem.eql(u8, arg, "-l") or std.mem.eql(u8, arg, "--list")) {
            list_mode = true;
        } else if (std.mem.eql(u8, arg, "-i")) {
            ai += 1;
            if (ai < argv.len) {
                iface_arg = std.mem.span(argv[ai]);
            }
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            std.debug.print(
                \\sniff - terminal packet sniffer
                \\
                \\Usage: sniff [options]
                \\
                \\Options:
                \\  -l, --list    List available network interfaces
                \\  -i <iface>    Capture on a specific interface
                \\  -h, --help    Show this help
                \\
                \\Without -i, captures on all interfaces (Linux) or default (macOS/Windows).
                \\Requires root/sudo (Linux, macOS) or Administrator (Windows).
                \\
            , .{});
            return;
        }
    }

    if (list_mode) {
        var ifaces: [capture.max_interfaces]capture.IfName = undefined;
        const count = capture.listInterfaces(&ifaces);
        if (count == 0) {
            std.debug.print("No interfaces found.\n", .{});
        } else {
            std.debug.print("Available interfaces:\n", .{});
            for (ifaces[0..count], 0..) |iface, idx| {
                std.debug.print("  {d}: {s}\n", .{ idx, iface.slice() });
            }
            std.debug.print("\nUse: sniff -i <name>\n", .{});
        }
        return;
    }

    if (iface_arg) |name| {
        const len = @min(name.len, active_iface.len);
        @memcpy(active_iface[0..len], name[0..len]);
        active_iface_len = @intCast(len);
    } else {
        const label = switch (builtin.os.tag) {
            .linux => "all",
            else => "default",
        };
        @memcpy(active_iface[0..label.len], label);
        active_iface_len = @intCast(label.len);
    }

    capture_handle = capture.openOn(iface_arg) catch |err| {
        std.debug.print("sniff: {s}\n", .{capture.errorMessage(err)});
        std.process.exit(1);
    };
    defer capture.close(capture_handle.?);

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
