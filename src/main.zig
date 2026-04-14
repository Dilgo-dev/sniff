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

const Theme = struct {
    name: []const u8,
    surface0: Rgb,
    surface1: Rgb,
    text: Rgb,
    subtext: Rgb,
    overlay: Rgb,
    green: Rgb,
    blue: Rgb,
    yellow: Rgb,
    mauve: Rgb,
    peach: Rgb,
    red: Rgb,
    search_bg: Rgb,
};

const themes = [_]Theme{
    .{
        .name = "dark",
        .surface0 = .{ .r = 49, .g = 50, .b = 68 },
        .surface1 = .{ .r = 69, .g = 71, .b = 90 },
        .text = .{ .r = 205, .g = 214, .b = 244 },
        .subtext = .{ .r = 166, .g = 173, .b = 200 },
        .overlay = .{ .r = 108, .g = 112, .b = 134 },
        .green = .{ .r = 166, .g = 227, .b = 161 },
        .blue = .{ .r = 137, .g = 180, .b = 250 },
        .yellow = .{ .r = 249, .g = 226, .b = 175 },
        .mauve = .{ .r = 203, .g = 166, .b = 247 },
        .peach = .{ .r = 250, .g = 179, .b = 135 },
        .red = .{ .r = 243, .g = 139, .b = 168 },
        .search_bg = .{ .r = 62, .g = 56, .b = 30 },
    },
    .{
        .name = "light",
        .surface0 = .{ .r = 230, .g = 233, .b = 239 },
        .surface1 = .{ .r = 204, .g = 208, .b = 218 },
        .text = .{ .r = 76, .g = 79, .b = 105 },
        .subtext = .{ .r = 108, .g = 111, .b = 133 },
        .overlay = .{ .r = 156, .g = 160, .b = 176 },
        .green = .{ .r = 64, .g = 160, .b = 43 },
        .blue = .{ .r = 30, .g = 102, .b = 245 },
        .yellow = .{ .r = 223, .g = 142, .b = 29 },
        .mauve = .{ .r = 136, .g = 57, .b = 239 },
        .peach = .{ .r = 254, .g = 100, .b = 11 },
        .red = .{ .r = 210, .g = 15, .b = 57 },
        .search_bg = .{ .r = 252, .g = 234, .b = 187 },
    },
};

var initial_theme_idx: u8 = 0;
var initial_col_widths: ColumnWidths = .{};
var initial_col_widths_set: bool = false;

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
    theme_idx: u8 = 0,
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
    graph_view: bool = false,
    // Ring buffer of bytes-per-second for the bandwidth graph
    bw_ring: [max_bw_samples]u32 = .{0} ** max_bw_samples,
    bw_pps_ring: [max_bw_samples]u16 = .{0} ** max_bw_samples,
    bw_head: usize = 0,
    bw_last_sec: i64 = 0,
    bw_accum_bytes: u32 = 0,
    bw_accum_pkts: u16 = 0,
    input_mode: InputMode = .none,
    input_buf: [128]u8 = .{0} ** 128,
    input_len: u8 = 0,
    input_cursor: u8 = 0,
    input_error: bool = false,
    status_buf: [64]u8 = .{0} ** 64,
    status_len: u8 = 0,
    status_time: i64 = 0,
    preset_view: bool = false,
    preset_selected: u8 = 0,
    presets: [max_presets]Preset = [_]Preset{.{}} ** max_presets,
    preset_count: u8 = 0,
    col_widths: ColumnWidths = .{},
    col_resize: bool = false,
    col_selected: u3 = 0,

    fn th(self: *const Model) Theme {
        return themes[self.theme_idx % themes.len];
    }
};

const Preset = struct {
    buf: [128]u8 = .{0} ** 128,
    len: u8 = 0,

    fn slice(self: *const Preset) []const u8 {
        return self.buf[0..self.len];
    }
};

const ColumnWidths = struct {
    num: u16 = 6,
    time: u16 = 10,
    src: u16 = 0,
    dst: u16 = 0,
    proto: u16 = 8,
    len: u16 = 7,

    fn srcWidth(self: ColumnWidths, cols: u16) u16 {
        return if (self.src > 0) self.src else addrWidth(cols);
    }

    fn dstWidth(self: ColumnWidths, cols: u16) u16 {
        return if (self.dst > 0) self.dst else addrWidth(cols);
    }

    fn colWidth(self: *const ColumnWidths, idx: u3, cols: u16) u16 {
        return switch (idx) {
            0 => self.num,
            1 => self.time,
            2 => self.srcWidth(cols),
            3 => self.dstWidth(cols),
            4 => self.proto,
            5 => self.len,
            else => 0,
        };
    }

    fn setCol(self: *ColumnWidths, idx: u3, val: u16, cols: u16) void {
        switch (idx) {
            0 => self.num = val,
            1 => self.time = val,
            2 => {
                if (self.src == 0) self.src = addrWidth(cols);
                self.src = val;
            },
            3 => {
                if (self.dst == 0) self.dst = addrWidth(cols);
                self.dst = val;
            },
            4 => self.proto = val,
            5 => self.len = val,
            else => {},
        }
    }
};

const col_names = [6][]const u8{ "#", "Time", "Source", "Destination", "Proto", "Len" };

const version = "0.1.0";
const max_packets = 50000;
const max_bw_samples = 300; // 5 minutes of per-second data
const max_presets = 20;

fn init(_: std.mem.Allocator) anyerror!Model {
    var model: Model = .{ .start_time = std.time.milliTimestamp(), .theme_idx = initial_theme_idx };
    loadPresets(&model);
    loadColumns(&model);
    if (initial_col_widths_set) {
        model.col_widths = initial_col_widths;
        saveColumns(&model);
    }
    return model;
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
            if (model.preset_view) {
                handlePresetKey(model, k);
            } else if (model.col_resize) {
                handleColResize(model, k);
            } else if (model.input_mode != .none) {
                handleTextInput(model, k);
            } else {
                switch (handleKey(model, k)) {
                    .quit => return .quit,
                    else => {},
                }
            }
        },
        .mouse => |me| handleMouse(model, me),
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
                    updateBwRing(model, pkt.timestamp_ms, pkt.length);
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
            if (c == 'b') {
                model.graph_view = !model.graph_view;
                model.hex_view = false;
                model.stats_view = false;
                model.stream_view = false;
            }
            if (c == 's') {
                model.stats_view = !model.stats_view;
                model.hex_view = false;
                model.stream_view = false;
                model.graph_view = false;
            }
            if (c == 'x') {
                model.hex_view = !model.hex_view;
                model.hex_scroll = 0;
                model.stats_view = false;
                model.stream_view = false;
                model.graph_view = false;
            }
            if (c == 't') {
                if (model.stream_view) {
                    model.stream_view = false;
                } else if (getVisible(model, model.selected)) |pkt| {
                    if (pkt.protocol == .tcp) {
                        model.stream_view = true;
                        model.hex_view = false;
                        model.stats_view = false;
                        model.graph_view = false;
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
            if (c == 'T') model.theme_idx = @intCast((model.theme_idx + 1) % themes.len);
            if (c == 'P') model.preset_view = !model.preset_view;
            if (c == 'c') {
                model.col_resize = true;
                model.col_selected = 0;
            }
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

fn handleMouse(model: *Model, me: glym.input.MouseEvent) void {
    const mouse = glym.input.MouseButton;
    switch (me.button) {
        mouse.scroll_up => {
            if (model.hex_view and model.hex_scroll > 0) {
                model.hex_scroll -= 1;
            } else if (model.stream_view and model.stream_scroll > 0) {
                model.stream_scroll -= 1;
            } else if (!model.hex_view and !model.stream_view and !model.stats_view and !model.graph_view) {
                if (model.selected > 0) {
                    model.follow = false;
                    model.selected -= 1;
                    adjustScroll(model);
                }
            }
        },
        mouse.scroll_down => {
            if (model.hex_view) {
                model.hex_scroll += 1;
            } else if (model.stream_view) {
                model.stream_scroll += 1;
            } else if (!model.stats_view and !model.graph_view) {
                const count = visibleCount(model);
                if (count > 0 and model.selected < count - 1) {
                    model.follow = false;
                    model.selected += 1;
                    adjustScroll(model);
                }
            }
        },
        mouse.left => {
            if (!me.pressed) return;
            if (model.hex_view or model.stream_view or model.stats_view or model.graph_view) return;
            // Packet list rows start at screen row 3 (0-indexed)
            if (me.row < 3) return;
            const row_offset = @as(usize, me.row) - 3;
            const lh = listHeight(model.rows);
            if (row_offset >= lh) return;
            const pkt_idx = model.scroll + row_offset;
            const count = visibleCount(model);
            if (pkt_idx < count) {
                model.follow = false;
                model.selected = pkt_idx;
            }
        },
        else => {},
    }
}

fn handleColResize(model: *Model, k: glym.input.Key) void {
    const min_w: u16 = 3;
    const max_w: u16 = 60;
    switch (k.code) {
        .escape, .enter => {
            model.col_resize = false;
            saveColumns(model);
        },
        .char => |c| {
            if (c == 'c' or c == 'q') {
                model.col_resize = false;
                saveColumns(model);
            }
        },
        .arrow_left => {
            if (model.col_selected > 0) model.col_selected -= 1;
        },
        .arrow_right => {
            if (model.col_selected < 5) model.col_selected += 1;
        },
        .arrow_up => {
            const cur = model.col_widths.colWidth(model.col_selected, model.cols);
            if (cur < max_w) model.col_widths.setCol(model.col_selected, cur + 1, model.cols);
        },
        .arrow_down => {
            const cur = model.col_widths.colWidth(model.col_selected, model.cols);
            if (cur > min_w) model.col_widths.setCol(model.col_selected, cur - 1, model.cols);
        },
        else => {},
    }
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

fn handlePresetKey(model: *Model, k: glym.input.Key) void {
    switch (k.code) {
        .escape => model.preset_view = false,
        .enter => {
            if (model.preset_count > 0 and model.preset_selected < model.preset_count) {
                const preset = model.presets[model.preset_selected].slice();
                @memcpy(model.input_buf[0..preset.len], preset);
                model.input_len = @intCast(preset.len);
                model.input_cursor = model.input_len;
                applyFilter(model);
                model.preset_view = false;
            }
        },
        .arrow_up => {
            if (model.preset_selected > 0) model.preset_selected -= 1;
        },
        .arrow_down => {
            if (model.preset_selected + 1 < model.preset_count) model.preset_selected += 1;
        },
        .char => |c| {
            if (c == 'a') {
                if (model.filter_len > 0 and model.preset_count < max_presets) {
                    const expr = model.filter_buf[0..model.filter_len];
                    // Avoid duplicates
                    for (model.presets[0..model.preset_count]) |*p| {
                        if (std.mem.eql(u8, p.slice(), expr)) return;
                    }
                    var p = &model.presets[model.preset_count];
                    @memcpy(p.buf[0..expr.len], expr);
                    p.len = @intCast(expr.len);
                    model.preset_count += 1;
                    savePresets(model);
                    setStatus(model, "Preset saved");
                }
            }
            if (c == 'd') {
                if (model.preset_count > 0 and model.preset_selected < model.preset_count) {
                    var i: usize = model.preset_selected;
                    while (i + 1 < model.preset_count) : (i += 1) {
                        model.presets[i] = model.presets[i + 1];
                    }
                    model.presets[model.preset_count - 1] = .{};
                    model.preset_count -= 1;
                    if (model.preset_selected >= model.preset_count and model.preset_selected > 0)
                        model.preset_selected -= 1;
                    savePresets(model);
                    setStatus(model, "Preset deleted");
                }
            }
            if (c == 'q') model.preset_view = false;
        },
        else => {},
    }
}

fn presetsPath(buf: *[std.fs.max_path_bytes]u8) ?[]const u8 {
    const home = std.posix.getenv("HOME") orelse return null;
    const s = std.fmt.bufPrint(buf, "{s}/.config/sniff/presets.txt", .{home}) catch return null;
    return s;
}

fn loadPresets(model: *Model) void {
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const path = presetsPath(&pbuf) orelse return;
    const file = std.fs.openFileAbsolute(path, .{}) catch return;
    defer file.close();

    var rbuf: [128 * max_presets]u8 = undefined;
    const n = file.readAll(&rbuf) catch return;
    const data = rbuf[0..n];

    var start: usize = 0;
    while (start < data.len and model.preset_count < max_presets) {
        var end = start;
        while (end < data.len and data[end] != '\n') : (end += 1) {}
        const line = data[start..end];
        if (line.len > 0 and line.len <= 128) {
            var p = &model.presets[model.preset_count];
            @memcpy(p.buf[0..line.len], line);
            p.len = @intCast(line.len);
            model.preset_count += 1;
        }
        start = end + 1;
    }
}

fn savePresets(model: *const Model) void {
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const path = presetsPath(&pbuf) orelse return;

    // Ensure ~/.config and ~/.config/sniff exist
    const home = std.posix.getenv("HOME") orelse return;
    var dbuf: [std.fs.max_path_bytes]u8 = undefined;
    const config_dir = std.fmt.bufPrint(&dbuf, "{s}/.config", .{home}) catch return;
    std.fs.makeDirAbsolute(config_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return,
    };
    const sniff_dir = std.fmt.bufPrint(&dbuf, "{s}/.config/sniff", .{home}) catch return;
    std.fs.makeDirAbsolute(sniff_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return,
    };

    const file = std.fs.createFileAbsolute(path, .{}) catch return;
    defer file.close();

    for (model.presets[0..model.preset_count]) |*p| {
        _ = file.write(p.slice()) catch return;
        _ = file.write("\n") catch return;
    }
}

fn columnsPath(buf: *[std.fs.max_path_bytes]u8) ?[]const u8 {
    const home = std.posix.getenv("HOME") orelse return null;
    return std.fmt.bufPrint(buf, "{s}/.config/sniff/columns.txt", .{home}) catch null;
}

fn loadColumns(model: *Model) void {
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const path = columnsPath(&pbuf) orelse return;
    const file = std.fs.openFileAbsolute(path, .{}) catch return;
    defer file.close();

    var rbuf: [256]u8 = undefined;
    const n = file.readAll(&rbuf) catch return;
    const data = rbuf[0..n];

    var start: usize = 0;
    while (start < data.len) {
        var end = start;
        while (end < data.len and data[end] != '\n') : (end += 1) {}
        const line = data[start..end];
        if (std.mem.indexOfScalar(u8, line, '=')) |eq| {
            const key = line[0..eq];
            const val = std.fmt.parseInt(u16, line[eq + 1 ..], 10) catch {
                start = end + 1;
                continue;
            };
            if (val >= 3 and val <= 60) {
                if (std.mem.eql(u8, key, "num")) {
                    model.col_widths.num = val;
                } else if (std.mem.eql(u8, key, "time")) {
                    model.col_widths.time = val;
                } else if (std.mem.eql(u8, key, "src")) {
                    model.col_widths.src = val;
                } else if (std.mem.eql(u8, key, "dst")) {
                    model.col_widths.dst = val;
                } else if (std.mem.eql(u8, key, "proto")) {
                    model.col_widths.proto = val;
                } else if (std.mem.eql(u8, key, "len")) {
                    model.col_widths.len = val;
                }
            }
        }
        start = end + 1;
    }
}

fn saveColumns(model: *const Model) void {
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const path = columnsPath(&pbuf) orelse return;

    const home = std.posix.getenv("HOME") orelse return;
    var dbuf: [std.fs.max_path_bytes]u8 = undefined;
    const config_dir = std.fmt.bufPrint(&dbuf, "{s}/.config", .{home}) catch return;
    std.fs.makeDirAbsolute(config_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return,
    };
    const sniff_dir = std.fmt.bufPrint(&dbuf, "{s}/.config/sniff", .{home}) catch return;
    std.fs.makeDirAbsolute(sniff_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return,
    };

    const file = std.fs.createFileAbsolute(path, .{}) catch return;
    defer file.close();

    const cw = model.col_widths;
    var buf: [256]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "num={d}\ntime={d}\nsrc={d}\ndst={d}\nproto={d}\nlen={d}\n", .{
        cw.num, cw.time, cw.src, cw.dst, cw.proto, cw.len,
    }) catch return;
    _ = file.write(s) catch {};
}

fn parseColumnSpec(spec: []const u8) ?ColumnWidths {
    var cw: ColumnWidths = .{};
    var has_any = false;
    var iter = std.mem.splitScalar(u8, spec, ',');
    while (iter.next()) |part| {
        const sep = std.mem.indexOfScalar(u8, part, ':') orelse continue;
        const key = part[0..sep];
        const val = std.fmt.parseInt(u16, part[sep + 1 ..], 10) catch continue;
        if (val < 3 or val > 60) continue;
        has_any = true;
        if (std.mem.eql(u8, key, "num")) {
            cw.num = val;
        } else if (std.mem.eql(u8, key, "time")) {
            cw.time = val;
        } else if (std.mem.eql(u8, key, "src")) {
            cw.src = val;
        } else if (std.mem.eql(u8, key, "dst")) {
            cw.dst = val;
        } else if (std.mem.eql(u8, key, "proto")) {
            cw.proto = val;
        } else if (std.mem.eql(u8, key, "len")) {
            cw.len = val;
        }
    }
    return if (has_any) cw else null;
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
    if (pkt.tls_sni_len > 0 and containsSubstring(pkt.sniName(), term)) return true;
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

fn protoColor(t: Theme, proto: packet.Protocol) Rgb {
    return switch (proto) {
        .tcp => t.green,
        .udp => t.blue,
        .icmp, .icmp6 => t.yellow,
        .arp => t.mauve,
        .other => t.subtext,
    };
}

fn view(model: *Model, r: *P.Renderer) void {
    const rows = r.rows;
    const cols = r.cols;
    const t = model.th();
    if (rows < 10 or cols < 40) {
        r.writeStyledText(0, 0, "Terminal too small", .{ .fg = .{ .rgb = t.red } });
        return;
    }

    const title_style: Style = .{ .bg = .{ .rgb = t.surface0 }, .fg = .{ .rgb = t.text }, .bold = true };
    r.fillRect(0, 0, 1, cols, .{ .char = ' ', .style = title_style });
    r.writeStyledText(0, 1, "sniff", title_style);
    {
        var buf: [80]u8 = undefined;
        const iface = activeIfaceSlice();
        const s = std.fmt.bufPrint(&buf, " [{s}] {d} packets", .{ iface, model.packets.items.len }) catch "";
        r.writeStyledText(0, 7, s, title_style);
    }
    const now = std.time.milliTimestamp();
    if (model.status_len > 0 and now - model.status_time < 3000) {
        const smsg = model.status_buf[0..model.status_len];
        r.writeStyledText(0, cols -| @as(u16, @intCast(smsg.len + 2)), " ", .{ .bg = .{ .rgb = t.surface0 } });
        r.writeStyledText(0, cols -| @as(u16, @intCast(smsg.len + 1)), smsg, .{ .bg = .{ .rgb = t.surface0 }, .fg = .{ .rgb = t.green }, .bold = true });
        r.writeStyledText(0, cols -| 1, " ", .{ .bg = .{ .rgb = t.surface0 } });
    } else if (model.paused) {
        r.writeStyledText(0, cols -| 10, " PAUSED ", .{ .bg = .{ .rgb = t.surface0 }, .fg = .{ .rgb = t.red }, .bold = true });
    } else if (model.follow) {
        r.writeStyledText(0, cols -| 10, " FOLLOW ", .{ .bg = .{ .rgb = t.surface0 }, .fg = .{ .rgb = t.green }, .bold = true });
    }
    {
        var info_col: u16 = cols / 3;
        if (model.filter.active) {
            r.writeStyledText(0, info_col, "filter:", .{ .bg = .{ .rgb = t.surface0 }, .fg = .{ .rgb = t.overlay } });
            info_col += 7;
            const expr = model.filter_buf[0..model.filter_len];
            r.writeStyledText(0, info_col, expr, .{ .bg = .{ .rgb = t.surface0 }, .fg = .{ .rgb = t.peach }, .bold = true });
            info_col += @as(u16, @intCast(expr.len)) + 2;
        }
        if (model.search_active) {
            r.writeStyledText(0, info_col, "/", .{ .bg = .{ .rgb = t.surface0 }, .fg = .{ .rgb = t.overlay } });
            info_col += 1;
            const term = model.search_buf[0..model.search_len];
            r.writeStyledText(0, info_col, term, .{ .bg = .{ .rgb = t.surface0 }, .fg = .{ .rgb = t.yellow }, .bold = true });
        }
    }

    if (model.graph_view) {
        viewGraph(model, r, rows, cols);
    } else if (model.stream_view) {
        viewStream(model, r, rows, cols);
    } else if (model.stats_view) {
        viewStats(model, r, rows, cols);
    } else if (model.hex_view) {
        viewHexDump(model, r, rows, cols);
    } else {
        viewPacketList(model, r, rows, cols);
    }

    if (model.preset_view) {
        viewPresets(model, r, rows, cols, t);
    }

    const help_style: Style = .{ .bg = .{ .rgb = t.surface0 }, .fg = .{ .rgb = t.subtext } };
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
            .{ .bg = .{ .rgb = t.surface0 }, .fg = .{ .rgb = t.red }, .bold = true }
        else switch (model.input_mode) {
            .search => .{ .bg = .{ .rgb = t.surface0 }, .fg = .{ .rgb = t.yellow }, .bold = true },
            .save => .{ .bg = .{ .rgb = t.surface0 }, .fg = .{ .rgb = t.green }, .bold = true },
            else => .{ .bg = .{ .rgb = t.surface0 }, .fg = .{ .rgb = t.mauve }, .bold = true },
        };
        r.writeStyledText(help_row, 1, prompt, prompt_style);
        const plen: u16 = @intCast(prompt.len);
        const text = model.input_buf[0..model.input_len];
        r.writeStyledText(help_row, 1 + plen, text, .{ .bg = .{ .rgb = t.surface0 }, .fg = .{ .rgb = t.text } });
        const ccol: u16 = 1 + plen + @as(u16, model.input_cursor);
        const cch: u21 = if (model.input_cursor < model.input_len) model.input_buf[model.input_cursor] else ' ';
        r.applyCell(help_row, ccol, cch, .{ .bg = .{ .rgb = t.text }, .fg = .{ .rgb = t.surface0 } });
        r.writeStyledText(help_row, cols -| 22, "enter:apply esc:cancel", .{ .bg = .{ .rgb = t.surface0 }, .fg = .{ .rgb = t.overlay } });
    } else if (model.col_resize) {
        const hk_style: Style = .{ .bg = .{ .rgb = t.surface0 }, .fg = .{ .rgb = t.mauve }, .bold = true };
        var col: u16 = 1;
        r.writeStyledText(help_row, col, "COLUMNS ", .{ .bg = .{ .rgb = t.surface0 }, .fg = .{ .rgb = t.peach }, .bold = true });
        col += 8;
        col = writeHelpKey(r, help_row, col, "left/right", "select", help_style, hk_style);
        col = writeHelpKey(r, help_row, col, "up/dn", "resize", help_style, hk_style);
        _ = writeHelpKey(r, help_row, col, "esc", "done", help_style, hk_style);
    } else {
        const hk_style: Style = .{ .bg = .{ .rgb = t.surface0 }, .fg = .{ .rgb = t.mauve }, .bold = true };
        var col: u16 = 1;
        col = writeHelpKey(r, help_row, col, "q", "quit", help_style, hk_style);
        col = writeHelpKey(r, help_row, col, "p", "pause", help_style, hk_style);
        col = writeHelpKey(r, help_row, col, "f", "filter", help_style, hk_style);
        col = writeHelpKey(r, help_row, col, "/", "search", help_style, hk_style);
        col = writeHelpKey(r, help_row, col, "n/N", "next/prev", help_style, hk_style);
        col = writeHelpKey(r, help_row, col, "x", "hex", help_style, hk_style);
        col = writeHelpKey(r, help_row, col, "t", "stream", help_style, hk_style);
        col = writeHelpKey(r, help_row, col, "s", "stats", help_style, hk_style);
        col = writeHelpKey(r, help_row, col, "b", "graph", help_style, hk_style);
        col = writeHelpKey(r, help_row, col, "w", "export", help_style, hk_style);
        col = writeHelpKey(r, help_row, col, "P", "presets", help_style, hk_style);
        col = writeHelpKey(r, help_row, col, "T", "theme", help_style, hk_style);
        col = writeHelpKey(r, help_row, col, "F", "follow", help_style, hk_style);
        col = writeHelpKey(r, help_row, col, "c", "columns", help_style, hk_style);
        _ = writeHelpKey(r, help_row, col, "up/dn", "navigate", help_style, hk_style);
    }
}

fn viewPacketList(model: *Model, r: *P.Renderer, rows: u16, cols: u16) void {
    const t = model.th();
    const header_style: Style = .{ .fg = .{ .rgb = t.subtext }, .bold = true };
    const normal_style: Style = .{ .fg = .{ .rgb = t.text } };
    const sep_style: Style = .{ .fg = .{ .rgb = t.overlay } };
    const dl_style: Style = .{ .fg = .{ .rgb = t.subtext } };
    const dv_style: Style = .{ .fg = .{ .rgb = t.text }, .bold = true };

    const cw = model.col_widths;
    if (model.col_resize) {
        const hl_style: Style = .{ .fg = .{ .rgb = t.text }, .bg = .{ .rgb = t.overlay }, .bold = true };
        var c: u16 = 0;
        inline for (0..6) |ci| {
            const idx: u3 = @intCast(ci);
            const w = cw.colWidth(idx, cols);
            const sty = if (model.col_selected == idx) hl_style else header_style;
            writeField(r, 1, c, w, col_names[ci], sty);
            c += w;
        }
    } else {
        writeColumns(r, 1, cols, cw, "#", "Time", "Source", "Destination", "Proto", "Len", header_style);
    }
    drawHLine(r, 2, cols, sep_style);

    const lh = listHeight(rows);
    var i: usize = 0;
    while (i < lh) : (i += 1) {
        const pkt_idx = model.scroll + i;
        const row: u16 = @intCast(3 + i);
        const is_selected = pkt_idx == model.selected;

        if (getVisible(model, pkt_idx)) |pkt| {
            const is_match = searchMatches(model, &pkt);
            const row_bg: Rgb = if (is_selected) t.surface1 else if (is_match) t.search_bg else t.surface0;
            const row_style: Style = if (is_selected or is_match)
                .{ .bg = .{ .rgb = row_bg }, .fg = .{ .rgb = t.text } }
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

            writeColumns(r, row, cols, cw, num_s, time_s, pkt.srcAddr(), pkt.dstAddr(), pkt.protocol.name(), len_s, row_style);

            const pcol = protoCol(cw, cols);
            const pfg = protoColor(t, pkt.protocol);
            const pstyle: Style = if (is_selected) .{ .bg = .{ .rgb = row_bg }, .fg = .{ .rgb = pfg }, .bold = true } else if (is_match) .{ .bg = .{ .rgb = row_bg }, .fg = .{ .rgb = pfg } } else .{ .fg = .{ .rgb = pfg } };
            r.writeStyledText(row, pcol, pkt.protocol.name(), pstyle);
        } else {
            break;
        }
    }

    const sep_row: u16 = @intCast(@as(usize, rows) -| 4);
    drawHLine(r, sep_row, cols, sep_style);

    if (getVisible(model, model.selected)) |pkt| {
        const d1: u16 = sep_row + 1;
        const d2: u16 = sep_row + 2;

        r.writeStyledText(d1, 1, "Src: ", dl_style);
        r.writeStyledText(d1, 6, pkt.srcAddr(), dv_style);
        if (pkt.src_port > 0) {
            var pbuf: [8]u8 = undefined;
            const ps = std.fmt.bufPrint(&pbuf, ":{d}", .{pkt.src_port}) catch "";
            r.writeStyledText(d1, @intCast(6 + pkt.srcAddr().len), ps, dv_style);
        }

        const arrow_col: u16 = @intCast(@min(@as(usize, 30), @as(usize, cols) -| 1));
        r.writeStyledText(d1, arrow_col, " -> ", dl_style);
        const dst_col: u16 = arrow_col + 4;
        r.writeStyledText(d1, dst_col, "Dst: ", dl_style);
        r.writeStyledText(d1, dst_col + 5, pkt.dstAddr(), dv_style);
        if (pkt.dst_port > 0) {
            var pbuf2: [8]u8 = undefined;
            const ps2 = std.fmt.bufPrint(&pbuf2, ":{d}", .{pkt.dst_port}) catch "";
            r.writeStyledText(d1, @intCast(dst_col + 5 + pkt.dstAddr().len), ps2, dv_style);
        }

        r.writeStyledText(d2, 1, "Proto: ", dl_style);
        r.writeStyledText(d2, 8, pkt.protocol.name(), .{ .fg = .{ .rgb = protoColor(t, pkt.protocol) } });
        {
            var lbuf: [32]u8 = undefined;
            const ls = std.fmt.bufPrint(&lbuf, "  Len: {d}", .{pkt.length}) catch "";
            r.writeStyledText(d2, @intCast(8 + pkt.protocol.name().len), ls, dl_style);
        }
        if (pkt.ip_ttl > 0) {
            var tbuf: [16]u8 = undefined;
            const ts = std.fmt.bufPrint(&tbuf, "  TTL: {d}", .{pkt.ip_ttl}) catch "";
            r.writeStyledText(d2, 28, ts, dl_style);
        }
        if (pkt.protocol == .tcp and pkt.tcp_flags > 0) {
            var fbuf: [40]u8 = undefined;
            const flags = pkt.tcpFlagsStr(&fbuf);
            r.writeStyledText(d2, 42, "Flags: ", dl_style);
            r.writeStyledText(d2, 49, flags, .{ .fg = .{ .rgb = t.peach } });
        }
        if (pkt.dns_name_len > 0) {
            const label = if (pkt.dns_is_response) "DNS resp: " else "DNS: ";
            r.writeStyledText(d2, 42, label, dl_style);
            r.writeStyledText(d2, 42 + @as(u16, @intCast(label.len)), pkt.dnsName(), .{ .fg = .{ .rgb = t.yellow }, .bold = true });
        } else if (pkt.tls_sni_len > 0) {
            r.writeStyledText(d2, 42, "SNI: ", dl_style);
            r.writeStyledText(d2, 47, pkt.sniName(), .{ .fg = .{ .rgb = t.mauve }, .bold = true });
        } else if (pkt.http_info_len > 0) {
            r.writeStyledText(d2, 42, pkt.httpInfo(), .{ .fg = .{ .rgb = t.peach }, .bold = true });
        }
    }
}

fn updateBwRing(model: *Model, timestamp_ms: i64, length: u32) void {
    const sec = @divFloor(timestamp_ms, 1000);
    if (model.bw_last_sec == 0) model.bw_last_sec = sec;

    if (sec == model.bw_last_sec) {
        model.bw_accum_bytes +|= length;
        model.bw_accum_pkts +|= 1;
    } else {
        // Flush current second
        model.bw_ring[model.bw_head % max_bw_samples] = model.bw_accum_bytes;
        model.bw_pps_ring[model.bw_head % max_bw_samples] = model.bw_accum_pkts;
        model.bw_head += 1;

        // Fill gaps for seconds with no traffic
        const gap = @as(usize, @intCast(@min(sec - model.bw_last_sec - 1, max_bw_samples)));
        var g: usize = 0;
        while (g < gap) : (g += 1) {
            model.bw_ring[model.bw_head % max_bw_samples] = 0;
            model.bw_pps_ring[model.bw_head % max_bw_samples] = 0;
            model.bw_head += 1;
        }

        model.bw_last_sec = sec;
        model.bw_accum_bytes = length;
        model.bw_accum_pkts = 1;
    }
}

fn viewGraph(model: *Model, r: *P.Renderer, rows: u16, cols: u16) void {
    const t = model.th();
    const sep_s: Style = .{ .fg = .{ .rgb = t.overlay } };

    // Flush current accumulator so the live second is visible
    const cur_sec = @divFloor(std.time.milliTimestamp(), 1000);
    var head = model.bw_head;
    var ring = model.bw_ring;
    var pps_ring = model.bw_pps_ring;
    if (cur_sec == model.bw_last_sec) {
        ring[head % max_bw_samples] = model.bw_accum_bytes;
        pps_ring[head % max_bw_samples] = model.bw_accum_pkts;
        head += 1;
    }

    const sample_count = @min(head, max_bw_samples);
    if (sample_count == 0) {
        r.writeStyledText(2, 1, "No bandwidth data yet", .{ .fg = .{ .rgb = t.subtext } });
        return;
    }

    r.writeStyledText(1, 1, "Live Bandwidth (bytes/sec)", .{ .fg = .{ .rgb = t.text }, .bold = true });
    drawHLine(r, 2, cols, sep_s);

    const graph_w: usize = @as(usize, cols) -| 12;
    const graph_h: usize = @as(usize, rows) -| 8;
    if (graph_w < 10 or graph_h < 4) return;

    // Use the most recent graph_w samples
    const show = @min(sample_count, graph_w);
    const start_idx = if (head > show) head - show else 0;

    // Find max for Y-axis scaling
    var max_val: u32 = 1;
    var total_bw: u64 = 0;
    var total_pps: u64 = 0;
    var i: usize = 0;
    while (i < show) : (i += 1) {
        const idx = (start_idx + i) % max_bw_samples;
        if (ring[idx] > max_val) max_val = ring[idx];
        total_bw += ring[idx];
        total_pps += pps_ring[idx];
    }

    // Y-axis labels (top, mid, bottom)
    const top_row: u16 = 3;
    const bot_row: u16 = @intCast(3 + graph_h);
    {
        var lbuf: [16]u8 = undefined;
        r.writeStyledText(top_row, 1, fmtBytesRate(max_val, &lbuf), .{ .fg = .{ .rgb = t.overlay } });
        r.writeStyledText(bot_row, 1, "0", .{ .fg = .{ .rgb = t.overlay } });
        const mid_row = top_row + @as(u16, @intCast(graph_h / 2));
        r.writeStyledText(mid_row, 1, fmtBytesRate(max_val / 2, &lbuf), .{ .fg = .{ .rgb = t.overlay } });
    }

    // Block characters for sub-cell resolution (eighths)
    const blocks = [_]u21{ ' ', 0x2581, 0x2582, 0x2583, 0x2584, 0x2585, 0x2586, 0x2587, 0x2588 };
    const bar_col: u16 = 10;

    i = 0;
    while (i < show) : (i += 1) {
        const idx = (start_idx + i) % max_bw_samples;
        const val = ring[idx];
        const col_x: u16 = bar_col + @as(u16, @intCast(i));
        if (col_x >= cols) break;

        // Scale value to graph_h * 8 (sub-cell units)
        const scaled: usize = if (max_val > 0)
            @as(usize, val) * graph_h * 8 / max_val
        else
            0;
        const full_rows = scaled / 8;
        const frac = scaled % 8;

        // Draw from bottom up
        var gy: usize = 0;
        while (gy < graph_h) : (gy += 1) {
            const draw_row: u16 = bot_row - @as(u16, @intCast(gy));
            if (gy < full_rows) {
                r.applyCell(draw_row, col_x, 0x2588, .{ .fg = .{ .rgb = t.green } });
            } else if (gy == full_rows and frac > 0) {
                r.applyCell(draw_row, col_x, blocks[frac], .{ .fg = .{ .rgb = t.green } });
            }
        }
    }

    // Summary below the graph
    const info_row: u16 = bot_row + 1;
    drawHLine(r, info_row, cols, sep_s);
    {
        const avg_bw: u64 = if (show > 0) total_bw / show else 0;
        const avg_pps: u64 = if (show > 0) total_pps / show else 0;
        var abuf: [16]u8 = undefined;
        var mbuf: [16]u8 = undefined;
        var sbuf: [80]u8 = undefined;
        const ss = std.fmt.bufPrint(&sbuf, "avg: {s}/s  peak: {s}/s  {d} pps avg  {d}s window", .{
            fmtBytesRate(@intCast(avg_bw), &abuf),
            fmtBytesRate(max_val, &mbuf),
            avg_pps,
            show,
        }) catch "";
        r.writeStyledText(info_row + 1, 1, ss, .{ .fg = .{ .rgb = t.subtext } });
    }
}

fn fmtBytesRate(bytes: u32, buf: *[16]u8) []const u8 {
    if (bytes >= 1024 * 1024) {
        return std.fmt.bufPrint(buf, "{d}.{d}MB", .{ bytes / (1024 * 1024), (bytes / (1024 * 100)) % 10 }) catch "";
    } else if (bytes >= 1024) {
        return std.fmt.bufPrint(buf, "{d}.{d}KB", .{ bytes / 1024, (bytes / 100) % 10 }) catch "";
    } else {
        return std.fmt.bufPrint(buf, "{d}B", .{bytes}) catch "";
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
    const t = model.th();
    const sa = model.stream_src[0..model.stream_src_len];
    const da = model.stream_dst[0..model.stream_dst_len];

    {
        var hbuf: [96]u8 = undefined;
        const hs = std.fmt.bufPrint(&hbuf, "TCP Stream: {s}:{d} <-> {s}:{d}", .{
            sa, model.stream_sport, da, model.stream_dport,
        }) catch "";
        r.writeStyledText(1, 1, hs, .{ .fg = .{ .rgb = t.text }, .bold = true });
    }
    drawHLine(r, 2, cols, .{ .fg = .{ .rgb = t.overlay } });

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
        const arrow_style: Style = if (is_client) .{ .fg = .{ .rgb = t.green }, .bold = true } else .{ .fg = .{ .rgb = t.blue }, .bold = true };
        const text_style: Style = if (is_client) .{ .fg = .{ .rgb = t.green } } else .{ .fg = .{ .rgb = t.blue } };

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
        r.writeStyledText(rows -| 2, cols -| @as(u16, @intCast(ss.len + 1)), ss, .{ .fg = .{ .rgb = t.overlay } });
    }

    if (line == 0) {
        r.writeStyledText(4, 1, "No payload data in this stream", .{ .fg = .{ .rgb = t.subtext } });
    }
}

fn viewStats(model: *Model, r: *P.Renderer, rows: u16, cols: u16) void {
    const t = model.th();
    const pkts = model.packets.items;
    if (pkts.len == 0) {
        r.writeStyledText(2, 1, "No packets captured yet", .{ .fg = .{ .rgb = t.subtext } });
        return;
    }

    // Protocol stats
    var proto_bytes: [6]u64 = .{0} ** 6;
    var proto_count: [6]u32 = .{0} ** 6;
    const proto_names = [_][]const u8{ "TCP", "UDP", "ICMP", "ICMPv6", "ARP", "OTHER" };
    const proto_colors = [_]Rgb{ t.green, t.blue, t.yellow, t.yellow, t.mauve, t.subtext };

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
    r.writeStyledText(row, 1, "Protocol Breakdown", .{ .fg = .{ .rgb = t.text }, .bold = true });
    row += 1;
    drawHLine(r, row, cols, .{ .fg = .{ .rgb = t.overlay } });
    row += 1;

    // Bar chart per protocol
    const bar_max: u16 = if (cols > 60) cols - 40 else 20;
    for (0..6) |pi| {
        if (proto_count[pi] == 0) continue;
        if (row >= rows -| 2) break;

        r.writeStyledText(row, 1, proto_names[pi], .{ .fg = .{ .rgb = proto_colors[pi] }, .bold = true });

        var cbuf: [16]u8 = undefined;
        const cs = std.fmt.bufPrint(&cbuf, "{d}", .{proto_count[pi]}) catch "";
        r.writeStyledText(row, 10, cs, .{ .fg = .{ .rgb = t.subtext } });

        var bbuf: [16]u8 = undefined;
        const bs = fmtBytes(proto_bytes[pi], &bbuf);
        r.writeStyledText(row, 20, bs, .{ .fg = .{ .rgb = t.text } });

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
        r.writeStyledText(row, 1, "Top Source IPs", .{ .fg = .{ .rgb = t.text }, .bold = true });
        row += 1;
        drawHLine(r, row, cols, .{ .fg = .{ .rgb = t.overlay } });
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
            r.writeStyledText(row, addr_col, addr[0..show_len], .{ .fg = .{ .rgb = t.blue }, .bold = true });

            var bbuf2: [16]u8 = undefined;
            const bs2 = fmtBytes(entry.bytes, &bbuf2);
            r.writeStyledText(row, bytes_col, bs2, .{ .fg = .{ .rgb = t.text } });

            const pct = if (total_bytes > 0) entry.bytes * 100 / total_bytes else 0;
            var pbuf: [8]u8 = undefined;
            const ps = std.fmt.bufPrint(&pbuf, "{d}%", .{pct}) catch "";
            r.writeStyledText(row, pct_col, ps, .{ .fg = .{ .rgb = t.subtext } });

            const ratio: u16 = if (total_bytes > 0) @intCast(@min(@as(u64, bar_max), entry.bytes * bar_max / total_bytes)) else 0;
            var bc: u16 = 0;
            while (bc < ratio) : (bc += 1) {
                r.applyCell(row, bar_col + bc, 0x2588, .{ .fg = .{ .rgb = t.blue } });
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
        r.writeStyledText(row, 1, ts, .{ .fg = .{ .rgb = t.text }, .bold = true });
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

fn viewPresets(model: *Model, r: *P.Renderer, rows: u16, cols: u16, t: Theme) void {
    const box_w: u16 = @min(cols -| 4, 60);
    const box_h: u16 = @min(rows -| 6, @as(u16, model.preset_count) + 4);
    if (box_w < 20 or box_h < 4) return;

    const x0: u16 = (cols -| box_w) / 2;
    const y0: u16 = (rows -| box_h) / 2;

    const bg: Style = .{ .bg = .{ .rgb = t.surface1 } };
    r.fillRect(y0, x0, box_h, box_w, .{ .char = ' ', .style = bg });

    const title_s: Style = .{ .bg = .{ .rgb = t.surface1 }, .fg = .{ .rgb = t.text }, .bold = true };
    r.writeStyledText(y0, x0 + 2, "Filter Presets", title_s);

    const hint_s: Style = .{ .bg = .{ .rgb = t.surface1 }, .fg = .{ .rgb = t.overlay } };
    r.writeStyledText(y0 + 1, x0 + 2, "enter:apply a:save d:delete esc:close", hint_s);

    if (model.preset_count == 0) {
        const empty_s: Style = .{ .bg = .{ .rgb = t.surface1 }, .fg = .{ .rgb = t.subtext } };
        r.writeStyledText(y0 + 3, x0 + 2, "No presets saved. Use 'a' to save current filter.", empty_s);
        return;
    }

    var i: u8 = 0;
    while (i < model.preset_count) : (i += 1) {
        const row: u16 = y0 + 3 + i;
        if (row >= y0 + box_h - 1) break;
        const is_sel = i == model.preset_selected;
        const sty: Style = if (is_sel)
            .{ .bg = .{ .rgb = t.mauve }, .fg = .{ .rgb = t.surface0 }, .bold = true }
        else
            .{ .bg = .{ .rgb = t.surface1 }, .fg = .{ .rgb = t.text } };
        if (is_sel) {
            r.fillRect(row, x0 + 1, 1, box_w - 2, .{ .char = ' ', .style = sty });
        }
        const expr = model.presets[i].slice();
        const show = @min(expr.len, @as(usize, box_w) -| 4);
        r.writeStyledText(row, x0 + 2, expr[0..show], sty);
    }
}

fn viewHexDump(model: *Model, r: *P.Renderer, rows: u16, cols: u16) void {
    const t = model.th();
    const pkt = getVisible(model, model.selected) orelse {
        r.writeStyledText(2, 1, "No packet selected", .{ .fg = .{ .rgb = t.subtext } });
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
        r.writeStyledText(1, 1, hs, .{ .fg = .{ .rgb = t.text }, .bold = true });
    }
    drawHLine(r, 2, cols, .{ .fg = .{ .rgb = t.overlay } });

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

    const offset_style: Style = .{ .fg = .{ .rgb = t.overlay } };
    const hex_style: Style = .{ .fg = .{ .rgb = t.blue } };
    const ascii_style: Style = .{ .fg = .{ .rgb = t.green } };
    const dot_style: Style = .{ .fg = .{ .rgb = t.overlay } };

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

fn writeHelpKey(r: *P.Renderer, row: u16, col: u16, key: []const u8, desc: []const u8, hs: Style, hks: Style) u16 {
    r.writeStyledText(row, col, key, hks);
    const after_key: u16 = col + @as(u16, @intCast(key.len));
    r.writeStyledText(row, after_key, ":", hs);
    r.writeStyledText(row, after_key + 1, desc, hs);
    return after_key + @as(u16, @intCast(desc.len)) + 3;
}

fn protoCol(cw: ColumnWidths, cols: u16) u16 {
    return cw.num + cw.time + cw.srcWidth(cols) + cw.dstWidth(cols);
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
    cw: ColumnWidths,
    num: []const u8,
    time_str: []const u8,
    src: []const u8,
    dst: []const u8,
    proto: []const u8,
    length: []const u8,
    sty: Style,
) void {
    var c: u16 = 0;
    writeField(r, row, c, cw.num, num, sty);
    c += cw.num;
    writeField(r, row, c, cw.time, time_str, sty);
    c += cw.time;
    const sw = cw.srcWidth(cols);
    writeField(r, row, c, sw, src, sty);
    c += sw;
    const dw = cw.dstWidth(cols);
    writeField(r, row, c, dw, dst, sty);
    c += dw;
    writeField(r, row, c, cw.proto, proto, sty);
    c += cw.proto;
    writeField(r, row, c, cw.len, length, sty);
}

fn writeField(r: *P.Renderer, row: u16, col: u16, width: u16, text: []const u8, sty: Style) void {
    const max: usize = @min(text.len, @as(usize, width) -| 1);
    r.writeStyledText(row, col, text[0..max], sty);
}

fn drawHLine(r: *P.Renderer, row: u16, cols: u16, sty: Style) void {
    const ch: u21 = if (builtin.os.tag == .windows) '-' else 0x2500;
    var c: u16 = 0;
    while (c < cols) : (c += 1) {
        r.applyCell(row, c, ch, sty);
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

fn writeJsonString(writer: anytype, s: []const u8) !void {
    try writer.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (c < 0x20) {
                    try writer.print("\\u{d:0>4}", .{@as(u16, c)});
                } else {
                    try writer.writeByte(c);
                }
            },
        }
    }
    try writer.writeByte('"');
}

fn writePacketJson(writer: anytype, pkt: *const packet.PacketInfo) !void {
    try writer.writeAll("{\"timestamp_ms\":");
    try writer.print("{d}", .{pkt.timestamp_ms});
    try writer.writeAll(",\"src\":");
    try writeJsonString(writer, pkt.srcAddr());
    try writer.writeAll(",\"dst\":");
    try writeJsonString(writer, pkt.dstAddr());
    try writer.print(",\"src_port\":{d},\"dst_port\":{d}", .{ pkt.src_port, pkt.dst_port });
    try writer.writeAll(",\"protocol\":");
    try writeJsonString(writer, pkt.protocol.name());
    try writer.print(",\"length\":{d}", .{pkt.length});
    if (pkt.ip_ttl > 0) {
        try writer.print(",\"ttl\":{d}", .{pkt.ip_ttl});
    }
    if (pkt.protocol == .tcp and pkt.tcp_flags > 0) {
        var fbuf: [40]u8 = undefined;
        const flags = pkt.tcpFlagsStr(&fbuf);
        try writer.writeAll(",\"tcp_flags\":");
        try writeJsonString(writer, flags);
    }
    if (pkt.dns_name_len > 0) {
        try writer.writeAll(",\"dns\":");
        try writeJsonString(writer, pkt.dnsName());
        try writer.print(",\"dns_response\":{}", .{pkt.dns_is_response});
    }
    if (pkt.tls_sni_len > 0) {
        try writer.writeAll(",\"sni\":");
        try writeJsonString(writer, pkt.sniName());
    }
    if (pkt.http_info_len > 0) {
        try writer.writeAll(",\"http\":");
        try writeJsonString(writer, pkt.httpInfo());
    }
    try writer.writeAll("}\n");
}

fn runJsonMode(handle: capture.CaptureHandle) void {
    const stdout = std.fs.File.stdout();
    var cap_buf: [65536]u8 = undefined;
    var out_buf: [4096]u8 = undefined;
    while (true) {
        const frame = capture.readOne(handle, &cap_buf) catch continue;
        if (frame.len < 14) continue;
        var info = packet.parse(frame) orelse continue;
        info.timestamp_ms = std.time.milliTimestamp();
        var fbs = std.io.fixedBufferStream(&out_buf);
        writePacketJson(fbs.writer(), &info) catch continue;
        stdout.writeAll(fbs.getWritten()) catch return;
    }
}

fn runPcapMode(handle: capture.CaptureHandle, path: []const u8) void {
    var path_buf: [256]u8 = undefined;
    if (path.len >= path_buf.len) {
        std.debug.print("error: output path too long\n", .{});
        return;
    }
    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;

    const file = std.fs.cwd().createFile(path_buf[0..path.len :0], .{}) catch {
        std.debug.print("error: cannot create {s}\n", .{path});
        return;
    };
    defer file.close();

    pcap.writeGlobalHeader(file) catch {
        std.debug.print("error: failed to write pcap header\n", .{});
        return;
    };

    var cap_buf: [65536]u8 = undefined;
    var count: usize = 0;
    while (true) {
        const frame = capture.readOne(handle, &cap_buf) catch continue;
        if (frame.len < 14) continue;
        var info = packet.parse(frame) orelse continue;
        info.timestamp_ms = std.time.milliTimestamp();
        const snap = @min(frame.len, packet.snap_len);
        @memcpy(info.raw[0..snap], frame[0..snap]);
        info.raw_len = @intCast(snap);
        pcap.writePacketRecord(file, &info) catch {
            std.debug.print("error: write failed after {d} packets\n", .{count});
            return;
        };
        count += 1;
    }
}

fn runUpdate() !void {
    std.debug.print("sniff update - checking for latest release...\n", .{});
    if (builtin.os.tag == .windows) {
        // PowerShell: download and run install script
        var child = std.process.Child.init(
            &.{ "powershell", "-NoProfile", "-Command", "irm https://getsniff.sh/install.ps1 | iex" },
            std.heap.page_allocator,
        );
        child.term = .{ .Exited = 0 };
        _ = child.spawnAndWait() catch {
            std.debug.print("error: failed to run powershell installer\n", .{});
            std.process.exit(1);
        };
    } else {
        // POSIX: curl | sh
        var child = std.process.Child.init(
            &.{ "sh", "-c", "curl -fsSL https://getsniff.sh/install | sh" },
            std.heap.page_allocator,
        );
        child.term = .{ .Exited = 0 };
        _ = child.spawnAndWait() catch {
            std.debug.print("error: failed to run install script\n", .{});
            std.process.exit(1);
        };
    }
}

pub fn main() !void {
    var iface_arg: ?[]const u8 = null;
    var list_mode = false;
    var json_mode = false;
    var no_tui = false;
    var write_path: ?[]const u8 = null;

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
        } else if (std.mem.eql(u8, arg, "update")) {
            return runUpdate();
        } else if (std.mem.eql(u8, arg, "--theme")) {
            ai += 1;
            if (ai < argv.len) {
                const name = std.mem.span(argv[ai]);
                for (themes, 0..) |th, idx| {
                    if (std.mem.eql(u8, th.name, name)) {
                        initial_theme_idx = @intCast(idx);
                        break;
                    }
                }
            }
        } else if (std.mem.eql(u8, arg, "--json")) {
            json_mode = true;
        } else if (std.mem.eql(u8, arg, "--no-tui")) {
            no_tui = true;
        } else if (std.mem.eql(u8, arg, "-w")) {
            ai += 1;
            if (ai < argv.len) {
                write_path = std.mem.span(argv[ai]);
            }
        } else if (std.mem.eql(u8, arg, "--columns")) {
            ai += 1;
            if (ai < argv.len) {
                const spec = std.mem.span(argv[ai]);
                if (parseColumnSpec(spec)) |cw| {
                    initial_col_widths = cw;
                    initial_col_widths_set = true;
                }
            }
        } else if (std.mem.eql(u8, arg, "-V") or std.mem.eql(u8, arg, "--version")) {
            std.debug.print("sniff {s}\n", .{version});
            return;
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            std.debug.print(
                \\sniff - terminal packet sniffer
                \\
                \\Usage: sniff [options]
                \\       sniff update
                \\
                \\Options:
                \\  -l, --list         List available network interfaces
                \\  -i <iface>         Capture on a specific interface
                \\  --theme <name>     Color theme: dark (default), light
                \\  --columns <spec>   Set column widths (e.g. num:8,src:24,dst:24)
                \\  --json             Stream packets as NDJSON to stdout (no TUI)
                \\  --no-tui           Capture without TUI (NDJSON to stdout, or pcap with -w)
                \\  -w <file>          Write captured packets to a pcap file (with --no-tui)
                \\  -V, --version      Show version
                \\  -h, --help         Show this help
                \\
                \\Commands:
                \\  update           Download and install the latest release
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

    if (json_mode or no_tui) {
        if (write_path) |path| {
            runPcapMode(capture_handle.?, path);
        } else {
            runJsonMode(capture_handle.?);
        }
        return;
    }

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
