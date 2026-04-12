# sniff

A terminal packet sniffer for Linux, written in Zig. Think Wireshark, but in your terminal.

![Zig](https://img.shields.io/badge/Zig-0.15-orange)
![License](https://img.shields.io/badge/license-MIT-blue)

## Features

- **Live capture** via raw sockets (`AF_PACKET`) - no libpcap dependency
- **Scrollable packet list** with columns: #, Time, Source, Destination, Protocol, Length
- **Detail pane** showing addresses, ports, TTL, TCP flags
- **Protocol colors** - TCP (green), UDP (blue), ICMP (yellow), ARP (purple)
- **Filter by protocol** - cycle through TCP/UDP/ICMP/ARP
- **Pause/resume** capture on the fly
- **50k packet ring buffer** with automatic eviction

Built on [glymmi/glym](https://github.com/glymmi/glym), a TUI framework for Zig using the MVU (Model-View-Update) pattern.

## Requirements

- Zig 0.15+
- Linux (uses `AF_PACKET` raw sockets)
- Root or `CAP_NET_RAW` capability

## Build and run

```sh
zig build
sudo zig-out/bin/sniff
```

Press any key to start capturing. Packets appear in real time.

## Key bindings

| Key        | Action                 |
|------------|------------------------|
| `q` / C-c  | Quit                   |
| `p`        | Pause / resume capture |
| `f`        | Cycle protocol filter  |
| Up / Down  | Select packet          |
| PgUp / PgDn | Page scroll          |
| `g` / `G`  | Jump to top / bottom   |

## License

MIT
