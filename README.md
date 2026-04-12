# sniff

A cross-platform terminal packet sniffer written in Zig. Think Wireshark, but in your terminal.

![Zig](https://img.shields.io/badge/Zig-0.15-orange)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Linux%20|%20macOS%20|%20Windows-lightgrey)

## Features

- **Live capture** - no external dependencies on Linux and macOS
- **Scrollable packet list** with columns: #, Time, Source, Destination, Protocol, Length
- **Detail pane** showing addresses, ports, TTL, TCP flags
- **Protocol colors** - TCP (green), UDP (blue), ICMP (yellow), ARP (purple)
- **Filter by protocol** - cycle through TCP/UDP/ICMP/ARP
- **Pause/resume** capture on the fly
- **50k packet ring buffer** with automatic eviction

Built on [glymmi/glym](https://github.com/glymmi/glym), a TUI framework for Zig using the MVU (Model-View-Update) pattern.

## Platform support

| Platform | Capture backend            | Extra dependency |
|----------|---------------------------|------------------|
| Linux    | AF_PACKET raw socket       | None             |
| macOS    | BPF (`/dev/bpfN` on en0)  | None             |
| Windows  | Npcap (`wpcap.dll`)        | [Npcap](https://npcap.com) |

## Requirements

- Zig 0.15+
- Root / sudo (Linux, macOS) or Administrator (Windows)
- Windows only: [Npcap](https://npcap.com) installed

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
