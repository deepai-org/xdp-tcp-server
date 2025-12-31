# XDP TCP Server

A full TCP server running entirely in kernel mode using XDP (eXpress Data Path) and eBPF. This implementation achieves **zero context switches** - packets never reach user space, and no process is ever woken up to handle connections.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Network Card                          │
└───────────────────────────┬─────────────────────────────────┘
                            │ Packet arrives
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                     XDP Hook (Driver)                        │
│  ┌───────────────────────────────────────────────────────┐  │
│  │              xdp_tcp_server.o (BPF)                   │  │
│  │                                                       │  │
│  │  1. Parse Ethernet/IP/TCP headers                     │  │
│  │  2. Check if destined for port 8080                   │  │
│  │  3. Lookup/create session in BPF map                  │  │
│  │  4. Handle TCP state machine:                         │  │
│  │     - SYN → Send SYN-ACK                              │  │
│  │     - ACK → Establish connection                      │  │
│  │     - DATA → Process & send response                  │  │
│  │     - FIN → Close connection                          │  │
│  │  5. XDP_TX → Transmit response                        │  │
│  └───────────────────────────────────────────────────────┘  │
└───────────────────────────┬─────────────────────────────────┘
                            │ XDP_TX (response sent)
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                        Network Card                          │
└─────────────────────────────────────────────────────────────┘

Note: Packets NEVER reach the Linux network stack (sk_buff)
      No user-space process is involved
      Zero context switches
```

## Components

### BPF Maps (Kernel "Socket" Storage)

- **sessions**: Hash map storing TCP connection state (10,000 max connections)
- **statistics**: Per-CPU array for lock-free statistics

### TCP State Machine

The XDP program implements a complete TCP state machine:

1. **LISTEN** → **SYN_RCVD**: Receive SYN, send SYN-ACK
2. **SYN_RCVD** → **ESTABLISHED**: Receive ACK, connection ready
3. **ESTABLISHED**: Handle data, send responses
4. **CLOSE_WAIT** → **LAST_ACK**: Receive FIN, send FIN-ACK
5. **LAST_ACK** → **CLOSED**: Receive final ACK, remove session

## Building

### Prerequisites

```bash
# Install dependencies (Ubuntu/Debian)
make deps

# Or manually:
sudo apt-get install clang llvm libbpf-dev libelf-dev \
    linux-headers-$(uname -r) linux-tools-$(uname -r)
```

### Compile

```bash
make
```

This produces:
- `xdp_tcp_server.o` - The BPF program
- `xdp_loader` - User-space loader

## Usage

### Basic Usage

```bash
# Attach to interface (requires root)
sudo ./xdp_loader eth0

# Use SKB mode if native mode fails
sudo ./xdp_loader -S eth0
```

### Testing

```bash
# From another terminal or machine:
curl http://<server-ip>:8080/

# Expected response:
# Hello, XDP!
```

### XDP Modes

| Mode | Flag | Description |
|------|------|-------------|
| Native | `-N` | Runs in NIC driver (fastest, requires driver support) |
| SKB | `-S` | Runs on sk_buff (slower, works everywhere) |
| Offload | `-O` | Runs on NIC hardware (fastest, requires special NICs) |

## Configuration

Edit `include/common.h` to change:

```c
#define SERVER_PORT 8080      // Listen port
#define MAX_SESSIONS 10000    // Max concurrent connections
#define WINDOW_SIZE 65535     // TCP window size
```

## Limitations

1. **No TCP Options**: Window scaling, SACK, timestamps not implemented
2. **No Congestion Control**: No slow start, AIMD, etc.
3. **No Retransmission**: Lost packets are not retried (would need BPF timers)
4. **No Fragmentation**: Responses must fit in single MTU
5. **Simple Application**: Fixed HTTP response only

## Performance Characteristics

- **Latency**: Sub-microsecond (no kernel bypass, direct NIC)
- **Throughput**: Limited only by NIC line rate
- **CPU**: Minimal - no interrupts, no scheduler involvement
- **Memory**: BPF maps only (~1MB for 10K sessions)

## Files

```
tcp/
├── Makefile              # Build system
├── README.md             # This file
├── include/
│   └── common.h          # Shared data structures
└── src/
    ├── xdp_tcp_server.c  # BPF program (kernel)
    └── loader.c          # User-space loader
```

## Debugging

```bash
# Check if XDP is attached
ip link show eth0

# View BPF maps
sudo bpftool map list
sudo bpftool map dump name sessions

# View loaded programs
sudo bpftool prog list

# Check kernel logs
sudo dmesg | tail -20

# Trace XDP events
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## License

GPL-2.0
