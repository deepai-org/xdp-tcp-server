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

## AWS EC2 Setup

Running XDP on AWS EC2 requires specific considerations due to the ENA (Elastic Network Adapter) driver.

### Quick Start on EC2

```bash
# Install dependencies (Ubuntu 24.04)
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev libelf-dev \
    linux-headers-$(uname -r) linux-tools-common linux-tools-$(uname -r)

# Clone and build
git clone https://github.com/deepai-org/xdp-tcp-server.git
cd xdp-tcp-server
make

# Change port if needed (edit include/common.h, then rebuild)
# #define SERVER_PORT 3456

# Attach to ens5 in SKB mode (required for ENA)
sudo ./xdp_loader -S ens5
```

### Important Notes

1. **SKB Mode Required**: The ENA driver does not support native XDP mode. Always use `-S` flag:
   ```bash
   sudo ./xdp_loader -S ens5    # Works
   sudo ./xdp_loader ens5       # Fails with "Invalid argument"
   ```

2. **Interface Name**: EC2 instances use `ens5` (not `eth0`):
   ```bash
   ip link show  # Find your interface name
   ```

3. **Security Group**: Open the port in your EC2 security group:
   - Type: Custom TCP
   - Port: 3456 (or your configured port)
   - Source: Your IP or 0.0.0.0/0

4. **Local Traffic Does Not Work**: XDP on the physical interface only sees external traffic. Packets from localhost are routed internally by the kernel and never reach `ens5`:
   ```bash
   # This will NOT work (from the same EC2 instance):
   curl http://localhost:3456/
   
   # This WILL work (from your laptop or another machine):
   curl http://<public-ip>:3456/
   ```

### Testing from External Machine

```bash
# Get your EC2 public IP
curl http://169.254.169.254/latest/meta-data/public-ipv4

# From your laptop:
curl http://<public-ip>:3456/
# Expected: HTTP/1.1 200 OK with body "Hi"
```

### Troubleshooting

**"Invalid argument" when loading:**
- Use SKB mode: `sudo ./xdp_loader -S ens5`

**No response to requests:**
- Check security group allows inbound traffic on the port
- Test from an external machine (not localhost)
- Verify XDP is attached: `ip link show ens5` (should show `xdp`)

**Build fails with missing headers:**
```bash
sudo apt-get install linux-headers-$(uname -r)
```

## Routes

The server responds to different paths:

| Path | Response | Description |
|------|----------|-------------|
| `/` | `Hello from XDP\!` | Default greeting |
| `/api` | `{"status":"ok"}` | JSON API response |
| `/health` | `OK` | Health check endpoint |

```bash
curl http://<ip>:3456/        # Hello from XDP\!
curl http://<ip>:3456/api     # {"status":"ok"}
curl http://<ip>:3456/health  # OK
```

**Testing Tip**: When testing on the EC2 instance itself, use the public IP instead of localhost:

```bash
# This works (goes through network, XDP sees it):
curl http://$(curl -s -H "X-aws-ec2-metadata-token: $(curl -s -X PUT http://169.254.169.254/latest/api/token -H X-aws-ec2-metadata-token-ttl-seconds:21600)" http://169.254.169.254/latest/meta-data/public-ipv4):3456/

# This does NOT work (localhost routes internally, bypasses XDP):
curl http://localhost:3456/
```
