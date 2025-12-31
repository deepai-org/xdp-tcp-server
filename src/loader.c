// SPDX-License-Identifier: GPL-2.0
/*
 * XDP TCP Server Loader
 * Loads and attaches the XDP program to a network interface
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "../include/common.h"

static volatile int keep_running = 1;
static int ifindex = 0;
static struct bpf_object *obj = NULL;

static void sig_handler(int sig)
{
    keep_running = 0;
}

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

static void print_stats(int stats_fd)
{
    struct stats total = {0};
    __u32 key = 0;
    int num_cpus = libbpf_num_possible_cpus();

    if (num_cpus < 0) {
        fprintf(stderr, "Failed to get number of CPUs\n");
        return;
    }

    struct stats *values = calloc(num_cpus, sizeof(struct stats));
    if (!values) {
        fprintf(stderr, "Failed to allocate memory for stats\n");
        return;
    }

    if (bpf_map_lookup_elem(stats_fd, &key, values) == 0) {
        for (int i = 0; i < num_cpus; i++) {
            total.packets_received += values[i].packets_received;
            total.packets_sent += values[i].packets_sent;
            total.syn_received += values[i].syn_received;
            total.connections_established += values[i].connections_established;
            total.connections_closed += values[i].connections_closed;
            total.bytes_received += values[i].bytes_received;
            total.bytes_sent += values[i].bytes_sent;
            total.errors += values[i].errors;
        }

        printf("\033[2J\033[H");  /* Clear screen */
        printf("=== XDP TCP Server Statistics ===\n\n");
        printf("Packets received:        %llu\n", total.packets_received);
        printf("Packets sent:            %llu\n", total.packets_sent);
        printf("SYN packets:             %llu\n", total.syn_received);
        printf("Connections established: %llu\n", total.connections_established);
        printf("Connections closed:      %llu\n", total.connections_closed);
        printf("Bytes received:          %llu\n", total.bytes_received);
        printf("Bytes sent:              %llu\n", total.bytes_sent);
        printf("Errors:                  %llu\n", total.errors);
        printf("\nPress Ctrl+C to stop...\n");
    }

    free(values);
}

static void cleanup(void)
{
    if (ifindex > 0) {
        printf("\nDetaching XDP program from interface...\n");
        bpf_xdp_detach(ifindex, 0, NULL);
    }
    if (obj) {
        bpf_object__close(obj);
    }
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [OPTIONS] <interface>\n\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -S          Use SKB mode (generic XDP)\n");
    fprintf(stderr, "  -N          Use native mode (driver XDP)\n");
    fprintf(stderr, "  -O          Use offload mode (hardware XDP)\n");
    fprintf(stderr, "  -F          Force attach (replace existing program)\n");
    fprintf(stderr, "  -h          Show this help message\n");
    fprintf(stderr, "\nDefault mode is native (driver) mode.\n");
    fprintf(stderr, "Server listens on port %d\n", SERVER_PORT);
}

int main(int argc, char **argv)
{
    struct bpf_program *prog;
    int prog_fd, stats_fd;
    int opt;
    __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
    int attach_mode = XDP_FLAGS_DRV_MODE;

    while ((opt = getopt(argc, argv, "SNOFh")) != -1) {
        switch (opt) {
        case 'S':
            attach_mode = XDP_FLAGS_SKB_MODE;
            break;
        case 'N':
            attach_mode = XDP_FLAGS_DRV_MODE;
            break;
        case 'O':
            attach_mode = XDP_FLAGS_HW_MODE;
            break;
        case 'F':
            xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: Interface name required\n");
        usage(argv[0]);
        return 1;
    }

    const char *ifname = argv[optind];
    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Error: Interface '%s' not found\n", ifname);
        return 1;
    }

    xdp_flags |= attach_mode;

    /* Set up signal handlers */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    atexit(cleanup);

    /* Set libbpf print callback */
    libbpf_set_print(libbpf_print_fn);

    /* Open and load BPF object */
    printf("Loading XDP TCP server...\n");

    /* Set up open options to relax BTF requirements */
    LIBBPF_OPTS(bpf_object_open_opts, open_opts,
        .relaxed_maps = true,
    );

    obj = bpf_object__open_file("xdp_tcp_server.o", &open_opts);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Error: Failed to open BPF object\n");
        obj = NULL;
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Error: Failed to load BPF object\n");
        return 1;
    }

    /* Find the XDP program */
    prog = bpf_object__find_program_by_name(obj, "xdp_tcp_server");
    if (!prog) {
        fprintf(stderr, "Error: Failed to find XDP program\n");
        return 1;
    }

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Error: Failed to get program FD\n");
        return 1;
    }

    /* Get statistics map FD */
    stats_fd = bpf_object__find_map_fd_by_name(obj, "statistics");
    if (stats_fd < 0) {
        fprintf(stderr, "Warning: Statistics map not found\n");
    }

    /* Attach XDP program */
    printf("Attaching XDP program to %s (ifindex %d)...\n", ifname, ifindex);

    if (bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL) < 0) {
        fprintf(stderr, "Error: Failed to attach XDP program\n");
        fprintf(stderr, "Try running with -S for SKB/generic mode\n");
        return 1;
    }

    printf("XDP TCP server running on port %d\n", SERVER_PORT);
    printf("Mode: %s\n",
           attach_mode == XDP_FLAGS_SKB_MODE ? "SKB (generic)" :
           attach_mode == XDP_FLAGS_HW_MODE ? "Hardware (offload)" :
           "Native (driver)");

    /* Main loop - print statistics */
    while (keep_running) {
        if (stats_fd >= 0) {
            print_stats(stats_fd);
        }
        sleep(1);
    }

    printf("\nShutting down...\n");
    return 0;
}
