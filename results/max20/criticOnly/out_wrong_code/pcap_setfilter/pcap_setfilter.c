#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program filter_program;

    // --- Setup for pcap_setfilter ---

    // 1. Open a network device. For a non-interactive, non-looping example,
    // we'll try to open the first available device. In a real application,
    // you would likely want to select a specific device or listen to a file.
    // Using "eth0" as a common default, but this might need to be adjusted
    // based on the actual available network interfaces on the system.
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device 'eth0': %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Successfully opened network device.\n");
    fflush(stdout);

    // 2. Compile a filter expression. A simple "tcp" filter for demonstration.
    // In a real scenario, you would get this from user input or a configuration.
    const char *filter_expr = "tcp";
    if (pcap_compile(handle, &filter_program, filter_expr, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter '%s': %s\n", filter_expr, pcap_geterr(handle));
        fflush(stdout);
        pcap_close(handle);
        return 123;
    }
    printf("Successfully compiled filter expression.\n");
    fflush(stdout);

    // --- Task2: Call pcap_setfilter ---

    printf("before pcap_setfilter\n");
    fflush(stdout);

    // The actual call to the pcap_setfilter function.
    if (pcap_setfilter(handle, &filter_program) == -1) {
        fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(handle));
        fflush(stdout);
        // Free the compiled filter program
        pcap_freecode(&filter_program);
        pcap_close(handle);
        printf("Calling pcap_setfilter fail\n");
        fflush(stdout);
        return 123;
    }

    printf("Calling pcap_setfilter success\n");
    fflush(stdout);

    // --- Cleanup ---
    // Free the compiled filter program
    pcap_freecode(&filter_program);
    // Close the capture handle
    pcap_close(handle);
    printf("Successfully cleaned up resources.\n");
    fflush(stdout);

    return 0;
}

