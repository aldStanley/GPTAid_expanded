#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




// Define a custom error code for this program
#define CUSTOM_ERROR_CODE 123

int main() {
    pcap_t *handle; // Packet capture handle
    char errbuf[PCAP_ERRBUF_SIZE]; // Error buffer for libpcap
    struct bpf_program fp; // Compiled filter program
    const char *filter_exp = "tcp port 80"; // Example filter expression
    // Using a loopback interface for common availability and less disruptive testing.
    // You might need to change this to a valid interface on your system, e.g., "eth0", "wlan0".
    // If you are testing with a file, you would use pcap_open_offline.
    const char *interface = "lo";

    // 1. Open a network interface for live capture
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        fflush(stdout);
        return CUSTOM_ERROR_CODE;
    }
    printf("Successfully opened network device %s.\n", interface);
    fflush(stdout);

    // 2. Compile the filter expression
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        fflush(stdout);
        pcap_close(handle);
        return CUSTOM_ERROR_CODE;
    }
    printf("Successfully compiled filter expression '%s'.\n", filter_exp);
    fflush(stdout);

    // 3. Call pcap_setfilter (the actual API call we are testing)
    printf("before first pcap_setfilter\n");
    fflush(stdout);

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "First pcap_setfilter call failed: %s\n", pcap_geterr(handle));
        fflush(stdout);
        pcap_freecode(&fp); // Free the compiled filter program
        pcap_close(handle); // Close the capture handle
        return CUSTOM_ERROR_CODE;
    }

    printf("First pcap_setfilter call success\n");
    fflush(stdout);

    // --- VIOLATION START ---
    // Close the capture handle
    pcap_close(handle);
    printf("Closed the pcap handle.\n");
    fflush(stdout);

    // Attempt to set the filter again on the closed handle
    printf("Attempting to call pcap_setfilter on a closed handle...\n");
    fflush(stdout);

    // This call is expected to fail or have undefined behavior,
    // as the handle has already been closed.
    if (pcap_setfilter(handle, &fp) == -1) {
        // The error message might vary depending on the libpcap implementation,
        // but it should indicate an invalid handle or a similar issue.
        fprintf(stderr, "Second pcap_setfilter call (on closed handle) failed as expected: %s\n", pcap_geterr(handle));
        fflush(stdout);
    } else {
        // This branch should ideally not be reached if the violation is effective.
        fprintf(stderr, "Second pcap_setfilter call (on closed handle) unexpectedly succeeded.\n");
        fflush(stdout);
    }
    // --- VIOLATION END ---

    // 4. Cleanup
    // Note: pcap_freecode(&fp) is still called here, but it's important to note
    // that the handle is already closed. If the second pcap_setfilter call
    // had succeeded unexpectedly, this would be a valid cleanup step.
    // However, in the context of demonstrating the violation, the primary issue
    // is the use of the closed handle.
    pcap_freecode(&fp); // Free the compiled filter program
    // pcap_close(handle); // This would be a double close if not already closed.
    printf("Cleaned up resources (filter code).\n");
    fflush(stdout);

    return 0; // Indicate successful execution (or at least program completion)
}

