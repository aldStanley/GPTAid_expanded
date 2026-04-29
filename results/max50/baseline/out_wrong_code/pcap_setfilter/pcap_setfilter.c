#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


// Define a custom error code for pcap_setfilter failure
#define PCAP_SETFILTER_ERROR_CODE 123

int main() {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp; // To store compiled filter program
    const char *filter_exp;
    const char *interface = "eth0"; // Replace with a valid interface on your system

    // 1. Open a live capture handle
    // For this example, we'll try to open a live interface.
    // In a real-world scenario, you might want to handle cases where the interface is not found or unavailable.
    printf("Attempting to open pcap handle on interface %s\n", interface);
    fflush(stdout);

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", interface, errbuf);
        fflush(stderr);
        return 123; // Using the specified exit code for general failure
    }
    printf("Successfully opened pcap handle.\n");
    fflush(stdout);

    // 2. Compile the filter expression
    // Example filter: capture only TCP packets
    filter_exp = "tcp";
    printf("Compiling filter expression: \"%s\"\n", filter_exp);
    fflush(stdout);

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        fflush(stderr);
        pcap_close(handle);
        return 123;
    }
    printf("Filter compiled successfully.\n");
    fflush(stdout);

    // 3. Set the compiled filter
    printf("before pcap_setfilter\n");
    fflush(stdout);

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Calling pcap_setfilter fail: %s\n", pcap_geterr(handle));
        fflush(stderr);
        pcap_freecode(&fp); // Free the compiled filter
        pcap_close(handle); // Close the pcap handle
        return PCAP_SETFILTER_ERROR_CODE; // Use the specific error code
    }

    printf("Calling pcap_setfilter success\n");
    fflush(stdout);

    // 4. Cleanup
    pcap_freecode(&fp); // Free the compiled filter
    pcap_close(handle); // Close the pcap handle
    printf("Pcap handle closed and filter freed.\n");
    fflush(stdout);

    return 0; // Success
}

