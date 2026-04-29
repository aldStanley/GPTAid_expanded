#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


// Define a custom error code for this program
#define CUSTOM_ERROR_CODE 123

// Definition of the pcap_setfilter function as provided in the prompt
// This function itself is not directly called in the example, but its behavior
// is what we're testing. The libpcap library's internal implementation will
// use a function similar to this.
// For the purpose of generating an example that *uses* the filter, we need to
// rely on the standard libpcap API, which we assume has this internal structure.
// The standard API call for setting the filter is also `pcap_setfilter`.
// The prompt implies we are to *test* or *use* a function named `pcap_setfilter`
// that has this structure. The most direct way to achieve this is to use the
// standard libpcap `pcap_setfilter` function, which aligns with the provided snippet.

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
    // This is the function that embodies the logic from the prompt.
    printf("before pcap_setfilter\n");
    fflush(stdout);

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Calling pcap_setfilter fail: %s\n", pcap_geterr(handle));
        fflush(stdout);
        pcap_freecode(&fp); // Free the compiled filter program
        pcap_close(handle); // Close the capture handle
        return CUSTOM_ERROR_CODE;
    }

    // If pcap_setfilter returns 0 (or any non-negative value indicating success)
    printf("Calling pcap_setfilter success\n");
    fflush(stdout);

    // 4. Cleanup
    pcap_freecode(&fp); // Free the compiled filter program
    pcap_close(handle); // Close the capture handle
    printf("Cleaned up resources.\n");
    fflush(stdout);

    return 0; // Indicate successful execution
}

