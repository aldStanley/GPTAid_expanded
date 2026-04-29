#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    pcap_t *handle;
    int linktype = DLT_EN10MB; // Example: Ethernet link type
    int snaplen = 96;        // Example: Snapshot length
    u_int precision = PCAP_TSTAMP_PRECISION_NANO; // Example: Nanosecond precision

    // Output before the API call
    printf("before pcap_open_dead_with_tstamp_precision\n");
    fflush(stdout);

    // Call the function
    handle = pcap_open_dead_with_tstamp_precision(linktype, snaplen, precision);

    // Check the status of the API call
    if (handle == NULL) {
        fprintf(stderr, "Calling pcap_open_dead_with_tstamp_precision fail\n");
        fflush(stderr);
        return 123;
    } else {
        printf("Calling pcap_open_dead_with_tstamp_precision success\n");
        fflush(stdout);
    }

    // You can now use the 'handle' for other dead capture operations if needed.
    // For this example, we'll just clean it up.

    // Clean up the pcap_t structure
    pcap_close(handle);
    printf("pcap_close called successfully.\n");
    fflush(stdout);

    return 0;
}

