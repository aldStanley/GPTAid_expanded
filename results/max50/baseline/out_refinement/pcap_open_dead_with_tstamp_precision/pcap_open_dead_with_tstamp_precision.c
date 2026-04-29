#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    pcap_t *handle;
    int linktype = DLT_EN10MB; // Example link-type: Ethernet
    int snaplen = 96;          // Example snapshot length
    u_int precision = PCAP_TSTAMP_PRECISION_MICRO; // Example timestamp precision

    printf("before pcap_open_dead_with_tstamp_precision\n");
    fflush(stdout);

    handle = pcap_open_dead_with_tstamp_precision(linktype, snaplen, precision);

    if (handle == NULL) {
        fprintf(stderr, "Calling pcap_open_dead_with_tstamp_precision fail\n");
        fflush(stderr);
        return 123;
    } else {
        printf("Calling pcap_open_dead_with_tstamp_precision success\n");
        fflush(stdout);
    }

    // In a real scenario, you would use the 'handle' for other pcap operations.
    // For this example, we just demonstrate the opening and then clean up.

    // Clean up the handle
    pcap_close(handle);
    printf("pcap_close called successfully.\n");
    fflush(stdout);

    return 0;
}

