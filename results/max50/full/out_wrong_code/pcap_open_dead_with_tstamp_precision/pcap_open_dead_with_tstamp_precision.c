#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    pcap_t *handle;
    int linktype = DLT_EN10MB; // Example: Ethernet link type
    int snaplen = 65535;      // Example: Max snapshot length
    u_int precision = PCAP_TSTAMP_PRECISION_NANO; // Example: Nanosecond precision

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

    // In a real application, you might then use this handle for testing,
    // or to pass to other libpcap functions that accept a pcap_t.
    // For this example, we'll just clean up.

    // Clean up the dead handle
    pcap_close(handle); // pcap_close will call pcap_cleanup_dead internally

    return 0;
}

