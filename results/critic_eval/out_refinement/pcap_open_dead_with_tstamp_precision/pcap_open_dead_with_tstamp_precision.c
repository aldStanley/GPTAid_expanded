#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    pcap_t *handle;
    int linktype = DLT_EN10MB; // Example: Ethernet link type
    int snaplen = 65535;      // Example: Maximum snapshot length
    u_int precision = PCAP_TSTAMP_PRECISION_MICRO; // Example: Microsecond precision

    // Add the required printf before calling the function
    printf("before pcap_open_dead_with_tstamp_precision\n");
    fflush(stdout);

    handle = pcap_open_dead_with_tstamp_precision(linktype, snaplen, precision);

    if (handle == NULL) {
        // The function itself doesn't provide specific error messages for invalid precision,
        // it defaults to microsecond precision. The only reported failure is memory allocation.
        // For a more informative error, one might check if malloc failed prior to this call,
        // but in this context, we assume pcap_open_dead_with_tstamp_precision is the only
        // relevant API failing here.
        fprintf(stderr, "Calling pcap_open_dead_with_tstamp_precision fail: Memory allocation failed.\n");
        fflush(stderr);
        return 123;
    } else {
        printf("Calling pcap_open_dead_with_tstamp_precision success\n");
        fflush(stdout);
    }

    // Clean up the allocated pcap_t structure.
    // Even though it's a "dead" handle, it was allocated with malloc, so it needs cleanup.
    pcap_close(handle);
    printf("pcap_close called for the dead handle.\n");
    fflush(stdout);

    return 0;
}

