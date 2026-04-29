#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp; // This will hold our compiled filter
    const char *filter_exp = "tcp port 80"; // Example filter expression
    const char *interface = "eth0"; // Replace with your actual network interface

    // 1. Open a device for capturing
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Device opened successfully.\n");
    fflush(stdout);

    // 2. Compile the filter expression
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        fflush(stdout);
        pcap_close(handle);
        return 123;
    }
    printf("Filter compiled successfully.\n");
    fflush(stdout);

    // 3. Set the compiled filter
    printf("before first pcap_setfilter\n");
    fflush(stdout);
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        fflush(stdout);
        pcap_freecode(&fp); // Free the compiled filter
        pcap_close(handle);
        return 123;
    }
    printf("Calling first pcap_setfilter success\n");
    fflush(stdout);

    // VIOLATION: Close the handle and then attempt to use it again.
    pcap_close(handle);
    printf("Device handle closed.\n");
    fflush(stdout);

    printf("before second pcap_setfilter (after closing handle)\n");
    fflush(stdout);
    // Attempt to set the filter again on a closed handle
    if (pcap_setfilter(handle, &fp) == -1) {
        // This is expected to fail, and we will print an error message.
        fprintf(stderr, "Attempted to set filter on closed handle. Error: %s\n", pcap_geterr(handle));
        fflush(stdout);
    } else {
        // This branch should ideally not be reached if the violation is successful.
        printf("Unexpected: Second pcap_setfilter call succeeded on a closed handle.\n");
        fflush(stdout);
    }

    // Clean up
    pcap_freecode(&fp);
    // pcap_close(handle); // handle is already closed
    printf("Cleaned up resources.\n");
    fflush(stdout);

    return 0;
}

