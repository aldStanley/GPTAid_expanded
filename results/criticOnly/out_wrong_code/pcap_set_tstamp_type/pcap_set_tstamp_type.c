#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int result;
    const char *device = pcap_lookupdev(errbuf);

    if (device == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }

    // Try to open a live capture handle
    // We'll use a snaplen of 65535 and promiscuous mode enabled
    handle = pcap_open_live(device, 65535, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        fflush(stdout);
        return 123;
    }

    printf("Device opened successfully.\n");
    fflush(stdout);

    // --- Setting the timestamp type ---
    // Let's try to set the timestamp type to PCAP_TSTAMP_HOST
    // This is generally the safest and most compatible option.
    // You might experiment with other PCAP_TSTAMP_* constants if supported.
    int desired_tstamp_type = PCAP_TSTAMP_HOST;

    printf("before pcap_set_tstamp_type\n");
    fflush(stdout);

    result = pcap_set_tstamp_type(handle, desired_tstamp_type);

    if (result == 0) {
        printf("Calling pcap_set_tstamp_type success\n");
        fflush(stdout);
    } else if (result == PCAP_ERROR_ACTIVATED) {
        fprintf(stderr, "Calling pcap_set_tstamp_type fail: The pcap handle is already activated.\n");
        fflush(stdout);
        pcap_close(handle);
        return 123;
    } else if (result == PCAP_WARNING_TSTAMP_TYPE_NOTSUP) {
        fprintf(stderr, "Calling pcap_set_tstamp_type fail: The requested timestamp type is not supported.\n");
        fflush(stdout);
        // You might want to try a different type here if supported, or just exit.
        // For this example, we'll exit.
        pcap_close(handle);
        return 123;
    } else {
        // Generic error handling for other negative return codes
        fprintf(stderr, "Calling pcap_set_tstamp_type fail with error code: %d\n", result);
        fflush(stdout);
        pcap_close(handle);
        return 123;
    }

    // --- Other pcap operations would go here ---
    // For this example, we'll just close the handle and exit.
    // We are not performing any packet capture to keep the code non-interactive
    // and avoid infinite loops.

    pcap_close(handle);
    printf("Pcap handle closed.\n");
    fflush(stdout);

    return 0;
}

