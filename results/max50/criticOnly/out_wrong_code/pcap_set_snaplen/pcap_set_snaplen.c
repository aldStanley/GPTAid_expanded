#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int snapshot_len = 1024; // Example snapshot length

    // Task2.1: Call pcap_open_live with appropriate parameters.
    // For a non-interactive example, we need to ensure the handle is not activated
    // before calling pcap_set_snaplen. pcap_open_live itself does not activate.
    handle = pcap_open_live("eth0", BUFSIZ, 0, 1000, errbuf); // promisc=0 to avoid immediate activation
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        fflush(stderr);
        return 123;
    }
    printf("Network device opened successfully.\n");
    fflush(stdout);

    // Task2.6: Add the specified printf before calling pcap_set_snaplen
    printf("before pcap_set_snaplen\n");
    fflush(stdout);

    // Task2.1: Call pcap_set_snaplen, respecting its invocation specification.
    // The function returns PCAP_ERROR_ACTIVATED if the handle is already activated.
    // By setting promisc to 0 in pcap_open_live, we prevent immediate activation.
    int result = pcap_set_snaplen(handle, snapshot_len);

    // Task2.3: Check the call status and output messages.
    if (result == 0) {
        printf("Calling pcap_set_snaplen success\n");
        fflush(stdout);
    } else {
        printf("Calling pcap_set_snaplen fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_set_snaplen failed with error code: %d\n", result);
        fflush(stderr);
        // The function code indicates PCAP_ERROR_ACTIVATED.
        if (result == PCAP_ERROR_ACTIVATED) {
            fprintf(stderr, "Error: The pcap handle is already activated.\n");
            fflush(stderr);
        } else {
            // Fallback for other potential errors, though less likely here.
            fprintf(stderr, "An unknown error occurred with pcap_set_snaplen.\n");
            fflush(stderr);
        }
        pcap_close(handle);
        return 123;
    }

    // Close the pcap handle
    pcap_close(handle);
    printf("Pcap handle closed.\n");
    fflush(stdout);

    return 0;
}

