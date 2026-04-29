#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const char *device = pcap_lookupdev(errbuf); // Find a suitable device

    if (device == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }

    // Open the capture device without activating it immediately.
    // We use pcap_open_live with a snaplen and a read_timeout.
    // The activation happens implicitly when we start capturing or setting filters.
    // To allow pcap_set_buffer_size to be called, we need to ensure it's not activated.
    handle = pcap_open_live(device, BUFSIZ, 0, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        fflush(stdout);
        return 123;
    }

    // Task 1: Invocation Specification Analysis
    // The caller must ensure that the pcap_t *p argument is a valid,
    // unactivated pcap handle. The buffer_size must be a positive integer.
    // The function returns PCAP_ERROR_ACTIVATED if the handle is already activated.
    // It silently ignores non-positive buffer_size values and returns 0.
    // For valid positive buffer_size, it sets the buffer size and returns 0.

    // Task2: Complete Code

    int desired_buffer_size = 1024 * 1024; // Example: 1MB buffer size

    printf("before pcap_set_buffer_size\n");
    fflush(stdout);

    int result = pcap_set_buffer_size(handle, desired_buffer_size);

    if (result == 0) {
        printf("Calling pcap_set_buffer_size success\n");
        fflush(stdout);
    } else if (result == PCAP_ERROR_ACTIVATED) {
        fprintf(stderr, "Calling pcap_set_buffer_size fail: The pcap handle is already activated.\n");
        fflush(stdout);
        pcap_close(handle); // Close the handle before exiting
        return 123;
    } else {
        fprintf(stderr, "Calling pcap_set_buffer_size fail: Unknown error occurred.\n");
        fflush(stdout);
        pcap_close(handle); // Close the handle before exiting
        return 123;
    }

    // To avoid the "already activated" error in subsequent calls,
    // we will not perform operations that activate the handle, like compiling/setting filters
    // or starting a capture loop, in this minimal example.
    // If we were to do so, we would need to ensure pcap_set_buffer_size is called
    // *before* those activation steps.

    // Clean up
    pcap_close(handle);

    return 0;
}

