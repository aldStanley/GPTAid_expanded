#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int major_version;

    // Task2.1: The caller needs to follow the invocation specification:
    // 1. A pcap_t pointer must be obtained and activated before calling pcap_major_version.
    // This means pcap_open_live or pcap_open_offline must be called successfully and
    // the returned handle must be valid and activated.
    // 2. The pcap_t pointer must not be NULL.

    // For this example, we'll demonstrate by opening a live capture.
    // This requires root privileges on Linux.
    const char *device = pcap_lookupdev(errbuf);
    if (device == NULL) {
        fprintf(stderr, "Error finding default device: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Found default device: %s\n", device);
    fflush(stdout);

    // Open a live capture handle.
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening live capture: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("pcap_open_live succeeded.\n");
    fflush(stdout);

    // Task2.6: Add specific printf before calling pcap_major_version
    printf("before pcap_major_version\n");
    fflush(stdout);

    // Task2.1, 2.2, 2.3, 2.4, 2.5: Call pcap_major_version and check status
    // The function pcap_major_version checks if p is activated internally.
    // If handle is NULL or not activated, it will return PCAP_ERROR_NOT_ACTIVATED.
    major_version = pcap_major_version(handle);

    if (major_version < 0) { // pcap_major_version returns negative on error
        // The function returns PCAP_ERROR_NOT_ACTIVATED (-2) if not activated.
        // Other negative values might indicate other internal errors, though
        // for this specific function, PCAP_ERROR_NOT_ACTIVATED is the primary error.
        fprintf(stderr, "Calling pcap_major_version fail. Error code: %d\n", major_version);
        fflush(stdout);
        // We already checked pcap_open_live, so if this fails, it's likely
        // related to the handle's state or an internal pcap error.
        if (major_version == PCAP_ERROR_NOT_ACTIVATED) {
            fprintf(stderr, "The pcap handle is not activated.\n");
            fflush(stdout);
        } else {
            fprintf(stderr, "An unknown error occurred with pcap_major_version.\n");
            fflush(stdout);
        }
        // Clean up pcap handle if it was successfully opened
        if (handle != NULL) {
            pcap_close(handle);
        }
        return 123;
    } else {
        printf("Calling pcap_major_version success\n");
        fflush(stdout);
        printf("Major version of libpcap: %d\n", major_version);
        fflush(stdout);
    }

    // Clean up the pcap handle
    pcap_close(handle);
    printf("pcap_close succeeded.\n");
    fflush(stdout);

    return 0;
}

