#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int major_version;

    // Task2.1: Initialize libpcap. We need an activated pcap_t handle
    // to call pcap_major_version. Opening a device is a common way to activate.
    // We'll try to open the first available device.
    const char *device = pcap_lookupdev(errbuf);
    if (device == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Found default device: %s\n", device);
    fflush(stdout);

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Successfully opened device %s.\n", device);
    fflush(stdout);

    // Task 1: Invocation Specification Analysis:
    // The function `pcap_major_version` checks the `activated` member of the `pcap_t` struct.
    // It returns `PCAP_ERROR_NOT_ACTIVATED` if `p->activated` is false.
    // Therefore, the caller must ensure that the `pcap_t` handle (`p`) is successfully
    // opened and activated before calling `pcap_major_version`.
    // This is achieved by a successful call to `pcap_open_live` or `pcap_create` followed by `pcap_activate`.

    // Task2.6: Add the required printf before calling pcap_major_version
    printf("before pcap_major_version\n");
    fflush(stdout);

    // Task2.2: Call pcap_major_version
    major_version = pcap_major_version(handle);

    // Task2.3 & 2.5: Check the call status and output accordingly
    if (major_version == PCAP_ERROR_NOT_ACTIVATED) {
        printf("Calling pcap_major_version fail\n");
        fflush(stdout);
        fprintf(stderr, "Error: pcap_t handle was not activated before calling pcap_major_version.\n");
        fflush(stdout);
        pcap_close(handle); // Clean up
        return 123;
    } else if (major_version < 0) {
        // pcap_major_version can return negative values on other errors,
        // although PCAP_ERROR_NOT_ACTIVATED is the most common one based on the provided code.
        // For completeness, we check for any negative return value.
        printf("Calling pcap_major_version fail\n");
        fflush(stdout);
        fprintf(stderr, "An unknown error occurred while calling pcap_major_version. Returned: %d\n", major_version);
        fflush(stdout);
        pcap_close(handle); // Clean up
        return 123;
    } else {
        printf("Calling pcap_major_version success\n");
        fflush(stdout);
        printf("Pcap major version is: %d\n", major_version);
        fflush(stdout);
    }

    // Task2.4: Flush stdout after each printf (already done)
    // Task2.2: Non-interactive, no infinite loops (achieved)
    // Task2.7: No file read operations needed for this specific task.
    // Task2.8: Output in the specified format (achieved)

    // Clean up libpcap resources
    pcap_close(handle);
    printf("Closed pcap handle.\n");
    fflush(stdout);

    return 0;
}

