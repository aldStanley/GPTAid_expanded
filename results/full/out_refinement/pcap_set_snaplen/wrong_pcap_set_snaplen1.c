#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int snaplen_value = 1024; // Example snapshot length
    int result;

    // Task2.1 & 2.3: Initialize libpcap handle.
    // We need an activated pcap handle to demonstrate setting snaplen.
    // For non-interactive and non-infinite loop, we'll open a device for live capture,
    // but won't start the capture loop.
    // We'll choose the first available network interface.
    char *dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Found device: %s\n", dev);
    fflush(stdout);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Successfully opened device for live capture.\n");
    fflush(stdout);

    // Task2.6: Add the required printf before the function call.
    printf("before pcap_set_snaplen\n");
    fflush(stdout);

    // VIOLATION: Pass a NULL pointer to pcap_set_snaplen, mimicking the violation example.
    // The rule is: The `pcap_t` pointer must point to a valid and uninitialized capture handle.
    // Passing NULL violates the "valid" part of the rule.
    pcap_t *null_handle = NULL;
    result = pcap_set_snaplen(null_handle, snaplen_value);

    // Task2.3: Check the call status of pcap_set_snaplen.
    if (result == 0) {
        printf("Calling pcap_set_snaplen success\n");
        fflush(stdout);
    } else {
        // This branch is expected to be taken due to the NULL pointer.
        printf("Calling pcap_set_snaplen fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_set_snaplen failed with error code: %d\n", result);
        fflush(stdout);
        // When passing NULL to pcap functions, pcap_geterr might not be reliable or might return an empty string.
        // The error code itself is usually sufficient for this type of violation.
        // fprintf(stderr, "pcap error: %s\n", pcap_geterr(handle)); // This would be problematic if handle is also NULL or invalid
        fflush(stdout);
        // We don't close 'handle' here because it was successfully opened, but we are testing the NULL pointer violation.
        // If handle was NULL, we would have exited earlier.
        if (handle != NULL) {
            pcap_close(handle);
            printf("Successfully closed pcap handle.\n");
            fflush(stdout);
        }
        return 123;
    }

    // Task2.3: Check the status of other API calls.
    // For demonstration, we'll also check pcap_close.
    if (handle != NULL) {
        pcap_close(handle);
        printf("Successfully closed pcap handle.\n");
        fflush(stdout);
    }

    return 0;
}

