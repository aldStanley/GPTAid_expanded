#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


// Define PCAP_ERRBUF_SIZE if it's not implicitly defined by pcap.h
#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE 256
#endif

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *device_name = NULL; // Can be NULL to try "any" device or a specific interface name like "eth0"

    // For demonstration, let's try to get a default device if none is specified.
    // In a real non-interactive scenario, you might hardcode a device or rely on a configuration.
    if (device_name == NULL) {
        char *default_dev = pcap_lookupdev(errbuf);
        if (default_dev == NULL) {
            fprintf(stderr, "Failed to find a default device: %s\n", errbuf);
            fflush(stdout);
            return 123;
        }
        device_name = default_dev;
        printf("Using default device: %s\n", device_name);
        fflush(stdout);
    }

    printf("before pcap_create\n");
    fflush(stdout);

    handle = pcap_create(device_name, errbuf);

    if (handle == NULL) {
        printf("Calling pcap_create fail\n");
        fflush(stdout);
        // The function pcap_create itself should have populated errbuf on failure
        fprintf(stderr, "Error in pcap_create: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }

    printf("Calling pcap_create success\n");
    fflush(stdout);

    // Now that pcap_create succeeded, we need to activate the handle
    // before we can use it for capturing. pcap_activate is the function
    // that actually sets up the capture session.
    int activation_status = pcap_activate(handle);
    if (activation_status != 0) {
        fprintf(stderr, "Error activating the capture handle: %s\n", pcap_geterr(handle));
        fflush(stdout);
        pcap_close(handle); // Clean up the handle
        return 123;
    }

    // At this point, 'handle' is ready for packet capture.
    // For this non-interactive example, we'll just demonstrate success and then close.
    printf("Pcap handle created and activated successfully.\n");
    fflush(stdout);

    // Clean up the pcap handle
    pcap_close(handle);
    printf("Pcap handle closed.\n");
    fflush(stdout);

    return 0;
}

