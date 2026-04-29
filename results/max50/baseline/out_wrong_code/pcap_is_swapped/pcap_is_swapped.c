#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int result;
    pcap_if_t *alldevs, *dev;
    char dev_name[256];

    // Task2.1: Initialize pcap. We need an activated pcap handle to call pcap_is_swapped.
    // The function `pcap_is_swapped` checks `!p->activated`.
    // If the handle is not activated, it returns PCAP_ERROR_NOT_ACTIVATED.
    // The most reliable way to test this is to create a handle but *not* activate it,
    // or to attempt activation and have it fail.

    // Find all network devices.
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding network devices: %s\n", errbuf);
        fflush(stderr);
        return 123;
    }

    // If no devices are found, we cannot proceed to create a handle.
    if (alldevs == NULL) {
        fprintf(stderr, "No network devices found on this system.\n");
        fflush(stderr);
        return 123;
    }

    // Use the first device found.
    strncpy(dev_name, alldevs->name, sizeof(dev_name) - 1);
    dev_name[sizeof(dev_name) - 1] = '\0'; // Ensure null termination

    // Free the device list as we've got the name.
    pcap_freealldevs(alldevs);

    // Create a pcap handle for the chosen device.
    // Crucially, we are NOT calling pcap_activate() immediately.
    handle = pcap_create(dev_name, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error creating pcap handle for device '%s': %s\n", dev_name, errbuf);
        fflush(stderr);
        return 123;
    }
    printf("pcap_create successful for device '%s'.\n", dev_name);
    fflush(stdout);

    // At this point, `handle` is a valid `pcap_t` struct, but its `activated` field is false.
    // This satisfies the condition `!p->activated` in `pcap_is_swapped`.

    printf("before pcap_is_swapped\n");
    fflush(stdout);

    result = pcap_is_swapped(handle);

    if (result == PCAP_ERROR_NOT_ACTIVATED) {
        printf("Calling pcap_is_swapped fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_is_swapped correctly returned PCAP_ERROR_NOT_ACTIVATED because the pcap handle was not activated.\n");
        fflush(stderr);
    } else {
        // This path should not be taken if the handle is unactivated.
        printf("Calling pcap_is_swapped success\n");
        fflush(stdout);
        printf("Unexpected result from pcap_is_swapped: %d\n", result);
        fflush(stdout);
        fprintf(stderr, "Error: pcap_is_swapped did not return PCAP_ERROR_NOT_ACTIVATED for an unactivated handle.\n");
        fflush(stderr);
    }

    // Clean up the pcap handle.
    pcap_close(handle);

    // Return 123 to indicate failure based on the expected outcome.
    return 123;
}

