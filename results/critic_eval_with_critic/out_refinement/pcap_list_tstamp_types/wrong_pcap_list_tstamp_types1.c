#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int *tstamp_types = NULL;
    int num_tstamp_types;

    // Open a network device for live capture.
    // In a real application, you'd want to choose a specific device
    // or use pcap_findalldevs to list available devices.
    // For this example, we'll try to open the first available device.
    // If no device is found, pcap_open_live will return NULL.
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        fflush(stderr);
        // In a real scenario, you might want to exit or try another device.
        // For this example, we'll proceed to demonstrate the NULL pointer violation.
        // If pcap_open_live fails, 'handle' will be NULL.
    } else {
        printf("Successfully opened network device.\n");
        fflush(stdout);
    }

    // --- Violation Start ---
    // To violate the rule "The pcap_t pointer must not be NULL",
    // we will pass a NULL pointer to pcap_list_tstamp_types.
    // This can happen if pcap_open_live fails and returns NULL,
    // and the program continues without checking for NULL.
    pcap_t *null_handle = NULL;

    // Task 6: Add the required printf statement before the function call.
    printf("before pcap_list_tstamp_types (with NULL handle)\n");
    fflush(stdout);

    // Call pcap_list_tstamp_types with a NULL handle.
    // This will violate the rule.
    num_tstamp_types = pcap_list_tstamp_types(null_handle, &tstamp_types);
    // --- Violation End ---

    // Task 5: Check the call status and output accordingly.
    // When pcap_list_tstamp_types is called with a NULL pcap_t pointer,
    // it is expected to return a negative value indicating an error.
    if (num_tstamp_types < 0) {
        // The error message from libpcap for a NULL handle is typically "NULL pointer".
        fprintf(stderr, "Calling pcap_list_tstamp_types with NULL handle failed as expected: %d\n", num_tstamp_types);
        fflush(stderr);
    } else {
        // This branch should ideally not be reached when passing a NULL handle.
        printf("Calling pcap_list_tstamp_types with NULL handle unexpectedly succeeded.\n");
        fflush(stdout);

        // Task2: Print the supported timestamp types
        printf("Supported timestamp types (%d):\n", num_tstamp_types);
        fflush(stdout);
        for (int i = 0; i < num_tstamp_types; i++) {
            printf("  Type %d: %d\n", i, tstamp_types[i]);
            fflush(stdout);
        }

        // Clean up allocated memory by pcap_list_tstamp_types
        if (tstamp_types != NULL) {
            free(tstamp_types);
            tstamp_types = NULL;
        }
    }

    // Close the network device if it was successfully opened.
    if (handle != NULL) {
        pcap_close(handle);
        printf("Network device closed.\n");
        fflush(stdout);
    }

    return 0;
}

