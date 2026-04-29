#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


// Define a constant for the return code on failure
#define FAILURE_RETURN_CODE 123

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL; // Initialize handle to NULL

    // 1. Obtain a pcap_t handle.
    // We use pcap_open_live for this example.
    // For a non-interactive and non-infinite loop, we need to specify
    // the interface. Let's try to open the first available interface.
    // In a real-world scenario, you'd want to handle interface selection more robustly.

    // Find a suitable network interface.
    char *interface = pcap_lookupdev(errbuf);
    if (interface == NULL) {
        fprintf(stderr, "Error finding default network interface: %s\n", errbuf);
        fflush(stdout);
        return FAILURE_RETURN_CODE;
    }
    printf("Using network interface: %s\n", interface);
    fflush(stdout);

    // Open the network device for live capture.
    // We set a snaplen (snapshot length) and a timeout.
    // We set the initial 'promisc' argument in pcap_open_live to 0,
    // as we intend to set it using pcap_set_promisc later.
    handle = pcap_open_live(interface, BUFSIZ, 0, 100, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device %s: %s\n", interface, errbuf);
        fflush(stdout);
        return FAILURE_RETURN_CODE;
    }
    printf("Successfully opened network interface for pcap.\n");
    fflush(stdout);

    // Now, we call pcap_set_promisc.
    // According to the function's check (pcap_check_activated),
    // we should call this *before* starting packet capture (e.g., before pcap_loop/dispatch).
    // pcap_open_live itself does not activate the handle for capture,
    // so it should be safe to call pcap_set_promisc here.

    int promiscuous_mode_setting = 1; // Set to 1 to enable promiscuous mode

    printf("before pcap_set_promisc\n");
    fflush(stdout);

    // *** Explicitly calling pcap_set_promisc ***
    int result = pcap_set_promisc(handle, promiscuous_mode_setting);

    // Check the status of the pcap_set_promisc call
    if (result == 0) {
        printf("Calling pcap_set_promisc success\n");
        fflush(stdout);
    } else {
        fprintf(stderr, "Calling pcap_set_promisc fail. Error code: %d\n", result);
        // Attempt to get a more descriptive error message if possible.
        // The error code PCAP_ERROR_ACTIVATED is self-explanatory based on the function's logic.
        if (result == PCAP_ERROR_ACTIVATED) {
            fprintf(stderr, "  Reason: The pcap handle was already activated.\n");
        } else {
            fprintf(stderr, "  An unknown error occurred.\n");
        }
        fflush(stdout);
        // Clean up the handle before returning
        pcap_close(handle);
        return FAILURE_RETURN_CODE;
    }

    // We are not starting packet capture in this example to keep it non-interactive.
    // If we were to start capture, we'd call pcap_loop or pcap_dispatch here.
    // For example:
    // pcap_loop(handle, 1, my_packet_handler, NULL); // Capture just 1 packet

    // Clean up the pcap handle
    printf("Cleaning up pcap handle.\n");
    fflush(stdout);
    pcap_close(handle);

    return 0; // Success
}

