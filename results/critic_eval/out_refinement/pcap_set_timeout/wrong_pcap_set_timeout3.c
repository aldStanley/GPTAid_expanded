#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




#define ERROR_EXIT_CODE 123

int main() {
    pcap_t *handle = NULL; // Initialize handle to NULL
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *device = pcap_lookupdev(errbuf); // Try to find a default device

    if (device == NULL) {
        fprintf(stderr, "Could not find default device: %s\n", errbuf);
        fflush(stdout);
        return ERROR_EXIT_CODE;
    }

    // Open a live capture handle.
    // Set initial timeout to 0 to ensure pcap_set_timeout can be called without
    // triggering the 'already activated' error due to the initial open_live timeout.
    handle = pcap_open_live(device, BUFSIZ, 1, 0, errbuf); // Buffer size, promisc, timeout=0, errbuf
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device, errbuf);
        fflush(stdout);
        return ERROR_EXIT_CODE;
    }
    printf("Successfully opened pcap handle with initial timeout 0.\n");
    fflush(stdout);

    // Now, we set the timeout using pcap_set_timeout.
    // This example sets a timeout of 500 milliseconds.
    int timeout_ms = 500;

    printf("before pcap_set_timeout\n");
    fflush(stdout);

    // --- VIOLATION START ---
    // To violate the rule "Ensure the pcap_t pointer points to a valid and initialized pcap_t structure",
    // we will call pcap_set_timeout with a NULL pointer.
    // This is analogous to the violation example where an uninitialized pointer was used.
    int set_timeout_result = pcap_set_timeout(NULL, timeout_ms);
    // --- VIOLATION END ---

    if (set_timeout_result != 0) {
        fprintf(stderr, "Calling pcap_set_timeout fail: %d\n", set_timeout_result);
        fflush(stdout);
        if (set_timeout_result == PCAP_ERROR_ACTIVATED) {
            fprintf(stderr, "Error: The pcap handle is already activated.\n");
            fflush(stdout);
        } else {
            // pcap_set_timeout itself might not populate errbuf on failure,
            // but we can still report a generic error.
            fprintf(stderr, "An unknown error occurred while setting timeout.\n");
            fflush(stdout);
        }
        // We still attempt to close the handle if it was successfully opened,
        // even though the pcap_set_timeout call failed due to an invalid handle.
        if (handle != NULL) {
            pcap_close(handle); // Clean up the handle
            printf("Pcap handle closed.\n");
            fflush(stdout);
        }
        return ERROR_EXIT_CODE;
    } else {
        printf("Calling pcap_set_timeout success\n");
        fflush(stdout);
    }

    // Clean up the pcap handle
    if (handle != NULL) {
        pcap_close(handle);
        printf("Pcap handle closed.\n");
        fflush(stdout);
    }

    return 0;
}

