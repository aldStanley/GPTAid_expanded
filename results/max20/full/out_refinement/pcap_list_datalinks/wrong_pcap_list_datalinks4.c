#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




// Function to print error messages with flushing
void print_and_flush(const char *message) {
    printf("%s\n", message);
    fflush(stdout);
}

int main() {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int *dlt_list = NULL; // This will be intentionally passed as NULL
    int num_datalinks = 0;
    const char *device = pcap_lookupdev(errbuf); // Get a default device

    if (device == NULL) {
        print_and_flush("Error finding default device: ");
        print_and_flush(errbuf);
        return 123;
    }

    // Open a live capture handle
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        print_and_flush("Error opening interface: ");
        print_and_flush(errbuf);
        return 123;
    }
    print_and_flush("Successfully opened pcap handle.");

    // --- Calling pcap_list_datalinks to VIOLATE the rule ---
    printf("before pcap_list_datalinks (violating rule)\n");
    fflush(stdout);

    // VIOLATION: Passing a NULL pointer for the second argument (dlt_buffer)
    // The pcap_list_datalinks function expects a pointer to a pointer (int **).
    // By passing NULL, we are violating the rule that a valid, non-NULL pointer
    // must be provided to receive the allocated memory.
    num_datalinks = pcap_list_datalinks(handle, NULL);

    if (num_datalinks < 0) {
        print_and_flush("Calling pcap_list_datalinks failed as expected due to NULL pointer.");
        print_and_flush("pcap_list_datalinks error: ");
        // pcap_geterr might not be meaningful here as the error is due to invalid argument,
        // but we'll still try to print it.
        print_and_flush(pcap_geterr(handle));
        // In this violation scenario, dlt_list remains NULL and no memory was allocated for it.
    } else {
        // This branch is unlikely to be reached if the violation is correctly handled by libpcap,
        // but we include it for completeness.
        print_and_flush("Calling pcap_list_datalinks unexpectedly succeeded.");
        // If it somehow succeeded, num_datalinks would be the count, but dlt_list would still be NULL
        // because we passed NULL.
        if (num_datalinks > 0) {
            printf("Number of supported datalinks reported: %d\n", num_datalinks);
            fflush(stdout);
            printf("Note: dlt_list is NULL because it was passed as NULL to the function.\n");
            fflush(stdout);
        } else {
            printf("No datalinks reported.\n");
            fflush(stdout);
        }
    }
    // --- End of pcap_list_datalinks call ---

    // No need to free dlt_list here because it was never allocated due to the violation.

    // Close the pcap handle
    pcap_close(handle);
    print_and_flush("Pcap handle closed.");

    return 0;
}

