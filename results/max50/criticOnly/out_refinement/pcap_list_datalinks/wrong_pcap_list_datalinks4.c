#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    // int *dlt_buffer = NULL; // This will be intentionally set to NULL for violation
    int dlt_count;

    // Find a suitable network device. This part is simplified for a non-interactive example.
    // In a real application, you'd likely want to list devices and let the user choose.
    char *dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 123;
    }
    printf("Using device: %s\n", dev);
    fflush(stdout);

    // Open the device for capturing
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 123;
    }
    printf("Successfully opened device %s\n", dev);
    fflush(stdout);

    // Task2: Call pcap_list_datalinks and violate the rule
    printf("before pcap_list_datalinks\n");
    fflush(stdout);

    // VIOLATION: Pass a NULL pointer for dlt_buffer
    // The pcap_list_datalinks function expects a pointer to a pointer (int **).
    // By passing NULL directly, we are violating the rule that a valid, non-NULL pointer
    // must be provided to receive the allocated memory.
    dlt_count = pcap_list_datalinks(handle, NULL);

    // Check the call status of pcap_list_datalinks
    if (dlt_count < 0) {
        fprintf(stderr, "Calling pcap_list_datalinks fail\n");
        fflush(stderr);
        fprintf(stderr, "Error from pcap_list_datalinks: %s\n", pcap_geterr(handle));
        fflush(stderr);
        pcap_close(handle);
        return 123;
    } else {
        // This block might not be reached if the violation causes a crash.
        // If it is reached, it indicates that pcap_list_datalinks might have
        // handled the NULL pointer in a way that didn't immediately crash,
        // but it's still a violation of the API contract.
        printf("Calling pcap_list_datalinks success (unexpected with NULL pointer)\n");
        fflush(stdout);
        printf("Number of DLTs found: %d\n", dlt_count);
        fflush(stdout);

        // If dlt_count is greater than 0, and we passed NULL,
        // we cannot access dlt_buffer because it was never allocated.
        // Attempting to access it would be a crash.
        // The violation is in the call itself, not necessarily in subsequent usage
        // if the function returns without crashing.
    }

    // Close the capture handle
    pcap_close(handle);
    printf("Closed pcap handle.\n");
    fflush(stdout);

    return 0;
}

