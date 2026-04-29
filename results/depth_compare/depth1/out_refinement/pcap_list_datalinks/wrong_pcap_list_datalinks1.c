#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




#define EXIT_FAILURE_CUSTOM 123

int main() {
    pcap_t *handle = NULL; // This handle will remain uninitialized
    char errbuf[PCAP_ERRBUF_SIZE];
    int *datalinks = NULL;
    int dlt_count = 0;
    const char *interface = NULL;

    // Attempt to find a suitable interface.
    // In a real application, you might want to list interfaces and let the user choose.
    // For this example, we'll try to get the first available one.
    char *devs = pcap_lookupdev(errbuf);
    if (devs == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        fflush(stdout);
        return EXIT_FAILURE_CUSTOM;
    }
    interface = devs;
    printf("Using interface: %s\n", interface);
    fflush(stdout);

    // *** VIOLATION START ***
    // We are intentionally NOT opening the capture device with pcap_open_live.
    // Therefore, 'handle' will remain NULL, and thus not point to an activated pcap_t instance.
    // The violation example shows calling pcap_list_datalinks with a NULL handle.
    // We will mimic this by calling it with our uninitialized 'handle'.
    // *** VIOLATION END ***

    printf("before pcap_list_datalinks (with uninitialized handle)\n");
    fflush(stdout);

    // Call pcap_list_datalinks with an uninitialized handle
    dlt_count = pcap_list_datalinks(handle, &datalinks);

    if (dlt_count >= 0) {
        // This block should not be reached if the violation is successful,
        // as pcap_list_datalinks should return an error for an unactivated handle.
        printf("Calling pcap_list_datalinks success (unexpected for this violation)\n");
        fflush(stdout);

        printf("Successfully retrieved %d data link types.\n", dlt_count);
        fflush(stdout);

        // Process the retrieved DLTs
        if (datalinks != NULL) {
            for (int i = 0; i < dlt_count; ++i) {
                printf("DLT[%d]: %d (%s)\n", i, datalinks[i], pcap_datalink_val_to_name(datalinks[i]));
                fflush(stdout);
            }
            // Free the allocated memory for the DLT list
            free(datalinks);
            datalinks = NULL; // Prevent dangling pointer
        } else {
            fprintf(stderr, "Error: datalinks pointer is NULL after successful call.\n");
            fflush(stdout);
        }
    } else {
        // This is the expected path for the violation.
        printf("Calling pcap_list_datalinks fail (as expected for this violation)\n");
        fflush(stdout);
        // When handle is NULL, pcap_geterr might behave unexpectedly or return an empty string.
        // The violation example uses pcap_geterr, so we will too, but acknowledge its potential limitations here.
        fprintf(stderr, "pcap_list_datalinks failed. Error code: %d. Error message: %s\n", dlt_count, pcap_geterr(handle));
        fflush(stdout);
    }

    // Close the capture device (this will do nothing if handle is NULL)
    if (handle != NULL) {
        pcap_close(handle);
    }

    // Return failure if pcap_list_datalinks returned an error
    return (dlt_count < 0) ? EXIT_FAILURE_CUSTOM : 0;
}

