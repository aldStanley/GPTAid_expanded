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
    int *dlt_list = NULL;
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

    // --- Calling pcap_list_datalinks ---
    printf("before pcap_list_datalinks\n");
    fflush(stdout);

    // VIOLATION: Pass a NULL pcap_t pointer to pcap_list_datalinks
    // This violates the rule that the pcap_t pointer must point to a valid and initialized pcap_t structure.
    num_datalinks = pcap_list_datalinks(NULL, &dlt_list);

    if (num_datalinks < 0) {
        print_and_flush("Calling pcap_list_datalinks fail");
        // When handle is NULL, pcap_geterr(handle) will likely cause a crash or undefined behavior.
        // We'll print a generic message instead to avoid further issues.
        print_and_flush("pcap_list_datalinks error: Called with a NULL pcap_t pointer.");
    } else {
        // This branch should ideally not be reached if the violation is effective.
        print_and_flush("Calling pcap_list_datalinks success (unexpected with NULL handle)");
    }
    // --- End of pcap_list_datalinks call ---

    // The following code might not execute as expected or might crash due to the invalid handle.
    // We keep it to show the intended flow if the call were successful.
    if (num_datalinks > 0 && dlt_list != NULL) {
        printf("Number of supported datalinks: %d\n", num_datalinks);
        fflush(stdout);
        printf("Supported DLTs:\n");
        fflush(stdout);
        for (int i = 0; i < num_datalinks; ++i) {
            printf("  DLT: %d (%s)\n", dlt_list[i], pcap_datalink_val_to_name(dlt_list[i]));
            fflush(stdout);
        }
        // Free the allocated buffer
        free(dlt_list);
        dlt_list = NULL; // Set to NULL to avoid dangling pointer
    } else if (num_datalinks == 0) {
        printf("No datalinks reported, which might indicate platform limitations.\n");
        fflush(stdout);
    }

    // Close the pcap handle if it was successfully opened
    if (handle != NULL) {
        pcap_close(handle);
        print_and_flush("Pcap handle closed.");
    } else {
        print_and_flush("Pcap handle was not opened, so no closing needed.");
    }

    return 0;
}

