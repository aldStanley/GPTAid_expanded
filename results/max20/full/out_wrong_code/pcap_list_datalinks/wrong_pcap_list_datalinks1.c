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
    pcap_t *handle = NULL; // Initialize handle to NULL
    char errbuf[PCAP_ERRBUF_SIZE];
    int *dlt_list = NULL;
    int num_datalinks = 0;
    const char *device = pcap_lookupdev(errbuf); // Get a default device

    if (device == NULL) {
        print_and_flush("Error finding default device: ");
        print_and_flush(errbuf);
        return 123;
    }

    // --- VIOLATION: Do NOT open a live capture handle ---
    // The violation example shows calling pcap_list_datalinks with a NULL handle.
    // We will replicate this by not opening the handle.
    // handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    // if (handle == NULL) {
    //     print_and_flush("Error opening interface: ");
    //     print_and_flush(errbuf);
    //     return 123;
    // }
    // print_and_flush("Successfully opened pcap handle.");

    // --- Calling pcap_list_datalinks with an unactivated/invalid handle ---
    printf("before pcap_list_datalinks\n");
    fflush(stdout);

    // Calling pcap_list_datalinks with a NULL handle violates the rule
    // "The pcap_t pointer must point to an activated pcap_t instance."
    num_datalinks = pcap_list_datalinks(handle, &dlt_list);

    if (num_datalinks < 0) {
        print_and_flush("Calling pcap_list_datalinks fail");
        // When handle is NULL, pcap_geterr(handle) might behave unexpectedly or crash.
        // The violation example uses fprintf(stderr, "Error: %s\n", pcap_geterr(handle));
        // We will print a generic error message as pcap_geterr might not be safe here.
        print_and_flush("pcap_list_datalinks error: The pcap handle was not activated or is invalid.");
        // In a real scenario, if handle was opened but not activated, you'd close it.
        // Since we didn't open it, no closing is needed.
        // pcap_close(handle);
        return 123;
    } else {
        // This branch should ideally not be reached if the violation is successful
        // and pcap_list_datalinks returns an error for an invalid handle.
        print_and_flush("Calling pcap_list_datalinks success (unexpected for a violated rule)");
    }
    // --- End of pcap_list_datalinks call ---

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

    // Close the pcap handle if it was opened (which it wasn't in this violation)
    // if (handle != NULL) {
    //     pcap_close(handle);
    //     print_and_flush("Pcap handle closed.");
    // }

    return 0;
}

