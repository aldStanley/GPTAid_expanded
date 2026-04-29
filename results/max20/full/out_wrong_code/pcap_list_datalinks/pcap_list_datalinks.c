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

    num_datalinks = pcap_list_datalinks(handle, &dlt_list);

    if (num_datalinks < 0) {
        print_and_flush("Calling pcap_list_datalinks fail");
        print_and_flush("pcap_list_datalinks error: ");
        print_and_flush(pcap_geterr(handle)); // Use pcap_geterr for pcap_t related errors
        pcap_close(handle);
        return 123;
    } else {
        print_and_flush("Calling pcap_list_datalinks success");
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

    // Close the pcap handle
    pcap_close(handle);
    print_and_flush("Pcap handle closed.");

    return 0;
}

