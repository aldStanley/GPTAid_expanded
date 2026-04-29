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
        // --- VIOLATION ---
        // The memory allocated by pcap_list_datalinks for dlt_list is NOT freed here.
        // This will cause a memory leak.
        // The original code had:
        // free(dlt_list);
        // dlt_list = NULL;
        // We are removing this to violate the rule.
        // --- END VIOLATION ---
    } else if (num_datalinks == 0) {
        print_and_flush("No datalinks reported, which might indicate platform limitations.");
        // Even if num_datalinks is 0, pcap_list_datalinks might still allocate a small buffer
        // or set dlt_list to NULL. The rule states the caller is responsible for freeing
        // the memory allocated by pcap_list_datalinks. If dlt_list was allocated,
        // it should be freed. In this specific case where num_datalinks is 0,
        // it's less likely to have a significant allocation, but the principle remains.
        // However, to strictly follow the example violation which focuses on num_datalinks > 0,
        // we are not adding a free here for the num_datalinks == 0 case.
    }

    // Close the pcap handle
    pcap_close(handle);
    print_and_flush("Pcap handle closed.");

    return 0;
}

