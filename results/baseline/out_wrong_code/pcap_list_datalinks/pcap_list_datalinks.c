#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>



int main() {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int *datalink_types = NULL;
    int num_datalinks = 0;
    const char *device = "eth0"; // Example device name for Linux

    // 1. Open a live capture device
    handle = pcap_open_live(device, 65535, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening capture device %s: %s\n", device, errbuf);
        printf("pcap_open_live failed\n");
        fflush(stdout);
        return 123;
    }
    printf("Successfully opened capture device %s\n", device);
    fflush(stdout);

    // 2. Prepare to call pcap_list_datalinks
    printf("before pcap_list_datalinks\n");
    fflush(stdout);

    // 3. Call pcap_list_datalinks
    num_datalinks = pcap_list_datalinks(handle, &datalink_types);

    // 4. Check the status of pcap_list_datalinks
    if (num_datalinks < 0) {
        // PCAP_ERROR (usually -1) indicates an error occurred.
        // The error message is populated in handle->errbuf by libpcap.
        // Accessing handle->errbuf directly is correct when handle is not NULL.
        fprintf(stderr, "pcap_list_datalinks failed: %s\n", errbuf); // Use the errbuf directly
        printf("Calling pcap_list_datalinks fail\n");
        fflush(stdout);
        pcap_close(handle); // Close the handle before exiting
        return 123;
    } else {
        printf("Calling pcap_list_datalinks success\n");
        fflush(stdout);

        printf("Number of supported datalinks: %d\n", num_datalinks);
        fflush(stdout);

        if (datalink_types != NULL) {
            printf("Supported DLTs:\n");
            fflush(stdout);
            for (int i = 0; i < num_datalinks; i++) {
                printf("  DLT %d: %d\n", i + 1, datalink_types[i]);
                fflush(stdout);
            }
            // 5. Free the allocated buffer
            free(datalink_types);
            datalink_types = NULL; // Good practice to NULLify after freeing
        } else {
            // This branch should be taken if num_datalinks is 0 or 1 and dlt_buffer is NULL,
            // which might happen if the platform only supports the current DLT and dlt_count was 0.
            // However, the function's logic ensures dlt_buffer will be allocated if successful.
            // This is a fallback for unexpected scenarios.
            printf("datalink_types pointer is NULL, though %d datalinks were reported.\n", num_datalinks);
            fflush(stdout);
        }
    }

    // 6. Close the pcap handle
    pcap_close(handle);
    printf("Closed capture device\n");
    fflush(stdout);

    return 0;
}

