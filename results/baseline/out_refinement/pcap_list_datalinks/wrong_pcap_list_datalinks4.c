#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>



int main() {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int *datalink_types = NULL; // This will be intentionally passed as NULL
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

    // 3. Call pcap_list_datalinks - VIOLATION HERE
    // The rule states: "The caller must provide a valid, non-NULL pointer for dlt_buffer
    // to receive the allocated memory for the DLT list. Passing a NULL pointer will
    // lead to a crash due to dereferencing a NULL pointer."
    // We are intentionally passing NULL for the second argument to violate this rule.
    num_datalinks = pcap_list_datalinks(handle, NULL); // VIOLATION: Passing NULL for dlt_buffer

    // 4. Check the status of pcap_list_datalinks
    if (num_datalinks < 0) {
        // PCAP_ERROR (usually -1) indicates an error occurred.
        // The error message is populated in handle->errbuf by libpcap.
        // Accessing handle->errbuf directly is correct when handle is not NULL.
        fprintf(stderr, "pcap_list_datalinks failed: %s\n", pcap_geterr(handle)); // Use pcap_geterr for consistency
        printf("Calling pcap_list_datalinks fail\n");
        fflush(stdout);
        pcap_close(handle); // Close the handle before exiting
        return 123;
    } else {
        printf("Calling pcap_list_datalinks success\n");
        fflush(stdout);

        printf("Number of supported datalinks: %d\n", num_datalinks);
        fflush(stdout);

        // In the original "right code", this block would iterate through datalink_types.
        // However, because we passed NULL to pcap_list_datalinks, the function
        // might behave differently. If it returns a non-negative value, it implies
        // it didn't crash immediately, but the dlt_buffer was not populated.
        // The violation is in the *call* itself, not necessarily in the immediate
        // aftermath if the library handles NULL gracefully by not allocating.
        // The example violation code checks if datalinks remained NULL.
        // Here, since we passed NULL, we can't check the pointer itself.
        // The crucial part is that the *call* was made with NULL.

        // If num_datalinks is greater than 0, and we passed NULL,
        // it means the function did not allocate memory for us.
        // The original code would have expected datalink_types to be non-NULL
        // if num_datalinks > 0.
        if (num_datalinks > 0) {
            printf("pcap_list_datalinks reported %d datalinks, but NULL was passed for the buffer.\n", num_datalinks);
            printf("This means no memory was allocated for the DLT list.\n");
            fflush(stdout);
            // No 'free(datalink_types)' here because datalink_types is NULL and
            // was never allocated by pcap_list_datalinks due to the violation.
        } else {
            printf("pcap_list_datalinks reported 0 datalinks.\n");
            fflush(stdout);
        }
    }

    // 6. Close the pcap handle
    pcap_close(handle);
    printf("Closed capture device\n");
    fflush(stdout);

    return 0;
}

