#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int *tstamp_types = NULL;
    int num_types;

    // Open a dummy pcap handle for demonstration purposes.
    // In a real application, you would open a live interface or a file.
    // For this example, we'll try to open a non-existent interface,
    // which will likely result in an error, but it allows us to get a pcap_t pointer.
    // A more robust example might use pcap_open_offline or attempt to find an interface.
    handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (handle == NULL) {
        fprintf(stderr, "Failed to open a dummy pcap handle: %s\n", pcap_geterr(handle));
        fflush(stdout);
        return 123;
    }

    // --- Task2, Requirement 6 ---
    printf("before pcap_list_tstamp_types\n");
    fflush(stdout);
    // --- End Task2, Requirement 6 ---

    // Call pcap_list_tstamp_types with a NULL handle to violate the rule.
    // The violation code example shows passing a NULL pointer for the pcap_t.
    pcap_t *null_handle = NULL;
    num_types = pcap_list_tstamp_types(null_handle, &tstamp_types);

    if (num_types < 0) {
        // Task2, Requirement 5
        printf("Calling pcap_list_tstamp_types fail\n");
        fflush(stdout);

        // Task2, Requirement 3: Output error message
        // When the handle is NULL, pcap_geterr might behave unexpectedly or return an error.
        // For this violation, we'll still attempt to print an error, acknowledging the NULL handle.
        fprintf(stderr, "Error calling pcap_list_tstamp_types with a NULL handle.\n");
        fflush(stdout);

        // Cleanup the pcap handle (if it was successfully opened before being set to NULL)
        // In this specific violation, 'handle' is still valid, but we are demonstrating
        // the call with a NULL pointer.
        if (handle != NULL) {
            pcap_close(handle);
        }
        return 123;
    } else {
        // This branch is unlikely to be reached when passing a NULL handle,
        // but it's kept for structural completeness.
        // Task2, Requirement 5
        printf("Calling pcap_list_tstamp_types success\n");
        fflush(stdout);

        printf("Number of timestamp types supported: %d\n", num_types);
        fflush(stdout);

        if (tstamp_types != NULL) {
            printf("Supported timestamp types:\n");
            fflush(stdout);
            for (int i = 0; i < num_types; i++) {
                printf("  Type %d: %d\n", i, tstamp_types[i]);
                fflush(stdout);
            }
            // The caller is responsible for freeing the allocated memory
            free(tstamp_types);
            tstamp_types = NULL;
        }
    }

    // Cleanup the pcap handle
    pcap_close(handle);

    return 0;
}

