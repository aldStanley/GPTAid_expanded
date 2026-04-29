#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    pcap_t *handle = NULL; // Initialize handle to NULL
    char errbuf[PCAP_ERRBUF_SIZE];
    int *dlt_buffer = NULL;
    int num_datalinks;

    // Task2.7: Define a placeholder file name for potential file operations
    const char *example_filename = "example.pcap";

    // VIOLATION: Do NOT open a network device or a file.
    // The 'handle' will remain NULL, violating the rule that
    // the pcap_t pointer must point to an activated pcap_t instance.
    // handle = pcap_open_live(NULL, BUFSIZ, 1, 1000, errbuf);
    // if (handle == NULL) {
    //     fprintf(stderr, "Couldn't open device: %s\n", errbuf);
    //     printf("pcap_open_live failed.\n");
    //     fflush(stdout);
    //     return 123;
    // }
    // printf("pcap_open_live succeeded.\n");
    // fflush(stdout);

    // Task2.6: Add the specified printf before calling pcap_list_datalinks
    printf("before pcap_list_datalinks\n");
    fflush(stdout);

    // Task 1: Analyze the function code to find the invocation specification
    // The function pcap_list_datalinks takes two arguments:
    // 1. pcap_t *p: A pointer to an initialized pcap handle.
    // 2. int **dlt_buffer: A pointer to a pointer of integers. The function will
    //    allocate memory for this buffer and store the list of data link types (DLTs)
    //    in it. The caller is responsible for freeing this memory.

    // Task2.2: Call pcap_list_datalinks with a NULL handle
    // This will violate the rule: "The `pcap_t` pointer must point to an activated `pcap_t` instance."
    num_datalinks = pcap_list_datalinks(handle, &dlt_buffer);

    // Task2.3 & 2.5: Check the call status of pcap_list_datalinks
    // When pcap_list_datalinks is called with a NULL handle, it returns PCAP_ERROR_NOT_ACTIVATED.
    if (num_datalinks == PCAP_ERROR_NOT_ACTIVATED) {
        fprintf(stderr, "pcap_list_datalinks failed: The pcap handle was not activated (NULL handle passed).\n");
        printf("Calling pcap_list_datalinks fail as expected due to NULL handle.\n");
        fflush(stdout);
        // Task2.3: If API call fails, return 123 and output error message
        // No need to close handle as it was never opened.
        return 123;
    } else if (num_datalinks < 0) {
        // This branch might be reached if pcap_geterr() can provide an error for a NULL handle,
        // but PCAP_ERROR_NOT_ACTIVATED is the primary expected error for a NULL handle.
        fprintf(stderr, "pcap_list_datalinks failed with an unexpected error: %s\n", pcap_geterr(handle));
        printf("Calling pcap_list_datalinks fail with unexpected error.\n");
        fflush(stdout);
        return 123;
    } else {
        // This branch should not be reached when the handle is NULL.
        printf("Calling pcap_list_datalinks success (unexpected for NULL handle).\n");
        fflush(stdout);

        // Task2.3: Print details about the retrieved DLTs
        printf("Number of datalink types available: %d\n", num_datalinks);
        fflush(stdout);
        for (int i = 0; i < num_datalinks; i++) {
            printf("  DLT[%d]: %d (%s)\n", i, dlt_buffer[i], pcap_datalink_val_to_name(dlt_buffer[i]));
            fflush(stdout);
        }
    }

    // Task2.1 & 2.3: Free the allocated memory for dlt_buffer
    // This part is important to demonstrate proper cleanup even if the call failed.
    if (dlt_buffer != NULL) {
        free(dlt_buffer);
        dlt_buffer = NULL; // Set to NULL after freeing
        printf("dlt_buffer freed successfully.\n");
        fflush(stdout);
    }

    // Close the pcap handle
    // This block will not be executed if handle is NULL.
    if (handle) {
        pcap_close(handle);
        printf("pcap_close succeeded.\n");
        fflush(stdout);
    }

    return 0;
}

