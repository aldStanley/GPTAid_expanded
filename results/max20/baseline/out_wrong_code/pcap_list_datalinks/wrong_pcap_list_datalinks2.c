#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    pcap_t *handle = NULL; // Initialize handle to NULL to violate the rule
    char errbuf[PCAP_ERRBUF_SIZE];
    int *dlt_buffer = NULL;
    int num_datalinks;

    // Task2.6: Add the specified print statement before the call.
    printf("before pcap_list_datalinks\n");
    fflush(stdout);

    // Task2.1: Call pcap_list_datalinks according to its specification.
    // The function expects a pointer to an int pointer (int **dlt_buffer).
    // The function will allocate memory for the dlt_buffer and return the number of datalinks.
    // VIOLATION: Passing a NULL pcap_t pointer to pcap_list_datalinks.
    num_datalinks = pcap_list_datalinks(handle, &dlt_buffer);

    // Task2.3: Check the call status of pcap_list_datalinks.
    if (num_datalinks < 0) {
        fprintf(stderr, "Calling pcap_list_datalinks fail\n");
        fflush(stdout);
        // When handle is NULL, pcap_geterr might not be safe or might return a generic error.
        // The violation example shows a generic error message.
        fprintf(stderr, "Error: pcap_list_datalinks failed with a NULL handle.\n");
        fflush(stdout);
        // No need to pcap_close(handle) as handle is NULL.
    } else {
        // This branch is unlikely to be reached when handle is NULL,
        // but included for completeness based on the original structure.
        printf("Calling pcap_list_datalinks success\n");
        fflush(stdout);

        // Print the returned datalink types.
        printf("Number of datalinks supported: %d\n", num_datalinks);
        fflush(stdout);
        for (int i = 0; i < num_datalinks; i++) {
            printf("  DLT: %d\n", dlt_buffer[i]);
            fflush(stdout);
        }

        // Task2.2: Free the allocated memory. The caller is responsible for freeing dlt_buffer.
        free(dlt_buffer);
        dlt_buffer = NULL; // Good practice to set to NULL after freeing
    }

    return 0;
}

