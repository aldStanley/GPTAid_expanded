#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int *tstamp_types = NULL;
    int num_tstamp_types;

    // Open a dummy pcap handle for demonstration purposes.
    // In a real-world scenario, you would open an interface or a file.
    // Using "any" for interface name and a small snaplen as we don't capture.
    handle = pcap_open_live("any", 65535, 1, 0, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Successfully opened pcap handle.\n");
    fflush(stdout);

    // Task 6: Add printf before calling pcap_list_tstamp_types
    printf("before pcap_list_tstamp_types\n");
    fflush(stdout);

    // Task 1: Invocation Specification Analysis
    // The caller needs to provide a pointer to an integer pointer (`int **tstamp_typesp`).
    // This pointer will be used by `pcap_list_tstamp_types` to allocate memory
    // for an array of integers representing the supported timestamp types.
    // The caller is responsible for freeing this allocated memory.
    // The function returns the number of timestamp types supported, or PCAP_ERROR on failure.

    num_tstamp_types = pcap_list_tstamp_types(handle, &tstamp_types);

    if (num_tstamp_types == PCAP_ERROR) {
        // Task 5: Output error message
        fprintf(stderr, "Calling pcap_list_tstamp_types fail: %s\n", pcap_geterr(handle));
        fflush(stdout);
        pcap_close(handle);
        return 123;
    } else {
        // Task 5: Output success message
        printf("Calling pcap_list_tstamp_types success\n");
        fflush(stdout);

        printf("Number of supported timestamp types: %d\n", num_tstamp_types);
        fflush(stdout);

        if (tstamp_types != NULL) {
            printf("Supported timestamp types:\n");
            fflush(stdout);
            for (int i = 0; i < num_tstamp_types; i++) {
                printf("  Type %d: %d\n", i + 1, tstamp_types[i]);
                fflush(stdout);
            }
            // The caller is responsible for freeing the allocated memory
            free(tstamp_types);
            tstamp_types = NULL; // Good practice to set to NULL after freeing
        } else {
            printf("No timestamp types were provided.\n");
            fflush(stdout);
        }
    }

    pcap_close(handle);
    printf("Successfully closed pcap handle.\n");
    fflush(stdout);

    return 0;
}

