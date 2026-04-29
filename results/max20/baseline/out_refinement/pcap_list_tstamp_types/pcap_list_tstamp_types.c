#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int *tstamp_types = NULL;
    int num_types;

    // Attempt to open a network device. Using "any" will try to find a suitable device.
    // In a real-world scenario, you'd likely want to specify a device name or use pcap_findalldevs.
    handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening adapter: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Successfully opened pcap handle.\n");
    fflush(stdout);

    // Task 6: Add the specified printf before the function call.
    printf("before pcap_list_tstamp_types\n");
    fflush(stdout);

    // Task 1: Invocation specification analysis.
    // The caller needs to provide a pointer to an integer pointer (`int **tstamp_typesp`).
    // This pointer will be updated by the function to point to a newly allocated array of integers,
    // representing the supported timestamp types.
    // The caller is responsible for freeing the memory allocated by `malloc` or `calloc`
    // when it's no longer needed.
    // The function returns the number of timestamp types supported, or PCAP_ERROR on failure.

    num_types = pcap_list_tstamp_types(handle, &tstamp_types);

    // Task 5: Output success or failure messages.
    if (num_types < 0) { // pcap_list_tstamp_types returns PCAP_ERROR as a negative value.
        fprintf(stderr, "Calling pcap_list_tstamp_types fail: %s\n", errbuf);
        fflush(stdout);
        pcap_close(handle);
        // No need to free tstamp_types here as it should be NULL on error.
        return 123;
    } else {
        printf("Calling pcap_list_tstamp_types success\n");
        fflush(stdout);

        // Output the supported timestamp types.
        if (tstamp_types != NULL) {
            printf("Supported timestamp types: %d\n", num_types);
            fflush(stdout);
            for (int i = 0; i < num_types; i++) {
                printf("Type %d: %d\n", i + 1, tstamp_types[i]);
                fflush(stdout);
            }
            // Free the allocated memory for tstamp_types.
            free(tstamp_types);
            tstamp_types = NULL; // Good practice to NULLify after freeing.
        } else {
            // This case should ideally not happen if num_types is >= 0,
            // but it's good to have a check.
            printf("No timestamp types returned, but call was successful.\n");
            fflush(stdout);
        }
    }

    // Close the pcap handle.
    pcap_close(handle);
    printf("Pcap handle closed.\n");
    fflush(stdout);

    return 0;
}

