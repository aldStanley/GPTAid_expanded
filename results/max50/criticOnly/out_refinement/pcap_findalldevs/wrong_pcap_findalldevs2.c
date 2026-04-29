#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>



#define ERROR_BUFFER_SIZE 256
#define EXIT_FAILURE_CODE 123

int main() {
    pcap_if_t *alldevs = NULL;
    char errbuf[ERROR_BUFFER_SIZE];
    int status;

    // Add line before calling pcap_findalldevs
    printf("before pcap_findalldevs\n");
    fflush(stdout);

    // --- VIOLATION START ---
    // To violate the rule "The caller must ensure that the memory pointed to by alldevsp is not freed or invalidated before pcap_findalldevs completes its execution."
    // we will pass a pointer to memory that has already been freed.
    // This makes the memory location pointed to by `alldevsp` invalid for writing.

    // Allocate memory for a pcap_if_t pointer.
    pcap_if_t *invalid_device_ptr = (pcap_if_t *)malloc(sizeof(pcap_if_t));
    if (invalid_device_ptr == NULL) {
        fprintf(stderr, "Failed to allocate memory for invalid_device_ptr\n");
        fflush(stderr);
        return EXIT_FAILURE_CODE;
    }

    // Free the allocated memory, making it invalid.
    free(invalid_device_ptr);
    invalid_device_ptr = NULL; // Good practice to NULL after free, but the pointer itself still points to freed memory.

    // Now, create a pointer to this freed memory.
    pcap_if_t **alldevsp_pointing_to_freed_memory = &invalid_device_ptr;

    // Call pcap_findalldevs with a pointer to freed memory.
    // This will likely cause a segmentation fault when pcap_findalldevs
    // attempts to write to the memory location pointed to by `alldevsp_pointing_to_freed_memory`.
    printf("Calling pcap_findalldevs with a pointer to freed memory...\n");
    fflush(stdout);
    status = pcap_findalldevs(alldevsp_pointing_to_freed_memory, errbuf);
    // --- VIOLATION END ---

    // Check the call status of pcap_findalldevs
    // This block might not be reached if the program crashes due to the violation.
    if (status == -1) {
        printf("Calling pcap_findalldevs fail\n");
        fflush(stdout);
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        fflush(stderr);
        return EXIT_FAILURE_CODE;
    } else {
        printf("Calling pcap_findalldevs success\n");
        fflush(stdout);

        // If successful, print the names of the devices
        // Note: In the violation case, `alldevs` might be NULL or contain garbage
        // if the crash didn't happen immediately.
        if (alldevs != NULL) {
            printf("Available network devices:\n");
            fflush(stdout);
            pcap_if_t *d;
            for (d = alldevs; d != NULL; d = d->next) {
                printf("  %s\n", d->name);
                fflush(stdout);
            }
        } else {
            printf("No network devices found.\n");
            fflush(stdout);
        }

        // Free the memory allocated for the device list
        // This will be called if the program doesn't crash.
        pcap_freealldevs(alldevs);
    }

    return 0;
}

