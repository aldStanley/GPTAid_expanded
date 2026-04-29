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

    // Call pcap_findalldevs
    // VIOLATION: Passing a NULL pointer for alldevsp.
    // The rule states that `alldevsp` must be a valid, writable pointer to a `pcap_if_t` pointer.
    // By passing NULL, we are violating this requirement.
    // The pcap_findalldevs function is designed to write the list of devices
    // into the memory location pointed to by `alldevsp`. If `alldevsp` is NULL,
    // it cannot perform this write operation, leading to undefined behavior or a crash
    // if the function doesn't have a specific check for NULL.
    // In this specific implementation of libpcap, pcap_findalldevs checks for NULL
    // and returns -1. However, the *intent* of the rule is to ensure the caller
    // provides a valid pointer for the function to write to.
    status = pcap_findalldevs(NULL, errbuf);

    // Check the call status of pcap_findalldevs
    if (status == -1) {
        printf("Calling pcap_findalldevs fail\n");
        fflush(stdout);
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        fflush(stderr);
        return EXIT_FAILURE_CODE;
    } else {
        // This block will not be reached if the violation causes a crash
        // or if the function returns -1 as it does for NULL input.
        printf("Calling pcap_findalldevs success\n");
        fflush(stdout);

        // If successful, print the names of the devices
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
        pcap_freealldevs(alldevs);
    }

    return 0;
}

