#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




#define ERROR_BUFFER_SIZE 256
#define EXIT_FAILURE_CODE 123

int main() {
    pcap_if_t *alldevs;
    char errbuf[ERROR_BUFFER_SIZE];

    printf("before pcap_findalldevs\n");
    fflush(stdout);

    // Call pcap_findalldevs
    int status = pcap_findalldevs(&alldevs, errbuf);

    if (status == 0) {
        printf("Calling pcap_findalldevs success\n");
        fflush(stdout);

        // Optional: Print the names of the found devices to demonstrate success
        pcap_if_t *d;
        printf("Available network devices:\n");
        fflush(stdout);
        for (d = alldevs; d != NULL; d = d->next) {
            printf("  %s\n", d->name);
            fflush(stdout);
        }

        // Free the list of devices when done
        pcap_freealldevs(alldevs);

        // VIOLATION: Attempt to access the freed memory through the 'alldevs' pointer
        // This is a use-after-free vulnerability.
        // The 'alldevs' pointer now points to deallocated memory.
        // Accessing 'alldevs->name' is undefined behavior.
        if (alldevs != NULL) { // This check is technically on freed memory
            printf("Attempting to access freed device name: %s\n", alldevs->name);
            fflush(stdout);
        } else {
            // This branch might be taken if alldevs was NULL initially,
            // but the violation is in the attempt to access it *after* freeing.
            // The key is the attempt to dereference alldevs after pcap_freealldevs.
            printf("alldevs is NULL after freeing, as expected for a valid free.\n");
            fflush(stdout);
        }

    } else {
        printf("Calling pcap_findalldevs fail\n");
        fflush(stdout);

        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        fflush(stderr);
        return EXIT_FAILURE_CODE;
    }

    return 0;
}

