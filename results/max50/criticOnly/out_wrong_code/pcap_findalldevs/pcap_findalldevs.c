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
    status = pcap_findalldevs(&alldevs, errbuf);

    // Check the call status of pcap_findalldevs
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

