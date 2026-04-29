#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


// Define PCAP_ERRBUF_SIZE if not already defined by pcap.h
#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE 256
#endif

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *device;

    // Variable to store the return status of pcap_lookupdev
    int lookup_status;

    printf("before pcap_lookupdev\n");
    fflush(stdout); // Flush stdout after printing

    // Call pcap_lookupdev
    device = pcap_lookupdev(errbuf);
    lookup_status = (device == NULL) ? -1 : 0; // -1 for failure, 0 for success

    if (lookup_status == 0) {
        // Success
        printf("Calling pcap_lookupdev success\n");
        fflush(stdout); // Flush stdout after printing

        // Successfully found a device, print its name
        printf("Found device: %s\n", device);
        fflush(stdout); // Flush stdout after printing
    } else {
        // Failure
        printf("Calling pcap_lookupdev fail\n");
        fflush(stdout); // Flush stdout after printing

        // Print the error message from errbuf
        fprintf(stderr, "Error in pcap_lookupdev: %s\n", errbuf);
        fflush(stderr); // Flush stderr after printing

        // Exit with a non-zero status to indicate an error
        return 123;
    }

    // No file read operations in this example, so no 'example.xxx' is needed.

    return 0; // Indicate successful execution
}

