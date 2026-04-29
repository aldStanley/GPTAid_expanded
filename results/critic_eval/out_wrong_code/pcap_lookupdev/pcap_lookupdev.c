#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


// Define PCAP_ERRBUF_SIZE if it's not defined in pcap.h
#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE 256
#endif

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *device = NULL;
    pcap_if_t *alldevs = NULL; // Used in pcap_findalldevs for error checking, though pcap_lookupdev handles it internally.

    // Ensure errbuf is initialized
    memset(errbuf, 0, sizeof(errbuf));

    // Add line before calling pcap_lookupdev
    printf("before pcap_lookupdev\n");
    fflush(stdout);

    // Call pcap_lookupdev
    // This function returns a pointer to a statically allocated buffer.
    // It does not require any prior initialization beyond providing an error buffer.
    device = pcap_lookupdev(errbuf);

    // Check the call status of pcap_lookupdev
    if (device == NULL) {
        // Calling pcap_lookupdev fail
        printf("Calling pcap_lookupdev fail\n");
        fflush(stdout);

        // Output error message to infer the cause of the error
        fprintf(stderr, "Error calling pcap_lookupdev: %s\n", errbuf);
        fflush(stderr);

        // Return 123 on failure
        return 123;
    } else {
        // Calling pcap_lookupdev success
        printf("Calling pcap_lookupdev success\n");
        fflush(stdout);

        // Output the found device name
        printf("Found network device: %s\n", device);
        fflush(stdout);
    }

    // No file read operations are inherently required by pcap_lookupdev itself.
    // If one were to use the obtained device name for file operations (e.g.,
    // saving captures to a file), then a filename like "example.pcap" would be used.

    return 0;
}

