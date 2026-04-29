#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int major_version;

    // Open a pcap device for live capturing.
    // This is necessary to activate the pcap handle before calling pcap_major_version.
    // We are using "any" for the device to be general, but in a real scenario,
    // you might want to specify a specific network interface.
    handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Unable to open device: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("pcap_open_live succeeded.\n");
    fflush(stdout);

    // Task2.6: Output before calling pcap_major_version
    printf("before pcap_major_version\n");
    fflush(stdout);

    // Call pcap_major_version
    major_version = pcap_major_version(handle);

    // Task2.5: Check the return value and print accordingly
    if (major_version == PCAP_ERROR_NOT_ACTIVATED) {
        printf("Calling pcap_major_version fail\n");
        fflush(stdout);
        // Although the function indicates it's not activated,
        // pcap_open_live should have activated it. This case
        // is included for completeness based on the function's return.
        fprintf(stderr, "pcap_major_version returned PCAP_ERROR_NOT_ACTIVATED, which is unexpected after pcap_open_live.\n");
        fflush(stdout);
        pcap_close(handle);
        return 123;
    } else if (major_version < 0) {
        // pcap_major_version can return negative values on other errors.
        printf("Calling pcap_major_version fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_major_version failed with error code: %d\n", major_version);
        fflush(stdout);
        pcap_close(handle);
        return 123;
    } else {
        printf("Calling pcap_major_version success\n");
        fflush(stdout);
        printf("Major version: %d\n", major_version);
        fflush(stdout);
    }

    // Close the pcap handle
    pcap_close(handle);
    printf("pcap_close succeeded.\n");
    fflush(stdout);

    return 0;
}

