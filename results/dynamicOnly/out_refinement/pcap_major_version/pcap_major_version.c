#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *interface = "eth0"; // Replace with a valid network interface if needed
    int major_version;

    // Open a live capture handle.
    // This is necessary to activate the pcap_t structure.
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening adapter: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("pcap_open_live successful.\n");
    fflush(stdout);

    printf("before pcap_major_version\n");
    fflush(stdout);

    // Call pcap_major_version
    major_version = pcap_major_version(handle);

    // Check the status of pcap_major_version
    if (major_version < 0) { // pcap_major_version returns PCAP_ERROR_NOT_ACTIVATED which is negative
        printf("Calling pcap_major_version fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_major_version failed with error code: %d\n", major_version);
        fflush(stdout);
        // Clean up the pcap handle
        pcap_close(handle);
        return 123;
    } else {
        printf("Calling pcap_major_version success\n");
        fflush(stdout);
        printf("Libpcap major version: %d\n", major_version);
        fflush(stdout);
    }

    // Clean up the pcap handle
    pcap_close(handle);
    printf("pcap_close successful.\n");
    fflush(stdout);

    return 0;
}

