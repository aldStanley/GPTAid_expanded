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

    // --- VIOLATION START ---
    // To violate the rule "The pcap_t pointer must point to a valid and initialized pcap_t structure",
    // we will call pcap_major_version with a NULL pointer.
    // This simulates passing an uninitialized or invalid pcap_t pointer.
    pcap_t *invalid_handle = NULL;
    major_version = pcap_major_version(invalid_handle);
    // --- VIOLATION END ---

    // Check the status of pcap_major_version
    // pcap_major_version returns PCAP_ERROR_NOT_ACTIVATED (which is negative)
    // when the handle is not valid or not activated.
    if (major_version < 0) {
        printf("Calling pcap_major_version fail (as expected due to invalid handle)\n");
        fflush(stdout);
        fprintf(stderr, "pcap_major_version failed with error code: %d\n", major_version);
        fflush(stdout);
        // Clean up the pcap handle (if it was successfully opened before the violation)
        pcap_close(handle);
        printf("pcap_close successful (for the valid handle).\n");
        fflush(stdout);
        return 123;
    } else {
        // This branch should ideally not be reached if the violation is successful.
        printf("Calling pcap_major_version success (unexpected for invalid handle)\n");
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

