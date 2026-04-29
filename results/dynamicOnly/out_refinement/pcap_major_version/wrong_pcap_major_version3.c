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
    // Close the handle *before* calling pcap_major_version.
    // This makes the handle unactivated, violating the rule.
    pcap_close(handle);
    printf("pcap_close called before pcap_major_version.\n");
    fflush(stdout);

    // Call pcap_major_version on an unactivated handle.
    major_version = pcap_major_version(handle);
    // --- VIOLATION END ---

    // Check the status of pcap_major_version
    // pcap_major_version returns PCAP_ERROR_NOT_ACTIVATED (which is negative)
    // when the handle is not activated.
    if (major_version < 0) {
        printf("Calling pcap_major_version fail (as expected due to unactivated handle)\n");
        fflush(stdout);
        fprintf(stderr, "pcap_major_version failed with error code: %d\n", major_version);
        fflush(stdout);
        // In this specific violation scenario, handle is already closed,
        // so no need to call pcap_close again.
        return 123;
    } else {
        // This branch should not be reached in the violation.
        printf("Calling pcap_major_version success (unexpected)\n");
        fflush(stdout);
        printf("Libpcap major version: %d\n", major_version);
        fflush(stdout);
    }

    // This part of the code will not be reached if the violation occurs as intended.
    // If the violation didn't happen, this would be the cleanup.
    // However, since we closed 'handle' earlier, calling pcap_close again would be an error.
    // For completeness, we'll leave a note.
    // printf("pcap_close successful.\n");
    // fflush(stdout);

    return 0;
}

