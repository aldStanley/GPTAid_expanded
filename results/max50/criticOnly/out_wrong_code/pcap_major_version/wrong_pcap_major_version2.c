#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int major_version;

    // Open a live capture device. For this example, we'll try to open the first available one.
    // In a real application, you would typically list available devices and let the user choose.
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("pcap_open_live success\n");
    fflush(stdout);

    // Close the pcap handle immediately after opening it.
    // This will invalidate the handle before it's used by pcap_major_version.
    pcap_close(handle);
    printf("pcap_close success (immediately after opening)\n");
    fflush(stdout);

    // Now, call pcap_major_version with the closed (invalid) handle.
    // This violates the rule that the pcap_t pointer must point to a valid and initialized pcap_t structure.
    printf("before pcap_major_version (with invalid handle)\n");
    fflush(stdout);

    major_version = pcap_major_version(handle);

    // The behavior of pcap_major_version with an invalid handle is undefined.
    // It might return PCAP_ERROR_NOT_ACTIVATED, a negative error code, or even crash.
    // We'll check for a negative return value as a general indicator of failure.
    if (major_version < 0) {
        printf("Calling pcap_major_version fail (as expected with invalid handle)\n");
        fflush(stdout);
        // The error message might not be informative as the handle is invalid.
        fprintf(stderr, "An error occurred while getting major version with an invalid handle: %d\n", major_version);
        fflush(stdout);
        // No need to close the handle again as it's already closed.
        return 123;
    } else {
        // This branch is unlikely to be reached with an invalid handle,
        // but included for completeness.
        printf("Calling pcap_major_version success (unexpected with invalid handle)\n");
        fflush(stdout);
        printf("Major version of libpcap: %d\n", major_version);
        fflush(stdout);
    }

    return 0;
}

