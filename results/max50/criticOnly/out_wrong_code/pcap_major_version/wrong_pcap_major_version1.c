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

    // pcap_major_version requires the pcap handle to be activated.
    // pcap_open_live() activates the handle. So, we can directly call pcap_major_version.

    printf("before pcap_major_version\n");
    fflush(stdout);

    // VIOLATION: Pass a NULL pcap_t pointer to pcap_major_version
    pcap_t *null_handle = NULL;
    major_version = pcap_major_version(null_handle);

    // The behavior when passing NULL to pcap_major_version is undefined.
    // In many libpcap implementations, it might return PCAP_ERROR_NOT_ACTIVATED or a similar error code,
    // or it might crash due to a NULL pointer dereference.
    // We'll check for a common error code, but a crash is also a possible outcome of this violation.
    if (major_version == PCAP_ERROR_NOT_ACTIVATED) {
        printf("Calling pcap_major_version fail (as expected due to NULL handle)\n");
        fflush(stdout);
        fprintf(stderr, "Error: pcap handle is NULL, which is not allowed.\n");
        fflush(stdout);
        // We don't need to close a NULL handle, but we should still clean up the valid handle if it was opened.
        pcap_close(handle);
        return 123;
    } else if (major_version < 0) {
        printf("Calling pcap_major_version fail (unexpected error with NULL handle)\n");
        fflush(stdout);
        fprintf(stderr, "An unexpected error occurred while getting major version with NULL handle: %d\n", major_version);
        fflush(stdout);
        pcap_close(handle);
        return 123;
    } else {
        // This branch is unlikely to be reached when passing NULL, but included for completeness.
        printf("Calling pcap_major_version success (unexpected with NULL handle)\n");
        fflush(stdout);
        printf("Major version of libpcap: %d\n", major_version);
        fflush(stdout);
    }

    // Close the pcap handle
    pcap_close(handle);
    printf("pcap_close success\n");
    fflush(stdout);

    return 0;
}

