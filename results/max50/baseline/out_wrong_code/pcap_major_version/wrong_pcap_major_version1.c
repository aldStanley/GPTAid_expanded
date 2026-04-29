#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int major_version;

    // Task2.1: Open a network interface to get an activated pcap handle
    // We choose the first available network interface. If none is available,
    // this will fail.
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening interface eth0: %s\n", errbuf);
        fflush(stdout); // Task2.4
        return 123; // Task2.3
    }
    printf("pcap_open_live succeeded.\n");
    fflush(stdout); // Task2.4

    // Task2.6: Add line before calling pcap_major_version
    printf("before pcap_major_version\n");
    fflush(stdout); // Task2.4

    // Task2.1 & Task2.5: Call pcap_major_version and check status
    // VIOLATION: Passing a NULL pointer to pcap_major_version
    pcap_t *null_handle = NULL;
    major_version = pcap_major_version(null_handle);

    // The following checks are still present to show how the original code
    // would have handled the result, but the violation occurs before this.
    if (major_version == PCAP_ERROR_NOT_ACTIVATED) {
        printf("Calling pcap_major_version fail\n");
        fflush(stdout); // Task2.4
        fprintf(stderr, "Error: pcap_major_version failed because the pcap handle is not activated.\n");
        fflush(stdout); // Task2.4
        // In a real scenario, if handle was NULL, we wouldn't close it.
        // However, to maintain consistency with the original code's structure
        // where handle is opened, we'll keep the close if it was successfully opened.
        // But since the violation is passing NULL, the original 'handle' might not be used.
        if (handle != NULL) {
            pcap_close(handle);
        }
        return 123; // Task2.3
    } else if (major_version < 0) {
        // Handle other potential pcap errors if pcap_major_version could return them
        // (though based on the provided code, it only returns PCAP_ERROR_NOT_ACTIVATED or a valid major version)
        printf("Calling pcap_major_version fail\n");
        fflush(stdout); // Task2.4
        fprintf(stderr, "An unexpected error occurred while calling pcap_major_version. Error code: %d\n", major_version);
        fflush(stdout); // Task2.4
        if (handle != NULL) {
            pcap_close(handle);
        }
        return 123; // Task2.3
    } else {
        printf("Calling pcap_major_version success\n");
        fflush(stdout); // Task2.4
        printf("Pcap major version: %d\n", major_version);
        fflush(stdout); // Task2.4
    }

    // Task2.2: Non-interactive and no infinite loops. Cleanup.
    pcap_close(handle);
    printf("pcap_close succeeded.\n");
    fflush(stdout); // Task2.4

    return 0;
}

