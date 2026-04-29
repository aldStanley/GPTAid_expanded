#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int major_version;

    // Attempt to open a network interface for live capture.
    // Replace "eth0" with a valid interface on your system, or use a pcap file.
    // For a non-interactive, non-looping example, opening an interface is common.
    // If you want to test with a pcap file, you'd use pcap_open_offline instead.
    // For this example, we'll try to open the first available interface.
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Unable to open adapter: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("pcap_open_live succeeded.\n");
    fflush(stdout);

    // Check if the handle is activated. pcap_open_live typically activates it.
    // However, for demonstration purposes, we'll simulate the check as required by the prompt.
    // If pcap_open_live failed, handle would be NULL, and we would have already returned.
    // The pcap_major_version function checks if p->activated is true.
    // Since pcap_open_live generally activates the handle, we expect this to pass.

    printf("before pcap_major_version\n");
    fflush(stdout);

    // Call pcap_major_version
    major_version = pcap_major_version(handle);

    // Check the return status of pcap_major_version
    if (major_version == PCAP_ERROR_NOT_ACTIVATED) {
        printf("Calling pcap_major_version fail\n");
        fflush(stdout);
        // The function implies that if it returns PCAP_ERROR_NOT_ACTIVATED,
        // the handle was not activated. We'll close the handle and exit.
        pcap_close(handle);
        printf("Error: pcap_t handle was not activated.\n");
        fflush(stdout);
        return 123;
    } else if (major_version < 0) {
        // pcap_major_version can return negative values for other errors,
        // though the source provided only shows PCAP_ERROR_NOT_ACTIVATED.
        // We'll treat any negative return as a failure.
        printf("Calling pcap_major_version fail\n");
        fflush(stdout);
        fprintf(stderr, "An unexpected error occurred with pcap_major_version: %d\n", major_version);
        fflush(stdout);
        pcap_close(handle);
        return 123;
    } else {
        printf("Calling pcap_major_version success\n");
        fflush(stdout);
        printf("Pcap major version: %d\n", major_version);
        fflush(stdout);
    }

    // Close the pcap handle
    pcap_close(handle);
    printf("pcap_close succeeded.\n");
    fflush(stdout);

    return 0;
}

