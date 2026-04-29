#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int snapshot_len;

    // Attempt to open a network device. Replace "eth0" if necessary.
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening adapter: %s\n", errbuf);
        printf("Could not open network device. Please ensure you have a network interface (e.g., 'eth0') and appropriate permissions.\n");
        fflush(stdout);
        return 123; // Indicate failure
    }

    // Task 1: Invocation Specification for pcap_snapshot:
    // The caller must provide a valid, non-NULL `pcap_t *p` pointer to an *activated* pcap handle.
    // An activated handle is one that has been successfully opened for live capture
    // (e.g., using `pcap_open_live`). If the `pcap_t *p` points to a handle that is not activated,
    // `pcap_snapshot` will return `PCAP_ERROR_NOT_ACTIVATED`.

    // Add the required print statement before calling pcap_snapshot
    printf("before pcap_snapshot\n");
    fflush(stdout); // Flush stdout as per requirement

    // VIOLATION: Close the handle before calling pcap_snapshot
    pcap_close(handle);
    // Now 'handle' is a dangling pointer. Calling pcap_snapshot on it violates the rule.

    // Call pcap_snapshot on the closed handle
    snapshot_len = pcap_snapshot(handle);

    // Check the status of the pcap_snapshot call
    if (snapshot_len == PCAP_ERROR_NOT_ACTIVATED) {
        printf("Calling pcap_snapshot fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_snapshot failed: The pcap handle was not activated.\n");
        fflush(stderr);
        // No need to close handle again as it's already closed
        return 123;       // Return error code
    } else if (snapshot_len < 0) {
        // pcap_snapshot can return negative values for other errors.
        printf("Calling pcap_snapshot fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_snapshot failed with error code: %d. Unknown error.\n", snapshot_len);
        fflush(stderr);
        // No need to close handle again as it's already closed
        return 123;       // Return error code
    } else {
        printf("Calling pcap_snapshot success\n");
        fflush(stdout);
        printf("Snapshot length obtained: %d\n", snapshot_len);
        fflush(stdout);
    }

    // The handle is already closed, so no need to call pcap_close(handle) here.

    return 0; // Indicate success
}

