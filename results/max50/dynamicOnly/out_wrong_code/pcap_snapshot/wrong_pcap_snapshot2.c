#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int snapshot_len;

    // Task2.2: Non-interactive and no infinite loops.
    // Task2.3: Check the call status of each API.
    // Task2.7: Example file name.
    // Using "any" as a device name for simplicity in this example.
    // In a real-world scenario, you would likely use a specific interface.
    handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening adapter: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("pcap_open_live succeeded.\n");
    fflush(stdout);

    // Task2.6: Add specific printf before pcap_snapshot
    printf("before pcap_snapshot\n");
    fflush(stdout);

    // Task 1: Invocation Specification Analysis
    // The pcap_snapshot function returns the snapshot length of a capture handle.
    // According to the source code:
    // - The pcap_t* parameter 'p' must not be NULL.
    // - The capture handle 'p' must be activated. The 'activated' member of the pcap_t
    //   structure needs to be true. This is typically achieved by calling
    //   pcap_open_live, pcap_open_dead, or pcap_create and then pcap_activate.
    //   If the handle is not activated, it returns PCAP_ERROR_NOT_ACTIVATED.
    //
    // Therefore, the caller must ensure:
    // 1. A valid and initialized pcap_t pointer is passed.
    // 2. The pcap_t handle has been successfully activated (e.g., after pcap_open_live
    //    and before any other operation that relies on an active handle).

    // VIOLATION: Calling pcap_snapshot on a handle that has been closed.
    // pcap_close() deactivates the handle, making it invalid for subsequent operations.
    pcap_close(handle);
    printf("pcap_close succeeded (deactivating the handle).\n");
    fflush(stdout);

    // Task2.3: Check the call status of pcap_snapshot
    // This call will now violate the rule because 'handle' is no longer activated.
    snapshot_len = pcap_snapshot(handle);

    if (snapshot_len == PCAP_ERROR_NOT_ACTIVATED) {
        // Task2.5: Output "Calling pcap_snapshot fail"
        printf("Calling pcap_snapshot fail\n");
        fflush(stdout);
        // Task2.3: Output error message
        fprintf(stderr, "pcap_snapshot failed: Capture handle is not activated.\n");
        fflush(stdout);
        // Note: handle is already closed, so no need to call pcap_close(handle) again.
        return 123;
    } else if (snapshot_len < 0) {
        // Task2.5: Output "Calling pcap_snapshot fail"
        printf("Calling pcap_snapshot fail\n");
        fflush(stdout);
        // Task2.3: Output error message
        fprintf(stderr, "pcap_snapshot failed with an unexpected negative value: %d\n", snapshot_len);
        fflush(stdout);
        // Note: handle is already closed.
        return 123;
    } else {
        // Task2.5: Output "Calling pcap_snapshot success"
        printf("Calling pcap_snapshot success\n");
        fflush(stdout);
        printf("Snapshot length: %d\n", snapshot_len);
        fflush(stdout);
    }

    // Task2.2: Non-interactive and no infinite loops.
    // This part of the code will not be reached if the violation occurs as expected.
    // If it were reached, it would be a redundant pcap_close.
    // printf("pcap_close succeeded.\n");
    // fflush(stdout);

    return 0;
}

