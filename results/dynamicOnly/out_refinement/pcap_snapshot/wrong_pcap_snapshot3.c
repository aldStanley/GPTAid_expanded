#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>



int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int snapshot_len;

    // Task2.1: Initialize pcap and open a device.
    // We need an activated pcap handle to call pcap_snapshot.
    // We'll try to open the first available network interface.
    // Using "any" for interface to try to open a generic interface if specific ones fail.
    handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device 'any': %s\n", errbuf);
        fflush(stderr);
        return 123;
    }
    printf("pcap_open_live initialized successfully.\n");
    fflush(stdout);

    // Task2.6: Add the required printf statement before calling pcap_snapshot.
    printf("before pcap_snapshot\n");
    fflush(stdout);

    // Task 1: Analyze the function code.
    // The function pcap_snapshot checks if the pcap handle 'p' is activated.
    // Invocation specification: The caller must provide a valid, activated pcap_t pointer.
    // If the handle is not activated, it returns PCAP_ERROR_NOT_ACTIVATED.
    // Otherwise, it returns the snapshot length stored in p->snapshot.

    // Task2.3 & 2.5: Call pcap_snapshot and check its status.
    // VIOLATION: Close the handle *before* calling pcap_snapshot.
    // This creates a dangling pointer scenario, as pcap_snapshot will be called
    // on a handle that has already been closed and its resources released by libpcap.
    pcap_close(handle);
    printf("pcap_close executed before pcap_snapshot.\n");
    fflush(stdout);

    // Now, calling pcap_snapshot on the closed handle.
    // This is a use-after-free scenario, violating the rule.
    snapshot_len = pcap_snapshot(handle);

    if (snapshot_len == PCAP_ERROR_NOT_ACTIVATED) {
        // Task2.5: Output for failure.
        printf("Calling pcap_snapshot fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_snapshot failed: PCAP_ERROR_NOT_ACTIVATED. The pcap handle was not activated.\n");
        fflush(stderr);
        // No need to close handle again as it's already closed.
        return 123;
    } else if (snapshot_len < 0) { // pcap_snapshot could return negative error codes other than PCAP_ERROR_NOT_ACTIVATED
        // Task2.5: Output for failure.
        printf("Calling pcap_snapshot fail\n");
        fflush(stdout);
        // Note: pcap_geterr might behave unexpectedly or crash if handle is truly invalid.
        // For this specific violation, we expect a negative return code.
        fprintf(stderr, "pcap_snapshot failed with error code: %d.\n", snapshot_len);
        fflush(stderr);
        return 123;
    } else {
        // Task2.5: Output for success.
        printf("Calling pcap_snapshot success\n");
        fflush(stdout);
        printf("Snapshot length retrieved: %d\n", snapshot_len);
        fflush(stdout);
    }

    // If the code somehow reaches here without error (unlikely for this violation),
    // we would normally close the handle. However, it's already closed.
    // printf("pcap_close executed successfully.\n");
    // fflush(stdout);

    return 0;
}

