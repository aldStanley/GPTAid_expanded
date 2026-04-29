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

    // The error "can't perform operation on activated capture" indicates that
    // pcap_open_live itself might have implicitly activated the handle on some systems,
    // or the default behavior of pcap_open_live is to activate it.
    // Therefore, calling pcap_activate again after pcap_open_live can lead to this error.
    // We should proceed to check pcap_snapshot directly if pcap_open_live succeeded
    // and assume the handle is activated or ready for operations that require activation.
    // A common way to check if it's ready for such operations is to try calling a function
    // that relies on activation and handle its potential errors.
    // In this case, pcap_snapshot is what we want to test, and it checks for activation.

    // Task2.6: Add the required printf statement before calling pcap_snapshot.
    printf("before pcap_snapshot\n");
    fflush(stdout);

    // Task 1: Analyze the function code.
    // The function pcap_snapshot checks if the pcap handle 'p' is activated.
    // Invocation specification: The caller must provide a valid, activated pcap_t pointer.
    // If the handle is not activated, it returns PCAP_ERROR_NOT_ACTIVATED.
    // Otherwise, it returns the snapshot length stored in p->snapshot.

    // Task2.3 & 2.5: Call pcap_snapshot and check its status.
    snapshot_len = pcap_snapshot(handle);

    if (snapshot_len == PCAP_ERROR_NOT_ACTIVATED) {
        // Task2.5: Output for failure.
        printf("Calling pcap_snapshot fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_snapshot failed: PCAP_ERROR_NOT_ACTIVATED. The pcap handle was not activated.\n");
        fflush(stderr);
        pcap_close(handle);
        return 123;
    } else if (snapshot_len < 0) { // pcap_snapshot could return negative error codes other than PCAP_ERROR_NOT_ACTIVATED
        // Task2.5: Output for failure.
        printf("Calling pcap_snapshot fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_snapshot failed with error code: %d. Error message: %s\n", snapshot_len, pcap_geterr(handle));
        fflush(stderr);
        pcap_close(handle);
        return 123;
    } else {
        // Task2.5: Output for success.
        printf("Calling pcap_snapshot success\n");
        fflush(stdout);
        printf("Snapshot length retrieved: %d\n", snapshot_len);
        fflush(stdout);
    }

    // Task2.4: Close the pcap handle.
    pcap_close(handle);
    printf("pcap_close executed successfully.\n");
    fflush(stdout);

    return 0;
}

