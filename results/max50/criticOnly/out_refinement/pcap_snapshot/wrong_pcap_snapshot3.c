#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *dev = pcap_lookupdev(errbuf);

    if (dev == NULL) {
        fprintf(stderr, "Error: Could not find default network device: %s\n", errbuf);
        fflush(stdout); // Flushing stdout even though stderr is used for error message
        return 123;
    }

    // Open a live capture handle
    // BUFSIZ is a standard buffer size, 1 for promiscuous mode, 1000ms timeout
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error: Couldn't open device %s: %s\n", dev, errbuf);
        fflush(stdout); // Flushing stdout even though stderr is used for error message
        return 123;
    }

    // Task2.6: Add the specified printf before calling pcap_snapshot
    printf("before pcap_snapshot\n");
    fflush(stdout);

    // VIOLATION: Close the handle before calling pcap_snapshot
    // This is done to create a dangling pointer as per the violation example.
    pcap_close(handle);
    // At this point, 'handle' is a dangling pointer.
    // Calling pcap_snapshot with a closed handle is a use-after-free.

    // Explicitly call the pcap_snapshot API
    // This call will operate on the dangling pointer.
    int snapshot_value = pcap_snapshot(handle);

    // Task2.5: Check the return value and print the appropriate message
    // PCAP_ERROR_NOT_ACTIVATED is returned if the handle is not activated.
    // pcap_open_live *should* activate the handle, but we check anyway.
    // With a dangling pointer, the behavior is undefined. The original code
    // had a double-free due to calling pcap_close twice. This modified code
    // aims to violate the dangling pointer rule by calling pcap_snapshot
    // after pcap_close, but avoids the double-free by not calling pcap_close again.
    if (snapshot_value == PCAP_ERROR_NOT_ACTIVATED) {
        printf("Calling pcap_snapshot fail\n");
        fflush(stdout);
        // No need to close handle again as it's already closed.
        return 123;
    } else {
        // If snapshot_value is not PCAP_ERROR_NOT_ACTIVATED, it's the snapshot length.
        // This branch is unlikely to be reached with a dangling pointer,
        // but we keep the logic for completeness.
        printf("Calling pcap_snapshot success\n");
        fflush(stdout);
        // Optionally, you could print the snapshot value itself:
        // printf("Snapshot length is: %d\n", snapshot_value);
        // fflush(stdout);
    }

    // Clean up the pcap handle
    // This call is now safe because pcap_close was only called once.
    // If pcap_snapshot returned a valid value, it implies the handle
    // might have been re-initialized or the library handled it gracefully,
    // but the initial call to pcap_snapshot on a closed handle is the violation.
    // If pcap_snapshot failed and returned an error, this close is still valid.
    // We do NOT call pcap_close(handle) here again to avoid the double-free.
    // The handle is already closed.

    return 0;
}

