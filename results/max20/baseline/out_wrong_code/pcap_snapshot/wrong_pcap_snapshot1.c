#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int snapshot_len;

    // Attempt to open a network device for live capture.
    // We'll use the first available device.
    // This requires root privileges in most Linux systems.
    char *dev_name = pcap_lookupdev(errbuf);
    if (dev_name == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }

    handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev_name, errbuf);
        fflush(stdout);
        return 123;
    }

    // The pcap_snapshot function requires the pcap handle to be activated.
    // pcap_open_live implicitly activates the handle.

    printf("before pcap_snapshot\n");
    fflush(stdout);

    // --- VIOLATION START ---
    // To violate the rule "Ensure the pcap_t handle is valid and points to an initialized capture session before calling pcap_snapshot",
    // we will close the handle *before* calling pcap_snapshot.
    // This makes the handle invalid and no longer points to an initialized capture session.
    pcap_close(handle);
    printf("pcap_close called prematurely.\n");
    fflush(stdout);

    // Call pcap_snapshot with an invalid handle
    snapshot_len = pcap_snapshot(handle);
    // --- VIOLATION END ---

    if (snapshot_len == PCAP_ERROR_NOT_ACTIVATED) {
        fprintf(stderr, "Calling pcap_snapshot fail: The pcap handle is not activated.\n");
        fflush(stdout);
        // No need to close handle here as it was already closed prematurely.
        return 123;
    } else if (snapshot_len < 0) {
        // pcap_snapshot returns an int, so a negative value might indicate an error
        // although the provided snippet only explicitly returns PCAP_ERROR_NOT_ACTIVATED
        // or the snapshot value. If the library's internal implementation of pcap_snapshot
        // were to return other negative error codes, this branch would catch them.
        // For the given snippet, this branch might be unreachable unless the library
        // changes its behavior.
        fprintf(stderr, "Calling pcap_snapshot fail: An unknown error occurred.\n");
        fflush(stdout);
        // No need to close handle here as it was already closed prematurely.
        return 123;
    } else {
        printf("Calling pcap_snapshot success\n");
        fflush(stdout);
        printf("Snapshot length: %d\n", snapshot_len);
        fflush(stdout);
    }

    // Clean up
    // This call might be redundant or cause issues if the handle was already closed.
    // In a real scenario, you'd want to avoid this.
    // pcap_close(handle); // This line is now commented out as it's already been called.
    // printf("pcap_close called successfully.\n");
    // fflush(stdout);

    return 0;
}

