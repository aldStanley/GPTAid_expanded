#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int snapshot_len;

    // Initialize pcap (opening a device is a common way to get a pcap_t handle)
    // For a non-interactive, non-looping example, we'll try to open the first available interface.
    // If no interface is available or an error occurs, this will fail.
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf); // Using "eth0" as a placeholder, adjust if needed
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        printf("Failed to initialize pcap handle.\n");
        fflush(stdout);
        return 123;
    }
    printf("pcap_open_live succeeded.\n");
    fflush(stdout);

    // VIOLATION: Close the handle before calling pcap_snapshot.
    // This creates a dangling pointer scenario, as pcap_snapshot will be called
    // on a handle that has already been closed and is no longer valid for libpcap operations.
    pcap_close(handle);
    printf("pcap_close called before pcap_snapshot.\n");
    fflush(stdout);

    printf("before pcap_snapshot\n");
    fflush(stdout);

    // This call will likely result in undefined behavior or a crash because 'handle' is a dangling pointer.
    // The internal check for activation might still pass if the memory hasn't been fully deallocated,
    // but the handle is logically invalid.
    snapshot_len = pcap_snapshot(handle);

    if (snapshot_len < 0) {
        fprintf(stderr, "pcap_snapshot failed. Error code: %d\n", snapshot_len);
        printf("Calling pcap_snapshot fail\n");
        fflush(stdout);
        // No need to pcap_close(handle) here as it was already closed.
        return 123;
    } else {
        printf("Calling pcap_snapshot success\n");
        fflush(stdout);
        printf("Snapshot length obtained: %d bytes.\n", snapshot_len);
        fflush(stdout);
    }

    // Clean up - this part might not be reached if the program crashes due to the dangling pointer.
    // If it is reached, pcap_close on an already closed handle is generally safe but redundant.
    // pcap_close(handle); // Redundant and potentially problematic if handle is truly invalid.
    printf("Cleanup completed (or attempted).\n");
    fflush(stdout);

    return 0;
}

