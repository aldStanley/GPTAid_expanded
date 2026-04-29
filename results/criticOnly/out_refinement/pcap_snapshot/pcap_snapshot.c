#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int snapshot_len;

    // Task2.2: Non-interactive and no infinite loops.
    // Task2.3: Check API call status and output error messages.
    // Task2.4: Flush stdout after each printf.

    // Task2.7: Replace 'xxx' with the actual file type if file operations were present.
    // This example uses pcap_open_live, which operates on network interfaces, not files.

    // To ensure the code is runnable and demonstrates the pcap_snapshot function,
    // we need to open a *valid* network interface. Since "nonexistent_interface"
    // caused an error, we'll attempt to find the first available interface.
    char *dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Using default device: %s\n", dev);
    fflush(stdout);

    // Now open the found device.
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening capture device %s: %s\n", dev, errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Successfully opened a pcap handle for device %s.\n", dev);
    fflush(stdout);

    // Task2.6: Add the specified printf before calling pcap_snapshot.
    printf("before pcap_snapshot\n");
    fflush(stdout);

    // Task 1: Invocation specification for pcap_snapshot:
    // The pcap_snapshot function requires a valid and activated pcap_t handle.
    // The pcap_t handle must have been successfully initialized (e.g., via pcap_open_live or pcap_open_offline)
    // and it must have been activated. The `activated` field in the pcap_t struct (private to libpcap)
    // indicates its activation status. If `p->activated` is false, pcap_snapshot returns PCAP_ERROR_NOT_ACTIVATED.
    // Therefore, the caller must ensure that the pcap_t handle is active before calling pcap_snapshot.
    // In this example, pcap_open_live implicitly activates the handle if successful.

    snapshot_len = pcap_snapshot(handle);

    // Task2.3: Check the call status of pcap_snapshot.
    // The pcap_snapshot function returns the snapshot length or PCAP_ERROR_NOT_ACTIVATED.
    // We check if the return value indicates an error.
    if (snapshot_len < 0) {
        fprintf(stderr, "Calling pcap_snapshot fail. Error code: %d\n", snapshot_len);
        fflush(stdout);

        // Task2.3: Infer the cause of the error.
        if (snapshot_len == PCAP_ERROR_NOT_ACTIVATED) {
            fprintf(stderr, "pcap_snapshot failed because the pcap handle is not activated.\n");
            fflush(stdout);
        } else {
            fprintf(stderr, "An unknown error occurred during pcap_snapshot.\n");
            fflush(stdout);
        }
        pcap_close(handle); // Clean up the handle
        return 123;
    } else {
        printf("Calling pcap_snapshot success\n");
        fflush(stdout);
        printf("The snapshot length for this capture is: %d bytes.\n", snapshot_len);
        fflush(stdout);
    }

    // Task2.1: Compilable and follows invocation specification.
    // Task2.7: No file read operations in this example.

    // Clean up the pcap handle.
    pcap_close(handle);
    printf("Pcap handle has been successfully closed.\n");
    fflush(stdout);

    return 0;
}

