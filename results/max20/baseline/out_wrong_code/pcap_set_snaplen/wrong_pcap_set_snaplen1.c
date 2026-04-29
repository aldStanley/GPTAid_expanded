#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>



int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *device = pcap_lookupdev(errbuf); // Find a default device

    // Task2.3: Check API call status for pcap_lookupdev
    if (device == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }

    // Open a live capture handle.
    // Using a standard large snaplen for pcap_open_live to potentially avoid
    // the handle being considered "activated" prematurely by the library.
    handle = pcap_open_live(device, 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        fflush(stdout);
        return 123;
    }

    int snapshot_len = 1024; // Example snapshot length to set with pcap_set_snaplen

    // Task2.6: Add specific printf before the function call
    printf("before pcap_set_snaplen\n");
    fflush(stdout);

    // VIOLATION: Pass a NULL pointer for the pcap_t handle.
    // This violates the rule that the pcap_t handle must be valid and not NULL.
    pcap_t *invalid_handle = NULL;
    int result = pcap_set_snaplen(invalid_handle, snapshot_len);

    // Task2.5: Output success or failure message
    if (result == 0) {
        printf("Calling pcap_set_snaplen success\n");
        fflush(stdout);
    } else {
        printf("Calling pcap_set_snaplen fail\n");
        fflush(stdout);
        // Task2.3: Output error message if API call fails
        // The error code -4 indicates PCAP_ERROR_ACTIVATED. This means pcap_check_activated(handle) returned true.
        // In libpcap, this typically means a capture has started or the handle is otherwise in an activated state.
        // pcap_set_snaplen is designed to be called *before* activation.
        // The fact that it fails immediately after pcap_open_live suggests that in the execution environment,
        // the handle is considered activated by pcap_open_live itself or very soon after.
        // The fix is to ensure `pcap_check_activated` returns false. By setting a large, standard snaplen
        // in `pcap_open_live` (like 65536), we might prevent it from entering an "activated" state that blocks `pcap_set_snaplen`.
        // If it still fails, it means the environment's `pcap_check_activated` is triggered by something else.
        // The previous fix used `BUFSIZ`. The current fix uses `65536`.
        fprintf(stderr, "pcap_set_snaplen failed. Error code %d indicates the capture handle might have been activated before setting snaplen. Ensure this is called before any capture initiation.\n", result);
        fflush(stdout);
        // Task2.3: Return 123 on failure
        // We still need to close the valid handle if it was opened successfully before the violation.
        if (handle != NULL) {
            pcap_close(handle);
        }
        return 123;
    }

    // Close the capture handle
    pcap_close(handle);

    return 0;
}

