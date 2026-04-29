#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int snapshot_len;

    // Task2.1: Open a device for live capture
    // In a real scenario, you'd choose a valid network interface.
    // For this example, we'll try to open a dummy device or fail gracefully.
    // We'll use "eth0" as a common example, but this might not exist on all systems.
    // If it fails, we'll output an error and exit.
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Unable to open device eth0: %s\n", errbuf);
        fflush(stderr);
        return 123;
    }
    printf("pcap_open_live succeeded.\n");
    fflush(stdout);

    // Task 1: Invocation Specification Analysis
    // The pcap_snapshot function requires that the pcap_t object pointed to by 'p'
    // must be activated. The function checks `!p->activated` and returns
    // `PCAP_ERROR_NOT_ACTIVATED` if the device is not activated.
    // `pcap_open_live` activates the pcap handle upon successful opening.
    // Therefore, the invocation specification is:
    // The `pcap_t *p` argument must be a valid, activated pcap handle.
    // This is typically obtained by calling `pcap_open_live` or `pcap_open_offline`.

    // Task2.6: Add line before calling pcap_snapshot
    printf("before pcap_snapshot\n");
    fflush(stdout);

    // VIOLATION: Close the handle before calling pcap_snapshot
    // This creates a dangling pointer scenario. While the memory might not be
    // immediately deallocated, it's no longer a valid handle for libpcap operations.
    pcap_close(handle);
    printf("pcap_close called before pcap_snapshot to violate the rule.\n");
    fflush(stdout);

    // Task2.2: Call pcap_snapshot
    // Task2.3: Check call status
    // This call now uses a closed (dangling) handle, violating the rule.
    snapshot_len = pcap_snapshot(handle);

    // Task2.5: Output success or failure message
    if (snapshot_len < 0) { // pcap_snapshot returns the snapshot length on success, or a negative error code
        fprintf(stderr, "Calling pcap_snapshot fail. Error code: %d\n", snapshot_len);
        fflush(stderr);
        // Task2.3: Infer cause of error
        if (snapshot_len == PCAP_ERROR_NOT_ACTIVATED) {
            fprintf(stderr, "Cause: The pcap handle is not activated. Ensure pcap_open_live or pcap_open_offline was successful.\n");
            fflush(stderr);
        } else {
            // When a handle is closed and then used, libpcap might return
            // PCAP_ERROR_NOT_ACTIVATED or another error depending on the internal state.
            // For this violation, we expect an error, and the specific error code
            // might vary, but it will indicate an invalid operation.
            fprintf(stderr, "Cause: An error occurred, likely due to using a closed pcap handle. Refer to libpcap documentation for error code %d.\n", snapshot_len);
            fflush(stderr);
        }
        // Task2.3: Return 123 on failure
        // Note: We cannot call pcap_close(handle) again as it's already closed.
        return 123;
    } else {
        printf("Calling pcap_snapshot success\n");
        fflush(stdout);
        printf("Snapshot length: %d\n", snapshot_len);
        fflush(stdout);
    }

    // Task2.2: Non-interactive and no infinite loops: The code performs a single
    // operation and then exits.

    // Task2.3 & 2.4: Check API status and flush stdout. This is done for pcap_open_live
    // and pcap_snapshot. All printf calls have flushing.

    // Task2.7: No file read operations are performed in this specific example.
    // If there were, "example.pcap" would be a suitable name if reading a pcap file.

    // Clean up
    // We don't call pcap_close here because it was already called before the
    // pcap_snapshot call to create the violation. Calling it again would be an error.

    return 0;
}

