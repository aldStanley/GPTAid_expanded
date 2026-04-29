#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>





int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL; // Initialize handle to NULL
    int snapshot_len;
    pcap_if_t *alldevs = NULL; // Initialize alldevs to NULL

    // Task2.1: Open a network interface for live capture.
    // This is a prerequisite for pcap_snapshot to be called successfully.
    // We'll use the first available interface.
    // Using pcap_findalldevs as pcap_lookupdev is deprecated.
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }

    if (alldevs == NULL) {
        fprintf(stderr, "No network devices found.\n");
        fflush(stdout);
        return 123;
    }

    const char *interface = alldevs->name;

    // Task2.3: Check the call status of each API after the API returns(if API status can be checked).
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        fflush(stdout);
        pcap_freealldevs(alldevs);
        return 123;
    }
    pcap_freealldevs(alldevs); // Free the list of devices

    // Task2.6: Add line: printf("before pcap_snapshot\n") before calling pcap_snapshot.
    printf("before pcap_snapshot\n");
    fflush(stdout);

    // Task1: Analyze the function code to find the invocation specification that the caller needs to follow correctly.
    // The function `pcap_snapshot` checks `p->activated`.
    // If `!p->activated` is true, it returns `PCAP_ERROR_NOT_ACTIVATED`.
    // Therefore, the caller must ensure that the `pcap_t` pointer `p`
    // passed to `pcap_snapshot` is activated. In the context of `libpcap`,
    // `pcap_open_live` or `pcap_open_offline` typically activate the handle.
    // After a successful `pcap_open_live`, the handle is considered activated.
    //
    // Task2.1: The code needs to be compilable and follow the invocation specification of this function.
    // We have ensured `handle` is valid and `pcap_open_live` has been called,
    // which should activate the `pcap_t` structure.

    // Task2.2: This code needs to be non-interactive and no infinite loops.
    // Task2.3: Check the call status of each API after the API returns.
    // Task2.4: After any printf, please flush the stdout.
    // Task2.5: Output: "Calling pcap_snapshot success" after calling pcap_snapshot successfully;
    //            Output: "Calling pcap_snapshot fail" after the call to pcap_snapshot has failed.

    // VIOLATION: To violate the rule "Ensure the `pcap_t` handle is valid and points to an initialized capture session before calling `pcap_snapshot`",
    // we will close the handle *before* calling pcap_snapshot. This makes the handle invalid.
    pcap_close(handle);
    handle = NULL; // Explicitly set to NULL after closing, though pcap_close might do this internally.

    // Now, calling pcap_snapshot with a handle that has been closed.
    // This violates the rule because the handle is no longer valid or pointing to an initialized session.
    snapshot_len = pcap_snapshot(handle);

    if (snapshot_len < 0) {
        // `pcap_snapshot` returns a negative value on error,
        // and `PCAP_ERROR_NOT_ACTIVATED` is usually a negative value as well.
        fprintf(stderr, "Calling pcap_snapshot fail\n");
        // Task2.3: Output error message to infer the cause of the error.
        // The error message will likely indicate an invalid handle or a closed session.
        fprintf(stderr, "Error: Snapshot length could not be retrieved. The pcap handle is likely invalid or has been closed.\n");
        fflush(stdout);
        // No need to pcap_close(handle) again as it's already closed.
        return 123;
    } else {
        printf("Calling pcap_snapshot success\n");
        fflush(stdout);
        // Removed std:: and included necessary headers for standard C output.
        printf("Snapshot length: %d\n", snapshot_len);
        fflush(stdout);
    }

    // Clean up
    // pcap_close(handle); // This would be a double close if not handled above.
    return 0;
}

