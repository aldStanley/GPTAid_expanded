#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




#define ERROR_EXIT_CODE 123

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL; // Initialize handle to NULL
    const char *interface = "eth0"; // Replace with a valid network interface on your system

    // 1. Obtain a pcap_t handle.
    // We need a handle that is NOT YET ACTIVATED.
    // pcap_open_live returns an unactivated handle.
    handle = pcap_open_live(interface, BUFSIZ, 0, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening interface %s: %s\n", interface, errbuf);
        fflush(stdout);
        return ERROR_EXIT_CODE;
    }
    printf("Successfully opened interface %s.\n", interface);
    fflush(stdout);

    // 2. Call pcap_set_promisc BEFORE any activation.
    // The error message "pcap_set_promisc called on an activated handle"
    // indicates that pcap_open_live *itself* might have implicitly activated the handle
    // or that some operation between pcap_open_live and pcap_set_promisc caused activation.
    //
    // A common misconception is that pcap_open_live always returns an unactivated handle.
    // While it prepares the handle, certain operations, especially if the OS
    // forces certain settings, might lead to early activation.
    //
    // The most reliable way to ensure pcap_set_promisc works is to call it immediately
    // after pcap_open_live, before any other pcap functions that might activate the device.
    // In this case, the issue might be within the pcap library's behavior on the specific system.
    // However, the function's contract is clear: it must be called on an unactivated handle.
    //
    // Since the current code calls pcap_set_promisc immediately after pcap_open_live,
    // and it's still failing, it points to a potential library behavior or environment issue.
    // For the purpose of fulfilling the request to "fix the code based on the run result"
    // and following the function's invocation specification, we stick to calling it
    // right after pcap_open_live. The previous output suggests a misunderstanding of what
    // constitutes "activated" for pcap_set_promisc.

    int promisc_mode = 1; // Enable promiscuous mode

    // This check is crucial as per the function's design.
    // If pcap_check_activated(handle) returns non-zero, it means activation has occurred.
    // The original code correctly checks this *inside* pcap_set_promisc, but we want to
    // ensure our *calling* code follows the specification, which is to call it on an
    // unactivated handle.

    printf("before pcap_set_promisc\n");
    fflush(stdout);

    // VIOLATION: To violate the rule "The pcap_t handle must not be NULL when calling pcap_set_promisc",
    // we will explicitly set the handle to NULL *after* it has been successfully opened
    // and then attempt to call pcap_set_promisc. This mimics the provided violation example.
    // In a real scenario, this would be a programming error.
    pcap_close(handle); // Close the handle to ensure it's no longer valid and then set to NULL
    handle = NULL;      // Explicitly set the handle to NULL

    // Call pcap_set_promisc with a NULL handle.
    int set_promisc_result = pcap_set_promisc(handle, promisc_mode);

    if (set_promisc_result != 0) {
        fprintf(stderr, "Calling pcap_set_promisc fail: ");
        fflush(stdout);
        // When the handle is NULL, pcap_geterr might not be meaningful or might crash.
        // The primary error here is the NULL handle itself.
        if (handle == NULL) {
            fprintf(stderr, "pcap_set_promisc called with a NULL handle.\n");
            fflush(stdout);
        } else if (set_promisc_result == PCAP_ERROR_ACTIVATED) {
            fprintf(stderr, "pcap_set_promisc called on an activated handle.\n");
            fflush(stdout);
        } else {
            // Get a more specific error message if available from libpcap
            // This part might not be reached or might behave unexpectedly with a NULL handle.
            fprintf(stderr, "Error code %d: %s\n", set_promisc_result, pcap_geterr(handle));
            fflush(stdout);
        }
        // No need to pcap_close(handle) here as it's already NULL or was closed.
        return ERROR_EXIT_CODE;
    }
    printf("Calling pcap_set_promisc success\n");
    fflush(stdout);

    // This part will not be reached due to the violation.

    // 3. Close the pcap handle.
    // pcap_close(handle); // This would be called if the violation didn't occur.
    // printf("Successfully closed the pcap handle.\n");
    // fflush(stdout);

    return 0;
}

