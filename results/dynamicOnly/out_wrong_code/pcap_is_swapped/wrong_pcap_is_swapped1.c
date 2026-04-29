#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    pcap_t *handle = NULL; // Initialize handle to NULL
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *device = pcap_lookupdev(errbuf);

    if (device == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }

    // Intentionally do NOT open a capture handle.
    // We will attempt to call pcap_is_swapped with a NULL handle,
    // which is a direct violation of the rule "Ensure the pcap_t handle is activated".
    // A NULL handle is by definition not activated.

    printf("before pcap_is_swapped (attempting to call with NULL handle)\n");
    fflush(stdout);

    // VIOLATION: Calling pcap_is_swapped with a NULL handle.
    // This violates the rule because the pcap_t handle is not activated (it's NULL).
    int swapped_status = pcap_is_swapped(handle);

    if (swapped_status == PCAP_ERROR_NOT_ACTIVATED) {
        printf("Calling pcap_is_swapped fail as expected for a NULL handle\n");
        fflush(stdout);
        fprintf(stderr, "pcap_is_swapped failed: The pcap handle is NULL, hence not activated.\n");
        fflush(stdout);
        // No need to close handle as it was never opened.
        return 123;
    } else if (swapped_status < 0) {
        // pcap_is_swapped can return negative error codes other than PCAP_ERROR_NOT_ACTIVATED
        printf("Calling pcap_is_swapped fail with unexpected error for a NULL handle\n");
        fflush(stdout);
        fprintf(stderr, "pcap_is_swapped encountered an unexpected error: %d\n", swapped_status);
        fflush(stdout);
        // No need to close handle as it was never opened.
        return 123;
    } else {
        printf("Calling pcap_is_swapped success (unexpected for a NULL handle)\n");
        fflush(stdout);
        printf("pcap_is_swapped returned: %d\n", swapped_status);
        fflush(stdout);
    }

    // No pcap_close needed as handle was never successfully opened.
    return 0;
}

