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

    // We will not open a capture handle in this modified code to ensure 'handle' remains NULL
    // when passed to pcap_is_swapped.

    printf("before pcap_is_swapped\n");
    fflush(stdout);

    // VIOLATION: Passing a NULL pointer for the pcap_t handle.
    // This directly violates the rule "Do not pass a NULL pointer for the pcap_t handle."
    // The example violation code also passes NULL to pcap_is_swapped.
    int swapped_status = pcap_is_swapped(handle);

    // The following checks are technically unreachable if handle is NULL and pcap_is_swapped
    // immediately causes a segmentation fault or returns an error before these checks.
    // However, to maintain consistency with the structure of the original "right code"
    // and to show how the error would be handled if the function *could* return an error
    // without crashing, we keep them. In practice, passing NULL here will likely crash.

    if (swapped_status == PCAP_ERROR_NOT_ACTIVATED) {
        printf("Calling pcap_is_swapped fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_is_swapped failed: The pcap handle is not activated.\n");
        fflush(stdout);
        // No need to pcap_close(handle) as handle is NULL
        return 123;
    } else if (swapped_status < 0) {
        printf("Calling pcap_is_swapped fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_is_swapped encountered an unexpected error: %d\n", swapped_status);
        fflush(stdout);
        // No need to pcap_close(handle) as handle is NULL
        return 123;
    } else {
        printf("Calling pcap_is_swapped success\n");
        fflush(stdout);
        printf("pcap_is_swapped returned: %d\n", swapped_status);
        fflush(stdout);
    }

    // No need to pcap_close(handle) as handle is NULL
    return 0;
}

