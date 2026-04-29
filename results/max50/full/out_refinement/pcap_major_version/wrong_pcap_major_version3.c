#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int major_version;

    // Open a pcap device for live capturing.
    // This is necessary to activate the pcap handle before calling pcap_major_version.
    // We are using "any" for the device to be general, but in a real scenario,
    // you might want to specify a specific network interface.
    handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Unable to open device: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("pcap_open_live succeeded.\n");
    fflush(stdout);

    // Task2.6: Output before calling pcap_major_version
    printf("before pcap_major_version\n");
    fflush(stdout);

    // --- VIOLATION START ---
    // To violate the rule "The pcap_t handle must be activated before calling pcap_major_version",
    // we will call pcap_close() on the handle *before* calling pcap_major_version().
    // This effectively deactivates the handle.

    printf("Calling pcap_close() to deactivate the handle before calling pcap_major_version().\n");
    fflush(stdout);
    pcap_close(handle);
    // Now 'handle' is no longer an activated pcap_t.

    // Call pcap_major_version on the deactivated handle
    major_version = pcap_major_version(handle);
    // --- VIOLATION END ---

    // Task2.5: Check the return value and print accordingly
    // We expect PCAP_ERROR_NOT_ACTIVATED here because we explicitly deactivated the handle.
    if (major_version == PCAP_ERROR_NOT_ACTIVATED) {
        printf("Calling pcap_major_version fail as expected (handle was deactivated).\n");
        fflush(stdout);
        fprintf(stderr, "pcap_major_version returned PCAP_ERROR_NOT_ACTIVATED, as expected after pcap_close().\n");
        fflush(stdout);
        // No need to call pcap_close(handle) again as it's already closed.
        return 123;
    } else if (major_version < 0) {
        // pcap_major_version can return negative values on other errors.
        printf("Calling pcap_major_version fail with an unexpected error.\n");
        fflush(stdout);
        fprintf(stderr, "pcap_major_version failed with error code: %d\n", major_version);
        fflush(stdout);
        // No need to call pcap_close(handle) again as it's already closed.
        return 123;
    } else {
        printf("Calling pcap_major_version success (unexpected).\n");
        fflush(stdout);
        printf("Major version: %d\n", major_version);
        fflush(stdout);
        // This branch should ideally not be reached if the violation is successful.
        // If it is reached, it means the handle was still considered activated,
        // which would be a failure of the violation attempt.
    }

    // This part of the code will not be reached if the violation is successful
    // and the program exits with 123.
    // If for some reason the violation didn't trigger the error, we would close here.
    // However, since we explicitly closed it earlier, this is redundant and potentially problematic
    // if pcap_close is called on an already closed handle.
    // For clarity in the violation scenario, we omit a redundant pcap_close here.

    return 0;
}

