#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int major_version;

    // Task2.1: Open a network interface to get an activated pcap handle
    // We choose the first available network interface. If none is available,
    // this will fail.
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening interface eth0: %s\n", errbuf);
        fflush(stdout); // Task2.4
        return 123; // Task2.3
    }
    printf("pcap_open_live succeeded.\n");
    fflush(stdout); // Task2.4

    // Task2.6: Add line before calling pcap_major_version
    printf("before pcap_major_version\n");
    fflush(stdout); // Task2.4

    // VIOLATION: Call pcap_major_version BEFORE the handle is guaranteed to be activated.
    // In the original "right code", pcap_open_live is called and if it succeeds,
    // the handle is considered activated.
    // To violate the rule, we will simulate a scenario where pcap_major_version
    // is called on a handle that is *not* activated.
    // The example violation code shows two ways:
    // 1. A handle that was never opened or is NULL.
    // 2. A handle that was opened but then closed.
    // We will simulate the second scenario by closing the handle *before* calling pcap_major_version.

    // Close the handle to make it unactivated.
    pcap_close(handle);
    printf("pcap_close called before pcap_major_version to simulate unactivated handle.\n");
    fflush(stdout); // Task2.4

    // Now, call pcap_major_version on the closed (unactivated) handle.
    // This will violate the rule that the handle must be activated.
    major_version = pcap_major_version(handle);

    // The expected outcome of calling pcap_major_version on an unactivated handle
    // is PCAP_ERROR_NOT_ACTIVATED.
    if (major_version == PCAP_ERROR_NOT_ACTIVATED) {
        printf("Calling pcap_major_version on unactivated handle resulted in expected error.\n");
        fflush(stdout); // Task2.4
        fprintf(stderr, "Error: pcap_major_version failed because the pcap handle is not activated (as intended by the violation).\n");
        fflush(stdout); // Task2.4
        // No need to pcap_close(handle) again as it's already closed.
        return 123; // Task2.3
    } else if (major_version < 0) {
        // Handle other potential pcap errors if pcap_major_version could return them
        printf("Calling pcap_major_version on unactivated handle resulted in an unexpected error.\n");
        fflush(stdout); // Task2.4
        fprintf(stderr, "An unexpected error occurred while calling pcap_major_version on an unactivated handle. Error code: %d\n", major_version);
        fflush(stdout); // Task2.4
        // No need to pcap_close(handle) again as it's already closed.
        return 123; // Task2.3
    } else {
        // This branch should ideally not be reached if the violation is successful.
        printf("Calling pcap_major_version on unactivated handle unexpectedly succeeded.\n");
        fflush(stdout); // Task2.4
        printf("Pcap major version: %d\n", major_version);
        fflush(stdout); // Task2.4
        // No need to pcap_close(handle) again as it's already closed.
        return 123; // Task2.3
    }

    // Task2.2: Non-interactive and no infinite loops. Cleanup.
    // The handle is already closed, so this part is effectively skipped for the violated path.
    // If the violation path was not taken (e.g., pcap_open_live failed),
    // then handle would be NULL and pcap_close(NULL) is safe.
    // However, in the violation scenario, handle is a valid pointer to a closed structure.
    // Calling pcap_close on an already closed handle might be undefined behavior,
    // but for the purpose of demonstrating the violation, we've already achieved it.
    // In a real program, you'd ensure pcap_close is only called once.
    // For this specific violation demonstration, we've already closed it.
    // If the code were to proceed here, it would be after the return statement.

    return 0;
}

