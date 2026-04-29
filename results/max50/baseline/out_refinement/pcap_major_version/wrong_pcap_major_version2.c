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

    // --- VIOLATION START ---
    // Violate Rule: The `pcap_t` pointer must point to a valid and initialized `pcap_t` structure.
    // We are passing a NULL pointer to pcap_major_version.
    // This is a direct violation of the rule, similar to the example where an uninitialized handle is used.
    // A NULL pointer is not a valid and initialized pcap_t structure.
    major_version = pcap_major_version(NULL);
    // --- VIOLATION END ---

    // The original code's error checking for PCAP_ERROR_NOT_ACTIVATED is still relevant,
    // but the primary violation is passing NULL.
    // Depending on the pcap library implementation, passing NULL might result in a crash,
    // a specific error code, or undefined behavior.
    // For the purpose of demonstrating the violation, we'll check for a negative return value,
    // which is a common way pcap functions indicate errors.
    if (major_version < 0) {
        printf("Calling pcap_major_version fail (due to NULL pointer)\n");
        fflush(stdout); // Task2.4
        // The error message might not be specific to NULL, but it indicates a failure.
        fprintf(stderr, "Error: pcap_major_version failed. Likely due to an invalid pcap handle (NULL).\n");
        fflush(stdout); // Task2.4
        // We still need to close the valid handle if it was opened, but in this specific
        // violation scenario, the NULL pointer is passed *after* a valid handle was obtained.
        // However, to be consistent with the violation, we'll proceed as if the error
        // occurred during the call. If the program were to continue, it would be
        // problematic. For this example, we'll just report the error and exit.
        // If the intention was to *only* test the NULL pointer, we wouldn't have opened a handle.
        // But to modify the *right code*, we keep the handle opening and then introduce the violation.
        pcap_close(handle); // Close the valid handle that was opened earlier.
        return 123; // Task2.3
    } else {
        // This branch is unlikely to be reached with a NULL pointer, but kept for completeness
        // if the pcap library had a very unusual way of handling NULL.
        printf("Calling pcap_major_version success\n");
        fflush(stdout); // Task2.4
        printf("Pcap major version: %d\n", major_version);
        fflush(stdout); // Task2.4
    }

    // Task2.2: Non-interactive and no infinite loops. Cleanup.
    pcap_close(handle);
    printf("pcap_close succeeded.\n");
    fflush(stdout); // Task2.4

    return 0;
}

