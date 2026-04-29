#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




// Function to flush stdout
void flush_stdout() {
    fflush(stdout);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    int status;

    // Initialize errbuf to ensure it's clear
    errbuf[0] = '\0';

    // 1. Open a network device (replace "eth0" with a valid interface on your system)
    //    Using NULL for filter and snaplen, and an error buffer.
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Failed to open network device: %s\n", errbuf);
        flush_stdout();
        return 123; // Indicate failure
    }
    printf("Network device opened successfully.\n");
    flush_stdout();

    // 2. VIOLATION: Pass a NULL pointer to pcap_activate
    //    The rule states: "The pcap_t structure passed to pcap_activate must be a valid, non-NULL pointer."
    //    By setting `handle` to NULL before calling `pcap_activate`, we violate this rule.
    pcap_t *handle_to_activate = NULL; // Intentionally set to NULL

    printf("Attempting to call pcap_activate with a NULL pointer...\n");
    flush_stdout();

    status = pcap_activate(handle_to_activate);

    // 3. Check the status of pcap_activate
    //    When a NULL pointer is passed, pcap_activate is expected to return an error.
    if (status < 0) {
        printf("Calling pcap_activate with NULL pointer failed (as expected).\n");
        flush_stdout();

        // If errbuf is empty, use pcap_statustostr for a generic message
        if (errbuf[0] == '\0') {
            // Use pcap_statustostr to get a descriptive string for the status code.
            const char *status_str = pcap_statustostr(status);
            if (status_str != NULL) {
                snprintf(errbuf, PCAP_ERRBUF_SIZE, "pcap_activate failed with status %d: %s", status, status_str);
            } else {
                snprintf(errbuf, PCAP_ERRBUF_SIZE, "pcap_activate failed with unknown status %d", status);
            }
        }
        printf("Error details: %s\n", errbuf);
        flush_stdout();

        // Clean up the handle if it was successfully opened before the violation
        if (handle != NULL) {
            pcap_close(handle);
            printf("Original pcap handle closed.\n");
            flush_stdout();
        }
        return 123; // Indicate failure
    } else {
        // This branch should ideally not be reached when passing NULL,
        // but included for completeness if pcap_activate had unexpected behavior.
        printf("Calling pcap_activate with NULL pointer unexpectedly succeeded.\n");
        flush_stdout();
    }

    // The rest of the code that would normally follow a successful activation
    // is not reached in this violation scenario.

    // 4. Clean up (if the violation didn't cause an early exit)
    if (handle != NULL) {
        pcap_close(handle);
        printf("pcap handle closed.\n");
        flush_stdout();
    }

    return 0; // Indicate success (though the violation itself is a failure)
}

