#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




// Define a custom error code for pcap_setfilter failure
#define PCAP_SETFILTER_ERROR_CODE 123

int main() {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp; // To store compiled filter program
    const char *filter_exp;
    const char *interface = "eth0"; // Replace with a valid interface on your system

    // 1. Open a live capture handle
    printf("Attempting to open pcap handle on interface %s\n", interface);
    fflush(stdout);

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", interface, errbuf);
        fflush(stderr);
        return 123; // Using the specified exit code for general failure
    }
    printf("Successfully opened pcap handle.\n");
    fflush(stdout);

    // 2. Compile the filter expression
    filter_exp = "tcp";
    printf("Compiling filter expression: \"%s\"\n", filter_exp);
    fflush(stdout);

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        fflush(stderr);
        pcap_close(handle);
        return 123;
    }
    printf("Filter compiled successfully.\n");
    fflush(stdout);

    // 3. Set the compiled filter
    printf("before first pcap_setfilter\n");
    fflush(stdout);

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Calling first pcap_setfilter fail: %s\n", pcap_geterr(handle));
        fflush(stderr);
        pcap_freecode(&fp); // Free the compiled filter
        pcap_close(handle); // Close the pcap handle
        return PCAP_SETFILTER_ERROR_CODE; // Use the specific error code
    }

    printf("Calling first pcap_setfilter success\n");
    fflush(stdout);

    // --- VIOLATION START ---
    // Close the pcap handle
    printf("Closing pcap handle.\n");
    fflush(stdout);
    pcap_close(handle);
    handle = NULL; // Explicitly set to NULL to indicate it's closed

    // Attempt to set the filter again on the closed handle
    printf("Attempting to call pcap_setfilter on a closed handle.\n");
    fflush(stdout);

    // This call will violate the rule because 'handle' is already closed.
    // The behavior of pcap_setfilter with a closed handle is undefined,
    // but it's a clear violation of the rule.
    if (pcap_setfilter(handle, &fp) == -1) {
        // We expect this to fail, but the primary goal is to demonstrate the violation.
        // pcap_geterr might return an error related to an invalid handle.
        fprintf(stderr, "Calling pcap_setfilter on closed handle (expected failure): %s\n", pcap_geterr(handle));
        fflush(stderr);
        // Note: pcap_geterr might behave unexpectedly or crash after pcap_close.
        // In a real scenario, you would not proceed after closing.
    } else {
        // This branch should ideally not be reached if pcap_setfilter correctly
        // detects a closed handle.
        printf("Unexpected success calling pcap_setfilter on a closed handle.\n");
        fflush(stdout);
    }
    // --- VIOLATION END ---


    // 4. Cleanup
    // Note: pcap_freecode(&fp) is still valid as 'fp' is a separate structure.
    pcap_freecode(&fp); // Free the compiled filter
    // pcap_close(handle); // This would be a double close if not for the violation above.
    printf("Filter freed.\n");
    fflush(stdout);

    // If the violation occurred and we didn't exit, we might return a specific code.
    // However, the primary goal is to demonstrate the violation.
    // In a real program, you would likely exit immediately after detecting the violation.
    return 0; // Success (if no critical errors occurred before the violation attempt)
}

