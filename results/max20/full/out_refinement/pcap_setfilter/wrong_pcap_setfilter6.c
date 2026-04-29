#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>



#define EXIT_FAILURE_CUSTOM 123
#define FILTER_EXPRESSION "tcp port 80"
// NOTE: Replace "eth0" with a valid network interface on your system.
// If you don't have a specific interface, you might need to discover one.
// For testing purposes, using "eth0" or "en0" or "wlan0" is common.
// If none are available, pcap_open_live might fail.
#define INTERFACE_NAME "eth0"

int main() {
    pcap_t *handle = NULL;
    struct bpf_program fp; // Declared but will not be compiled
    char errbuf[PCAP_ERRBUF_SIZE];

    // 1. Open a live capture handle.
    // The timeout is set to 100ms to prevent blocking indefinitely.
    // Promiscuous mode is off (0).
    handle = pcap_open_live(INTERFACE_NAME, BUFSIZ, 0, 100, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Failed to open live capture on interface %s: %s\n", INTERFACE_NAME, errbuf);
        fflush(stdout); // Ensure the error message is displayed
        return EXIT_FAILURE_CUSTOM;
    }
    printf("Successfully opened live capture handle.\n");
    fflush(stdout);

    // 2. VIOLATION: Skip pcap_compile.
    // The struct bpf_program 'fp' is declared but not initialized by pcap_compile.
    // This directly violates the rule: "Ensure that the struct bpf_program (fp) has been properly initialized and compiled using pcap_compile or a similar mechanism before being passed to pcap_setfilter."
    printf("Skipping pcap_compile to violate the rule.\n");
    fflush(stdout);

    // 3. Call pcap_setfilter with an uncompiled bpf_program.
    printf("before pcap_setfilter\n");
    fflush(stdout); // Ensure the "before" message is flushed

    // Check if handle is valid before calling the function
    if (handle != NULL) {
        // Passing an uninitialized 'fp' to pcap_setfilter
        int setfilter_result = pcap_setfilter(handle, &fp);

        // Check the status of the pcap_setfilter API call
        if (setfilter_result == -1) {
            fprintf(stderr, "Calling pcap_setfilter fail as expected due to uncompiled filter: %s\n", pcap_geterr(handle));
            fflush(stdout);
            // Clean up resources before exiting
            // Note: pcap_freecode(&fp) is not called here because fp was never compiled.
            pcap_close(handle);
            return EXIT_FAILURE_CUSTOM;
        } else {
            // This branch is unlikely to be reached if the violation is successful.
            printf("Calling pcap_setfilter success (unexpected, might indicate a lenient pcap implementation or a different issue).\n");
            fflush(stdout);
            // Clean up resources if it unexpectedly succeeded.
            pcap_freecode(&fp); // This might still cause issues if fp was not properly initialized.
            pcap_close(handle);
            return EXIT_FAILURE_CUSTOM; // Indicate an unexpected success in a violation context.
        }
    } else {
        fprintf(stderr, "Pre-condition check failed for pcap_setfilter: handle is invalid.\n");
        fflush(stdout);
        // Clean up resources if they were partially initialized
        // Note: pcap_freecode(&fp) is not called here because fp was never compiled.
        if (handle != NULL) {
            pcap_close(handle);
        }
        return EXIT_FAILURE_CUSTOM;
    }

    // 4. Clean up resources (this part might not be reached if pcap_setfilter fails)
    // pcap_freecode(&fp); // This would be called if pcap_compile was successful.
    // printf("Freed compiled filter code successfully.\n");
    // fflush(stdout);

    // pcap_close(handle);
    // printf("Closed pcap capture handle correctly.\n");
    // fflush(stdout);

    return 0;
}

