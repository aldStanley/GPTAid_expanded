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
    struct bpf_program fp;
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

    // 2. Compile the filter expression.
    // PCAP_NETMASK_UNKNOWN is used when the network mask is not known or needed.
    if (pcap_compile(handle, &fp, FILTER_EXPRESSION, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error compiling filter '%s': %s\n", FILTER_EXPRESSION, pcap_geterr(handle));
        fflush(stdout);
        pcap_close(handle); // Clean up the handle
        return EXIT_FAILURE_CUSTOM;
    }
    printf("Successfully compiled BPF filter program.\n");
    fflush(stdout);

    // 3. Call pcap_setfilter
    printf("before pcap_setfilter\n");
    fflush(stdout); // Ensure the "before" message is flushed

    // Check if handle is valid before calling the function
    // pcap_setfilter expects a valid pcap_t and a valid bpf_program
    if (handle != NULL) {
        int setfilter_result = pcap_setfilter(handle, &fp);

        // Check the status of the pcap_setfilter API call
        if (setfilter_result == -1) {
            fprintf(stderr, "Calling pcap_setfilter fail: %s\n", pcap_geterr(handle));
            fflush(stdout);
            // Clean up resources before exiting
            pcap_freecode(&fp);
            pcap_close(handle);
            return EXIT_FAILURE_CUSTOM;
        } else {
            printf("Calling pcap_setfilter success\n");
            fflush(stdout);
        }
    } else {
        fprintf(stderr, "Pre-condition check failed for pcap_setfilter: handle is invalid.\n");
        fflush(stdout);
        // Clean up resources if they were partially initialized
        pcap_freecode(&fp);
        if (handle != NULL) { // This check is technically redundant here due to the outer if, but good for robustness
            pcap_close(handle);
        }
        return EXIT_FAILURE_CUSTOM;
    }

    // 4. Clean up resources
    // Free the compiled BPF code.
    pcap_freecode(&fp);
    printf("Freed compiled filter code successfully.\n");
    fflush(stdout);

    // Close the pcap capture handle.
    pcap_close(handle);
    printf("Closed pcap capture handle correctly.\n");
    fflush(stdout);

    return 0;
}

