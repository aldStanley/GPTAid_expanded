#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int ret_val;

    // Attempt to open a live capture handle.
    // Replace "eth0" with a valid network interface name on your system.
    // For a non-interactive example, we'll just try to open the first available.
    // In a real-world scenario, you might want to list interfaces and let the user choose.
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening adapter: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Successfully opened pcap handle.\n");
    fflush(stdout);

    // --- Calling pcap_set_tstamp_type ---

    // Example: Try to set the timestamp type to host time.
    // PCAP_TSTAMP_HOST is generally well-supported.
    int desired_tstamp_type = PCAP_TSTAMP_HOST;

    printf("before pcap_set_tstamp_type\n");
    fflush(stdout);

    ret_val = pcap_set_tstamp_type(handle, desired_tstamp_type);

    // Check the return value of pcap_set_tstamp_type
    if (ret_val == 0) {
        printf("Calling pcap_set_tstamp_type success\n");
        fflush(stdout);
    } else {
        printf("Calling pcap_set_tstamp_type fail\n");
        fflush(stdout);
        // Output error message to infer the cause of the error
        if (ret_val == PCAP_ERROR_ACTIVATED) {
            fprintf(stderr, "pcap_set_tstamp_type failed: Capture handle is already activated.\n");
            fflush(stdout);
        } else if (ret_val == PCAP_WARNING_TSTAMP_TYPE_NOTSUP) {
            fprintf(stderr, "pcap_set_tstamp_type failed: The requested timestamp type (%d) is not supported.\n", desired_tstamp_type);
            fflush(stdout);
        } else {
            // Generic error handling if there are other possible return codes
            fprintf(stderr, "pcap_set_tstamp_type failed with unknown error code: %d\n", ret_val);
            fflush(stdout);
        }
        pcap_close(handle); // Close handle before exiting on error
        return 123;
    }

    // --- Other pcap operations can follow here ---
    // For this example, we will just close the handle.
    // If you were to capture packets, you would use pcap_loop or pcap_next_ex.
    // Since this code is non-interactive and has no infinite loops, we won't start a capture.

    pcap_close(handle);
    printf("Successfully closed pcap handle.\n");
    fflush(stdout);

    return 0;
}

