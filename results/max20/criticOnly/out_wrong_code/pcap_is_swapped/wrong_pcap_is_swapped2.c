#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Task2.1: Attempt to open a network device.
    // We'll try to open the first available device. This might require root privileges.
    // If it fails, we'll try opening a dummy file.
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device eth0, trying dummy file: %s\n", errbuf);
        fflush(stdout);
        // Task2.7: Use example.pcap for file operations
        handle = pcap_open_offline("example.pcap", errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Could not open dummy file example.pcap: %s\n", errbuf);
            fflush(stdout);
            return 123; // Indicate failure with a specific exit code
        }
    }

    // Task2.3 & 2.5: Check the status of pcap_open_live/pcap_open_offline
    if (handle == NULL) {
        printf("Opening pcap handle failed\n");
        fflush(stdout);
        return 123;
    }

    // Task2.6: Add the specified printf before calling pcap_is_swapped
    printf("before pcap_is_swapped\n");
    fflush(stdout);

    // Task2.1: Call pcap_is_swapped.
    // The invocation specification for pcap_is_swapped is that the pcap_t pointer must point
    // to an activated pcap handle. pcap_open_live and pcap_open_offline activate the handle.

    // VIOLATION: Passing a NULL pointer for the pcap_t handle.
    // This directly violates the rule "Do not pass a NULL pointer for the pcap_t handle."
    // Consistent with the violation example, we are passing NULL.
    int result = pcap_is_swapped(NULL);

    // Task2.3 & 2.5: Check the call status of pcap_is_swapped
    // Note: When passing NULL, pcap_is_swapped will likely return an error or crash
    // before reaching these checks. The error handling below is for a valid handle.
    // However, to demonstrate the violation, we keep the structure.
    if (result == PCAP_ERROR_NOT_ACTIVATED) {
        printf("Calling pcap_is_swapped fail\n");
        fflush(stdout);
        // Task2.3: Output error message
        fprintf(stderr, "pcap_is_swapped: pcap handle is not activated.\n");
        fflush(stdout);
        pcap_close(handle);
        return 123;
    } else if (result < 0) { // pcap_is_swapped can return negative error codes
        printf("Calling pcap_is_swapped fail\n");
        fflush(stdout);
        // Task2.3: Output error message using pcap_geterr
        // This part might not be reached if NULL causes a crash.
        fprintf(stderr, "pcap_is_swapped error: %s\n", pcap_geterr(handle));
        fflush(stdout);
        pcap_close(handle);
        return 123;
    } else {
        printf("Calling pcap_is_swapped success\n");
        fflush(stdout);
        printf("pcap_is_swapped returned: %d\n", result);
        fflush(stdout);
    }

    // Clean up
    pcap_close(handle);

    return 0;
}

