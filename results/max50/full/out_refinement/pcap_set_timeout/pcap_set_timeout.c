#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




// Define a constant for the error exit code
#define EXIT_FAILURE_CODE 123

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *interface = "eth0"; // Replace with a valid network interface on your system
    int timeout_value = 1000; // Timeout in milliseconds (e.g., 1 second)

    // 1. Open a live capture handle.
    // It is crucial to call pcap_set_timeout immediately after opening the handle
    // and before any operation that might activate the capture.
    handle = pcap_open_live(interface, BUFSIZ, 0, 0, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening interface %s: %s\n", interface, errbuf);
        fflush(stdout); // Flush stdout as per requirement 4
        return EXIT_FAILURE_CODE;
    }
    printf("Successfully opened pcap handle.\n");
    fflush(stdout); // Flush stdout as per requirement 4

    // Add the required printf statement before calling pcap_set_timeout
    printf("before pcap_set_timeout\n");
    fflush(stdout); // Flush stdout as per requirement 4

    // 2. Call pcap_set_timeout.
    // This must be called before the capture is activated.
    int result = pcap_set_timeout(handle, timeout_value);

    // 3. Check the status of the pcap_set_timeout call
    if (result != 0) {
        fprintf(stderr, "Calling pcap_set_timeout fail\n");
        fflush(stdout); // Flush stdout as per requirement 4

        // Attempt to get a more specific error message from libpcap if available
        // pcap_geterr can be used after a failed pcap operation.
        char *pcap_error = pcap_geterr(handle);
        if (pcap_error != NULL && strlen(pcap_error) > 0) {
            fprintf(stderr, "pcap_set_timeout error details: %s\n", pcap_error);
            fflush(stdout); // Flush stdout as per requirement 4
        } else {
            fprintf(stderr, "pcap_set_timeout returned error code: %d\n", result);
            fflush(stdout); // Flush stdout as per requirement 4
        }
        pcap_close(handle);
        return EXIT_FAILURE_CODE;
    } else {
        printf("Calling pcap_set_timeout success\n");
        fflush(stdout); // Flush stdout as per requirement 4
    }

    // 4. Clean up: Close the pcap handle.
    // We are not activating capture, so no need for further capture-related operations.
    pcap_close(handle);
    printf("Pcap handle closed.\n");
    fflush(stdout); // Flush stdout as per requirement 4

    return 0;
}

