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

    // --- VIOLATION START ---
    // Rule: The pcap_t structure must be properly initialized before being passed to pcap_activate.
    // Violation: We will create a pcap_t variable and pass its address to pcap_activate
    // without it being properly initialized by pcap_open_live or pcap_create.
    // This simulates passing an uninitialized or improperly initialized structure.
    // In a real scenario, this might happen if a pointer is accidentally set to NULL
    // or points to garbage memory before pcap_activate is called.

    // To simulate this, we will create a local pcap_t variable and pass its address.
    // This variable will not have gone through the initialization process of pcap_open_live.
    // Note: Directly declaring `pcap_t uninitialized_handle;` and passing `&uninitialized_handle`
    // would lead to a compilation error because `pcap_t` is an incomplete type.
    // The violation example shows passing an uninitialized `pcap_t` *structure*, not a pointer
    // to a structure that was never allocated or initialized by libpcap functions.
    // The most direct way to violate the rule as per the example is to pass a pointer
    // to a `pcap_t` that has not been successfully returned by `pcap_open_live` or `pcap_create`.
    // We will achieve this by setting `handle` to NULL *after* it was successfully opened,
    // and then passing this NULL pointer to `pcap_activate`. This is a common way a pointer
    // might become invalid or uninitialized before a function call.

    printf("About to intentionally violate the rule by passing an invalid handle to pcap_activate.\n");
    flush_stdout();

    // Intentionally invalidate the handle pointer before calling pcap_activate
    // This simulates passing an uninitialized or invalid pcap_t pointer.
    pcap_close(handle); // Close the valid handle to ensure it's no longer valid
    handle = NULL;      // Set the pointer to NULL to represent an uninitialized/invalid state

    // Now, call pcap_activate with a NULL pointer, violating the initialization rule.
    // The pcap_activate function expects a valid, initialized pcap_t pointer.
    status = pcap_activate(handle);
    // --- VIOLATION END ---

    // 4. Check the status of pcap_activate
    if (status < 0) {
        printf("Calling pcap_activate failed (as expected due to invalid handle).\n");
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

        // No need to clean up `handle` here as it's already NULL or was closed.
        return 123; // Indicate failure
    } else {
        // This part of the code should not be reached if the violation is successful.
        printf("Calling pcap_activate succeeded unexpectedly. This indicates the violation might not have worked as intended.\n");
        flush_stdout();

        // If by some chance it succeeded, we would proceed, but the goal is to fail.
        int nonblock_status = pcap_setnonblock(handle, 1, errbuf);
        if (nonblock_status < 0) {
            printf("Failed to set non-blocking mode: %s\n", errbuf);
            flush_stdout();
        } else {
            printf("Non-blocking mode is now enabled.\n");
            flush_stdout();
        }

        // Example: Capture a few packets (now in non-blocking mode)
        struct pcap_pkthdr *header;
        const u_char *packet;
        int packet_count = 0;
        int max_packets_to_capture = 5; // Capture a small number of packets

        printf("Starting packet capture (non-blocking mode enabled)...\n");
        flush_stdout();

        int timeout_ms = 100; // 100 milliseconds

        while (packet_count < max_packets_to_capture) {
            int result = pcap_next_ex(handle, &header, &packet);

            if (result == 1) { // Packet received
                printf("Packet %d captured: Length = %d\n", packet_count + 1, header->len);
                flush_stdout();
                packet_count++;
            } else if (result == 0) { // Timeout
                // Continue loop
            } else if (result == -1) { // Error
                printf("Error during packet capture: %s\n", pcap_geterr(handle));
                flush_stdout();
                break; // Exit loop on capture error
            } else if (result == -2) { // EOF
                printf("End of file reached.\n");
                flush_stdout();
                break; // Exit loop if reading from a file and EOF is reached
            }
        }
        printf("Finished packet capture.\n");
        flush_stdout();
    }

    // Clean up if handle is still valid (which it shouldn't be if the violation worked)
    if (handle != NULL) {
        pcap_close(handle);
        printf("pcap handle closed.\n");
        flush_stdout();
    }

    return 0; // Indicate success (though the goal is to return 123)
}

