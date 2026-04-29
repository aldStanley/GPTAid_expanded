#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int buffer_size_to_set = 4096; // Example positive buffer size
    int status;

    // Task2.1: Obtain a pcap_t handle.
    const char *interface_name = pcap_lookupdev(errbuf);
    if (interface_name == NULL) {
        fprintf(stderr, "Error finding default interface: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Using interface: %s\n", interface_name);
    fflush(stdout);

    handle = pcap_open_live(interface_name, 0, 0, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Unable to open capture device %s: %s\n", interface_name, errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Successfully opened capture device.\n");
    fflush(stdout);

    // VIOLATION: Close the handle before calling pcap_set_buffer_size
    pcap_close(handle);
    printf("Pcap handle closed prematurely.\n");
    fflush(stdout);

    // Task2.6: Add the required printf before calling pcap_set_buffer_size
    printf("before pcap_set_buffer_size\n");
    fflush(stdout);

    // Task2.1 & 2.5: Call pcap_set_buffer_size with a dangling pointer
    // This will violate the rule: "Ensure that the pcap_t pointer passed to pcap_set_buffer_size is not a dangling pointer."
    status = pcap_set_buffer_size(handle, buffer_size_to_set);

    if (status != 0) {
        fprintf(stderr, "Calling pcap_set_buffer_size fail: Error code %d\n", status);
        fflush(stdout);
        // Task2.3: Check for specific error code if known
        if (status == PCAP_ERROR_ACTIVATED) {
            fprintf(stderr, "Reason: The pcap handle has already been activated.\n");
            fflush(stdout);
        } else {
            // When the handle is dangling, pcap_geterr might not provide a useful message,
            // or it might even crash depending on the libpcap implementation and OS.
            // We'll still attempt to print it for completeness, but expect it to be uninformative.
            fprintf(stderr, "Reason: %s\n", pcap_geterr(handle));
            fflush(stdout);
        }
        // We don't need to pcap_close(handle) here because it was already closed.
        // Attempting to close it again might lead to a double-free error.
        return 123;
    } else {
        printf("Calling pcap_set_buffer_size success\n");
        fflush(stdout);
    }

    // The rest of the code related to pcap_activate and further operations
    // will likely not be reached or will also fail due to the dangling pointer.
    // We include them for structural completeness but they are effectively dead code
    // in this violation scenario.

    // Task2.1: Activate the capture handle (this must be after pcap_set_buffer_size)
    status = pcap_activate(handle);
    if (status != 0) {
        fprintf(stderr, "Error activating the capture: %s\n", pcap_geterr(handle));
        fflush(stdout);
        // Again, handle is already closed.
        return 123;
    }
    printf("Capture handle activated successfully.\n");
    fflush(stdout);

    // Task2.2: Non-interactive and no infinite loops.
    // For demonstration, we will not start capturing or process packets.
    // In a real application, you would likely call pcap_loop or pcap_next_ex here.

    // Clean up
    // pcap_close(handle); // This would be a double-free if reached.
    printf("Pcap handle was already closed.\n");
    fflush(stdout);

    return 0;
}

