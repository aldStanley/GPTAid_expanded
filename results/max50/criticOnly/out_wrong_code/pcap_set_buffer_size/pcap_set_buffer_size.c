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
    // We'll use pcap_open_live for demonstration, assuming a network interface exists.
    // In a real-world scenario, you might want to list interfaces and let the user choose.
    const char *interface_name = pcap_lookupdev(errbuf);
    if (interface_name == NULL) {
        fprintf(stderr, "Error finding default interface: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Using interface: %s\n", interface_name);
    fflush(stdout);

    // To ensure pcap_set_buffer_size is called before activation, we open with snaplen 0 and promisc 0.
    // pcap_open_live itself does NOT activate the handle. Activation happens with pcap_activate.
    // The previous attempts might have been failing because of some internal libpcap behavior
    // or how the specific environment was interpreting the initial open.
    // We will proceed with the explicit pcap_activate call after setting the buffer size.
    handle = pcap_open_live(interface_name, 0, 0, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Unable to open capture device %s: %s\n", interface_name, errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Successfully opened capture device.\n");
    fflush(stdout);

    // Task2.6: Add the required printf before calling pcap_set_buffer_size
    printf("before pcap_set_buffer_size\n");
    fflush(stdout);

    // Task2.1 & 2.5: Call pcap_set_buffer_size and check its status
    status = pcap_set_buffer_size(handle, buffer_size_to_set);

    if (status != 0) {
        fprintf(stderr, "Calling pcap_set_buffer_size fail: Error code %d\n", status);
        fflush(stdout);
        // Task2.3: Check for specific error code if known
        if (status == PCAP_ERROR_ACTIVATED) {
            fprintf(stderr, "Reason: The pcap handle has already been activated.\n");
            fflush(stdout);
        } else {
            // If pcap_set_buffer_size returns an error other than PCAP_ERROR_ACTIVATED,
            // it's likely a system-level error or invalid parameter for the underlying OS.
            // The error message from pcap_geterr is more informative here.
            fprintf(stderr, "Reason: %s\n", pcap_geterr(handle));
            fflush(stdout);
        }
        pcap_close(handle);
        return 123;
    } else {
        printf("Calling pcap_set_buffer_size success\n");
        fflush(stdout);
    }

    // Task2.1: Activate the capture handle (this must be after pcap_set_buffer_size)
    status = pcap_activate(handle);
    if (status != 0) {
        fprintf(stderr, "Error activating the capture: %s\n", pcap_geterr(handle));
        fflush(stdout);
        pcap_close(handle);
        return 123;
    }
    printf("Capture handle activated successfully.\n");
    fflush(stdout);

    // Task2.2: Non-interactive and no infinite loops.
    // For demonstration, we will not start capturing or process packets.
    // In a real application, you would likely call pcap_loop or pcap_next_ex here.

    // Clean up
    pcap_close(handle);
    printf("Pcap handle closed.\n");
    fflush(stdout);

    return 0;
}

