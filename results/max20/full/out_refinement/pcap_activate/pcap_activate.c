#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    pcap_t *handle = NULL; // Initialize to NULL
    char errbuf[PCAP_ERRBUF_SIZE];
    int status;
    const char *device = "eth0"; // Replace with a valid network interface if needed, or use a pcap file

    // Initialize errbuf to be empty
    errbuf[0] = '\0';

    // 1. Open a network device for live capture (or a pcap file)
    // For this example, we'll try to open a live device.
    // pcap_open_live returns a pcap_t *, which is an opaque pointer.
    // The errbuf parameter is for libpcap to fill with an error message.
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device, errbuf);
        fflush(stderr); // Flush stderr after printing
        printf("Failed to open pcap device.\n");
        fflush(stdout);
        return 123;
    }
    printf("Successfully opened pcap device.\n");
    fflush(stdout);

    // 2. Set non-blocking mode if desired before activation
    // For this example, we will NOT set non-blocking mode to keep it simple.
    // If you wanted non-blocking:
    // handle->opt.nonblock = 1;

    // 3. Call pcap_activate
    printf("before pcap_activate\n");
    fflush(stdout);
    status = pcap_activate(handle);

    // 4. Check the status of pcap_activate
    if (status >= 0) {
        printf("Calling pcap_activate success\n");
        fflush(stdout);

        // Now 'handle' is activated and ready for packet capture
        // For a non-interactive example, we'll just close it.
        pcap_close(handle);
        printf("Successfully closed pcap handle.\n");
        fflush(stdout);
    } else {
        printf("Calling pcap_activate fail\n");
        fflush(stdout);
        // When pcap_activate fails, it sets the error message in the
        // errbuf associated with the pcap_t structure.
        // We need to retrieve this error message from the handle.
        // The original error was "invalid use of incomplete typedef 'pcap_t'".
        // This suggests that the struct definition for pcap_t might not be fully
        // available or is being accessed incorrectly.
        // However, pcap_activate is supposed to set the error in the handle's errbuf.
        // The correct way to get the error message after a pcap_activate failure
        // is to use pcap_geterr(handle).
        fprintf(stderr, "pcap_activate failed: %s\n", pcap_geterr(handle));
        fflush(stderr);

        // If pcap_activate failed, it might have partially initialized
        // the handle. Cleanup is usually handled by pcap_close.
        if (handle) {
             pcap_close(handle);
        }
        return 123;
    }

    return 0;
}

