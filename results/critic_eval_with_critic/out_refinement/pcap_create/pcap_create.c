#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


// Define PCAP_ERRBUF_SIZE if it's not already defined by pcap.h
#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE 256
#endif

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *device_name = "eth0"; // Replace with a valid device name on your system, or NULL for "any"

    // Ensure stdout is flushed after every printf
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("before pcap_create\n");
    fflush(stdout); // Flush stdout

    // Attempt to create a pcap handle
    handle = pcap_create(device_name, errbuf);

    if (handle == NULL) {
        printf("Calling pcap_create fail\n");
        fflush(stdout); // Flush stdout
        fprintf(stderr, "Error from pcap_create: %s\n", errbuf);
        fflush(stderr); // Flush stderr
        return 123; // Indicate failure
    } else {
        printf("Calling pcap_create success\n");
        fflush(stdout); // Flush stdout

        // Optional: Set capture properties if needed.
        // For demonstration, let's set a snaplen and a timeout.
        int snaplen = 65535; // Capture up to 65535 bytes per packet
        int timeout_ms = 1000; // 1 second timeout

        // Set snaplen
        if (pcap_set_snaplen(handle, snaplen) != 0) {
            fprintf(stderr, "Error setting snaplen: %s\n", pcap_geterr(handle));
            fflush(stderr); // Flush stderr
            pcap_close(handle);
            return 123;
        }
        printf("Snaplen set successfully.\n");
        fflush(stdout); // Flush stdout


        // Set timeout
        if (pcap_set_timeout(handle, timeout_ms) != 0) {
            fprintf(stderr, "Error setting timeout: %s\n", pcap_geterr(handle));
            fflush(stderr); // Flush stderr
            pcap_close(handle);
            return 123;
        }
        printf("Timeout set successfully.\n");
        fflush(stdout); // Flush stdout

        // Activate the capture handle. This is a separate step from pcap_create.
        // pcap_create prepares the handle, pcap_activate makes it ready for capturing.
        if (pcap_activate(handle) != 0) {
            fprintf(stderr, "Error activating pcap handle: %s\n", pcap_geterr(handle));
            fflush(stderr); // Flush stderr
            pcap_close(handle);
            return 123;
        }
        printf("pcap_activate success.\n");
        fflush(stdout); // Flush stdout

        // At this point, 'handle' is ready to be used for capturing.
        // For this example, we'll just close it.

        printf("Closing pcap handle.\n");
        fflush(stdout); // Flush stdout
        pcap_close(handle);
    }

    return 0; // Indicate success
}

