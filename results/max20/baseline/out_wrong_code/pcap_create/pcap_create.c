#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


#define PCAP_ERRBUF_SIZE 256
#define EXAMPLE_FILE_NAME "example.pcap" // Example file name, though not directly used by pcap_create

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const char *device_to_open = "eth0"; // Replace with a valid network interface on your system

    // Ensure stdout is flushed after every printf
    setvbuf(stdout, NULL, _IOLBF, 0);

    // Print the initial message before calling pcap_create
    printf("before pcap_create\n");
    fflush(stdout);

    // Call pcap_create to attempt to create a capture handle
    handle = pcap_create(device_to_open, errbuf);

    // Check the status of the pcap_create call
    if (handle == NULL) {
        printf("Calling pcap_create fail\n");
        fflush(stdout);
        // Infer the cause of the error from errbuf
        fprintf(stderr, "Error in pcap_create: %s\n", errbuf);
        fflush(stderr);
        return 123; // Indicate failure
    } else {
        printf("Calling pcap_create success\n");
        fflush(stdout);

        // Although pcap_create succeeded, the handle is not yet activated.
        // For this example, we'll proceed to activate it to have a usable handle.
        // In a real application, you might perform other configurations before activation.

        // Attempt to activate the capture handle
        int activate_status = pcap_activate(handle);
        if (activate_status < 0) {
            fprintf(stderr, "Error activating capture handle: %s\n", pcap_geterr(handle));
            fflush(stderr);
            pcap_close(handle); // Clean up the handle if activation fails
            return 123;
        } else if (activate_status > 0) {
            // This indicates a warning, not a fatal error
            fprintf(stderr, "Warning during capture handle activation: %s\n", pcap_geterr(handle));
            fflush(stderr);
        } else {
            printf("Capture handle activated successfully.\n");
            fflush(stdout);

            // At this point, 'handle' is a valid, activated pcap_t object
            // and you can start capturing packets or performing other operations.
            // For this example, we'll just close it.

            printf("Closing the capture handle.\n");
            fflush(stdout);
            pcap_close(handle);
        }
    }

    return 0; // Indicate success
}

