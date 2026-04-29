#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


#define PCAP_ERRBUF_SIZE 256 // A reasonable buffer size for error messages

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *device_to_open = "eth0"; // Example device, replace with a valid one on your system

    // Add line:
    printf("before pcap_create\n");
    fflush(stdout); // Flush stdout after printing

    // Call pcap_create
    handle = pcap_create(device_to_open, errbuf);

    // Check the call status of pcap_create
    if (handle == NULL) {
        // Output: "Calling pcap_create fail"
        printf("Calling pcap_create fail\n");
        fflush(stdout); // Flush stdout after printing

        // Output error message to infer the cause of the error
        fprintf(stderr, "pcap_create failed: %s\n", errbuf);
        fflush(stderr); // Flush stderr after printing
        return 123; // Return a non-zero exit code to indicate failure
    } else {
        // Output: "Calling pcap_create success"
        printf("Calling pcap_create success\n");
        fflush(stdout); // Flush stdout after printing
    }

    // At this point, 'handle' is a valid pcap_t.
    // For this example, we will just close it.
    // In a real application, you would then use pcap_activate()
    // and other pcap functions.

    // Freeing the allocated device string is handled by pcap_close().
    // As per the code, p->opt.device is managed by pcap_close().
    pcap_close(handle);

    return 0; // Indicate successful execution
}

