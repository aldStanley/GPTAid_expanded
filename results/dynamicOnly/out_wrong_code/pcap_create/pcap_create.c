#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const char *device_name = NULL; // Using NULL to test "any" device

    // Add the required line before calling pcap_create
    printf("before pcap_create\n");
    fflush(stdout);

    // Call pcap_create
    handle = pcap_create(device_name, errbuf);

    // Check the call status of pcap_create
    if (handle == NULL) {
        fprintf(stderr, "Calling pcap_create fail\n");
        fflush(stderr);
        fprintf(stderr, "Error: %s\n", errbuf);
        fflush(stderr);
        return 123;
    } else {
        printf("Calling pcap_create success\n");
        fflush(stdout);

        // Further actions with the handle could be performed here.
        // For this example, we'll just close it.
        // If we were to open a real device and capture, we'd use functions like:
        // pcap_activate(handle);
        // pcap_loop(handle, 10, packet_handler, NULL);

        // Close the handle to release resources
        pcap_close(handle);
    }

    return 0;
}

