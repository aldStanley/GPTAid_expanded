#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


#define ERRBUF_SIZE 256

int main() {
    pcap_t *handle;
    char errbuf[ERRBUF_SIZE];
    const char *device = "eth0"; // Replace with a valid network interface on your system

    printf("before pcap_create\n");
    fflush(stdout);

    /*
     * Call pcap_create to get a pcap_t handle.
     * device: The network interface to capture from.
     * errbuf: A buffer to store error messages.
     */
    handle = pcap_create(device, errbuf);

    if (handle == NULL) {
        printf("Calling pcap_create fail\n");
        fflush(stdout);
        fprintf(stderr, "Error creating pcap handle for device %s: %s\n", device, errbuf);
        fflush(stderr);
        return 123;
    } else {
        printf("Calling pcap_create success\n");
        fflush(stdout);

        // Further configuration and activation can be done here.
        // For this example, we'll just close the handle.

        // Example of checking a function status after pcap_create:
        // Let's assume pcap_set_snaplen is called to set the snapshot length.
        int snaplen = 1024;
        if (pcap_set_snaplen(handle, snaplen) != 0) {
            fprintf(stderr, "Error setting snapshot length: %s\n", pcap_geterr(handle));
            fflush(stderr);
            pcap_close(handle); // Clean up the handle if an error occurs
            return 123;
        } else {
            printf("Successfully set snapshot length to %d.\n", snaplen);
            fflush(stdout);
        }

        // Example of checking another function status: pcap_activate
        if (pcap_activate(handle) < 0) {
            fprintf(stderr, "Error activating the capture: %s\n", pcap_geterr(handle));
            fflush(stderr);
            pcap_close(handle); // Clean up the handle if an error occurs
            return 123;
        } else {
            printf("Capture activated successfully.\n");
            fflush(stdout);
        }

        // In a real application, you would now use pcap_loop or pcap_next_ex to capture packets.
        // For this example, we'll just close the handle to exit gracefully.
        pcap_close(handle);
        printf("Pcap handle closed successfully.\n");
        fflush(stdout);
    }

    return 0;
}

