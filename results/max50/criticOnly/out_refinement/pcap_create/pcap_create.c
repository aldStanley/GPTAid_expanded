#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


#define PCAP_ERRBUF_SIZE 256

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *device = NULL; // Using NULL to test the "any" device functionality
    // On Linux, you might want to specify a device like "eth0" or "wlan0"
    // For a non-interactive example, "any" is a good choice to attempt to open something.
    // If you want to test a specific interface, replace NULL with e.g., "eth0"

    printf("before pcap_create\n");
    fflush(stdout);

    /*
     * Attempt to create a pcap handle.
     * On Linux, passing NULL for device will attempt to open the "any" device.
     * If you want to target a specific interface, pass its name as a string literal,
     * e.g., const char *device = "eth0";
     */
    handle = pcap_create(device, errbuf);

    if (handle == NULL) {
        // Calling pcap_create fail
        fprintf(stderr, "Calling pcap_create fail\n");
        fflush(stderr);
        // Output error message to infer the cause of the error
        fprintf(stderr, "Error: %s\n", errbuf);
        fflush(stderr);
        return 123;
    } else {
        // Calling pcap_create success
        printf("Calling pcap_create success\n");
        fflush(stdout);

        // Further configuration before activation can be done here.
        // For this example, we will just activate it.
        // Setting snapshot length to 65535 and promiscuous mode to 1 (true)
        // as an example of configuration.
        if (pcap_set_snaplen(handle, 65535) != 0) {
            fprintf(stderr, "Error setting snaplen: %s\n", pcap_geterr(handle));
            fflush(stderr);
            pcap_close(handle);
            return 123;
        }
        if (pcap_set_promisc(handle, 1) != 0) {
            fprintf(stderr, "Error setting promiscuous mode: %s\n", pcap_geterr(handle));
            fflush(stderr);
            pcap_close(handle);
            return 123;
        }

        // Activate the pcap handle
        int activation_status = pcap_activate(handle);
        if (activation_status != 0) {
            // pcap_activate can return 0, -1, or positive values indicating a warning.
            // A return value of -1 indicates an error.
            if (activation_status < 0) {
                fprintf(stderr, "Error activating the capture handle: %s\n", pcap_geterr(handle));
                fflush(stderr);
                pcap_close(handle);
                return 123;
            } else {
                // Warnings are not errors but indicate potential issues.
                fprintf(stderr, "Warning during capture handle activation: %s\n", pcap_geterr(handle));
                fflush(stderr);
            }
        } else {
            printf("Capture handle activated successfully.\n");
            fflush(stdout);
        }

        // In a real application, you would now use pcap_loop or pcap_next_ex
        // to capture packets. For this example, we'll just close the handle.
        printf("Closing the capture handle.\n");
        fflush(stdout);
        pcap_close(handle);
    }

    return 0;
}

