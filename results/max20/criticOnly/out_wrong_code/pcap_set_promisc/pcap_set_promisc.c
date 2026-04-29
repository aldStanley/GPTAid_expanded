#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


// Function to handle pcap errors
void pcap_error_handler(const char *message) {
    fprintf(stderr, "Error: %s\n", message);
    fflush(stdout); // Flush stdout as per requirements
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *device = "eth0"; // Replace with an actual network interface on your system.
                                 // For demonstration, we'll try to open a device live,
                                 // but pcap_set_promisc should be called BEFORE pcap_activate.

    // Attempt to open a live capture handle.
    // This is a more realistic scenario for using pcap_set_promisc.
    // pcap_open_live does NOT activate the handle. Activation happens with pcap_activate.
    handle = pcap_open_live(device, BUFSIZ, 0, 1000, errbuf);

    if (handle == NULL) {
        pcap_error_handler("Failed to open live capture device.");
        fprintf(stderr, "Error message: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Successfully opened live pcap handle for device '%s'.\n", device);
    fflush(stdout);

    // 2. Call pcap_set_promisc.
    // We will attempt to set promiscuous mode to ON (1).
    // This MUST be called BEFORE pcap_activate.
    int promisc_value = 1;

    printf("before pcap_set_promisc\n");
    fflush(stdout);

    int result = pcap_set_promisc(handle, promisc_value);

    // 3. Check the call status of pcap_set_promisc.
    if (result == 0) {
        printf("Calling pcap_set_promisc success\n");
        fflush(stdout);

        // Now, activate the handle. If pcap_set_promisc was successful,
        // promiscuous mode should be enabled during activation.
        if (pcap_activate(handle) < 0) {
            fprintf(stderr, "Error activating the capture: %s\n", pcap_geterr(handle));
            fflush(stdout);
            pcap_close(handle);
            return 123;
        }
        printf("Pcap handle activated successfully with promiscuous mode set.\n");
        fflush(stdout);

    } else {
        printf("Calling pcap_set_promisc fail\n");
        fflush(stdout);
        // pcap_set_promisc returns PCAP_ERROR_ACTIVATED if called after activation.
        // Since we are calling it before pcap_activate, if it fails here,
        // it might be for other reasons, or the initial opening failed in a way
        // that pcap_set_promisc interprets as an activation issue.
        // We can get a more specific error message from pcap_geterr.
        fprintf(stderr, "Error calling pcap_set_promisc: %s\n", pcap_geterr(handle));
        fflush(stdout);
        pcap_close(handle);
        return 123;
    }

    // In a real application, you would now start capturing packets.
    // For this example, we'll just close the handle.
    pcap_close(handle);
    printf("Pcap handle closed successfully.\n");
    fflush(stdout);

    return 0;
}

