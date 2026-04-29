#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *device = NULL;
    int promisc_setting = 1; // 1 to enable promiscuous mode, 0 to disable
    int status;

    // Find a suitable network device. For simplicity, we'll try to find the first available one.
    device = pcap_lookupdev(errbuf);
    if (device == NULL) {
        fprintf(stderr, "Error finding default network device: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Using network device: %s\n", device);
    fflush(stdout);

    // Open the network device for live capture.
    // We'll set a snaplen and a timeout.
    // Crucially, we set the 'promisc' flag to 0 initially in pcap_open_live
    // because pcap_set_promisc MUST be called BEFORE activation.
    // pcap_open_live does NOT activate the handle.
    handle = pcap_open_live(device, BUFSIZ, 0, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening live capture device %s: %s\n", device, errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Successfully opened live capture device.\n");
    fflush(stdout);

    // Task2.6: Add the required printf before calling pcap_set_promisc
    printf("before pcap_set_promisc\n");
    fflush(stdout);

    // VIOLATION: Passing a NULL pointer to pcap_set_promisc
    // This violates the rule that the pcap_t handle must be a valid and initialized pointer.
    printf("Attempting to call pcap_set_promisc with a NULL handle...\n");
    fflush(stdout);
    status = pcap_set_promisc(NULL, promisc_setting);

    // The pcap_set_promisc function is expected to return an error code when passed a NULL pointer.
    // The exact error code might vary depending on the libpcap version, but it will not be 0.
    // We'll check for a non-zero status to indicate the violation was successful.
    if (status != 0) {
        printf("Calling pcap_set_promisc with NULL handle resulted in an error as expected.\n");
        fflush(stdout);
    } else {
        // This case should ideally not happen if the violation is successful.
        fprintf(stderr, "Calling pcap_set_promisc with NULL handle did NOT result in an error (unexpected).\n");
        fflush(stdout);
    }

    // In a real application, you would now proceed to start packet capture.
    // For this example, we will just close the handle to ensure it's non-interactive
    // and doesn't run into activation issues.
    printf("Closing the pcap handle.\n");
    fflush(stdout);
    pcap_close(handle);

    return 0;
}

