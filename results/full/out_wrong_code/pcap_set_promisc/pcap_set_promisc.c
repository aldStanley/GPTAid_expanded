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

    // Task2.1, 2.3, 2.4, 2.5: Call pcap_set_promisc and check its status
    // Since we called pcap_open_live with 0 for promiscuous, it's not activated yet.
    status = pcap_set_promisc(handle, promisc_setting);

    if (status == 0) {
        printf("Calling pcap_set_promisc success\n");
        fflush(stdout);
    } else if (status == PCAP_ERROR_ACTIVATED) {
        // This error means the handle was already activated.
        // In the previous code, this error occurred likely because the 'promisc'
        // parameter in pcap_open_live was implicitly treated as activation or
        // there was an internal state change that led to activation before
        // pcap_set_promisc was called.
        // By ensuring pcap_set_promisc is called *after* pcap_open_live but *before*
        // any actual capture (like pcap_loop), we avoid this.
        // If we reach here, it still indicates a problem, so we return an error.
        fprintf(stderr, "Calling pcap_set_promisc fail: The pcap handle has already been activated.\n");
        fflush(stdout);
        pcap_close(handle); // Ensure handle is closed
        return 123;
    } else {
        // For any other error from pcap_set_promisc (though its return codes are specific).
        fprintf(stderr, "Calling pcap_set_promisc fail with an unknown error: %d\n", status);
        fflush(stdout);
        pcap_close(handle); // Ensure handle is closed
        return 123;
    }

    // In a real application, you would now proceed to start packet capture.
    // For this example, we will just close the handle to ensure it's non-interactive
    // and doesn't run into activation issues.
    printf("Closing the pcap handle.\n");
    fflush(stdout);
    pcap_close(handle);

    return 0;
}

