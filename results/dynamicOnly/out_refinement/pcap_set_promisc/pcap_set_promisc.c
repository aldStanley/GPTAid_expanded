#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const char *interface = "eth0"; // Replace with a valid interface on your system

    // 1. Open a network device for capturing.
    // This is where we get a pcap_t handle.
    // For demonstration, we'll use pcap_open_live.
    // pcap_open_live can implicitly activate the device.
    // If pcap_set_promisc must be called *before* activation,
    // a different approach might be needed if pcap_open_live
    // always activates. However, according to man pages,
    // pcap_set_promisc should be called after pcap_open_live
    // and before pcap_activate. Let's assume this is the order.

    // Open the device for sniffing.
    handle = pcap_open_live(interface, BUFSIZ, 0, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", interface, errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Successfully opened network interface.\n");
    fflush(stdout);

    // 2. Set promiscuous mode before activation.
    // We will try to set it to enabled (promisc = 1).
    int promisc_setting = 1;

    printf("before pcap_set_promisc\n");
    fflush(stdout);

    // Call pcap_set_promisc
    int set_promisc_result = pcap_set_promisc(handle, promisc_setting);

    // Check the status of pcap_set_promisc
    if (set_promisc_result == 0) {
        printf("Calling pcap_set_promisc success\n");
        fflush(stdout);
    } else if (set_promisc_result == PCAP_ERROR_ACTIVATED) {
        fprintf(stderr, "pcap_set_promisc failed: pcap handle already activated.\n");
        fflush(stdout);
        printf("Calling pcap_set_promisc fail\n");
        fflush(stdout);
        // If it failed because it was activated, we might still want to proceed
        // to show other operations, but for this example, we'll exit.
        pcap_close(handle);
        return 123;
    } else {
        // Other pcap errors might occur, though less common for set_promisc itself.
        // pcap_geterr() can be used for more detailed error messages.
        fprintf(stderr, "pcap_set_promisc failed with error code %d. Error: %s\n", set_promisc_result, pcap_geterr(handle));
        fflush(stdout);
        printf("Calling pcap_set_promisc fail\n");
        fflush(stdout);
        pcap_close(handle);
        return 123;
    }

    // 3. Activate the capture.
    // If pcap_set_promisc succeeded, we can now activate.
    if (pcap_activate(handle) < 0) {
        fprintf(stderr, "pcap_activate failed: %s\n", pcap_geterr(handle));
        fflush(stdout);
        pcap_close(handle);
        return 123;
    }
    printf("Successfully activated pcap handle.\n");
    fflush(stdout);

    // In a real application, you would now start capturing packets.
    // For this non-interactive, non-infinite loop example, we will just close.

    // 4. Close the capture handle.
    pcap_close(handle);
    printf("Successfully closed pcap handle.\n");
    fflush(stdout);

    return 0;
}

