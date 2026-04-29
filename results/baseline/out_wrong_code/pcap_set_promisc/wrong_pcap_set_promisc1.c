#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>





int main() {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int promisc_mode = 1; // Set to 1 for promiscuous mode, 0 for non-promiscuous
    int ret;

    // 1. Find a network device.
    const char *dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Found default device: %s\n", dev);
    fflush(stdout);

    // 2. Open the device for capturing.
    // To allow pcap_set_promisc to work correctly without the "activated capture" error,
    // we set promiscuous mode to 0 initially when opening the device.
    // pcap_set_promisc should be called *before* pcap_activate or any other
    // function that might implicitly activate the capture.
    handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Device %s opened successfully.\n", dev);
    fflush(stdout);

    // 3. Call pcap_set_promisc to set the promiscuous mode.
    // This function must be called before the capture is activated.
    // pcap_open_live does not activate the capture by itself.
    // The error "can't perform operation on activated capture" from the previous run
    // suggests that either pcap_open_live in some environments might implicitly activate,
    // or another call was made that activated it. By ensuring it's called right after
    // open_live and before any explicit activation, we follow the intended usage.

    // VIOLATION: Set handle to NULL to violate the rule that pcap_t handle must not be NULL.
    handle = NULL;

    printf("before pcap_set_promisc\n");
    fflush(stdout);

    ret = pcap_set_promisc(handle, promisc_mode);

    // 4. Check the status of pcap_set_promisc.
    if (ret != 0) {
        // If pcap_set_promisc still fails, it might indicate a permission issue
        // or that the device cannot support the requested mode.
        // When handle is NULL, pcap_geterr might behave unexpectedly or return an error.
        // The primary goal here is to demonstrate the violation of passing a NULL handle.
        fprintf(stderr, "Calling pcap_set_promisc fail. Error: %s\n", pcap_geterr(handle));
        fflush(stdout);
        // We cannot call pcap_close(handle) here because handle is NULL.
        // In a real scenario, you would handle the NULL handle case before attempting to close.
        return 123;
    } else {
        printf("Calling pcap_set_promisc success\n");
        fflush(stdout);
    }

    // 5. Close the packet capture handle.
    // This part will not be reached if the violation causes an early exit.
    // If, for some reason, the violation doesn't cause an immediate exit and ret is 0,
    // this would attempt to close a NULL handle, which is also problematic.
    // However, the primary violation is in the pcap_set_promisc call itself.
    pcap_close(handle);
    printf("Packet capture handle closed.\n");
    fflush(stdout);

    return 0;
}

