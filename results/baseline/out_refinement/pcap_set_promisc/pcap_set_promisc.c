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
    printf("before pcap_set_promisc\n");
    fflush(stdout);

    ret = pcap_set_promisc(handle, promisc_mode);

    // 4. Check the status of pcap_set_promisc.
    if (ret != 0) {
        // If pcap_set_promisc still fails, it might indicate a permission issue
        // or that the device cannot support the requested mode.
        fprintf(stderr, "Calling pcap_set_promisc fail. Error: %s\n", pcap_geterr(handle));
        fflush(stdout);
        pcap_close(handle); // Clean up the handle
        return 123;
    } else {
        printf("Calling pcap_set_promisc success\n");
        fflush(stdout);
    }

    // 5. Close the packet capture handle.
    pcap_close(handle);
    printf("Packet capture handle closed.\n");
    fflush(stdout);

    return 0;
}

