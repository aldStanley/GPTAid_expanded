#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    struct bpf_program fp;
    const char *dev = NULL;
    const char *filter_exp = "udp"; // Example filter expression

    // 1. Find a network device
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Error: Couldn't find default network device. %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Successfully found network device: %s\n", dev);
    fflush(stdout);

    // 2. Open a handle to the network device for live capture
    // BUFSIZ for buffer size, 1 for promiscuous mode (often requires root/admin), 1000 for timeout in ms
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error: Couldn't open device %s for live capture: %s\n", dev, errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Successfully opened network device for live capture.\n");
    fflush(stdout);

    // 3. Compile the filter expression into a BPF program
    // The third argument is the filter expression, 0 for optimization level, 0 for network layer
    if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1) {
        fprintf(stderr, "Error: Couldn't parse filter expression '%s': %s\n", filter_exp, pcap_geterr(handle));
        fflush(stdout);
        pcap_close(handle); // Clean up the handle
        return 123;
    }
    printf("Successfully compiled filter expression '%s'.\n", filter_exp);
    fflush(stdout);

    // 4. Set the compiled filter on the capture handle
    printf("before pcap_setfilter\n");
    fflush(stdout);

    // This is the direct call to pcap_setfilter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error: Couldn't install filter '%s' on device %s: %s\n", filter_exp, dev, pcap_geterr(handle));
        fflush(stdout);
        pcap_freecode(&fp); // Clean up compiled filter
        pcap_close(handle); // Clean up the handle
        printf("Calling pcap_setfilter fail\n");
        fflush(stdout);
        return 123;
    } else {
        printf("Calling pcap_setfilter success\n");
        fflush(stdout);
    }

    // 5. Clean up resources
    pcap_freecode(&fp);
    pcap_close(handle);
    printf("Resources cleaned up successfully.\n");
    fflush(stdout);

    return 0;
}

