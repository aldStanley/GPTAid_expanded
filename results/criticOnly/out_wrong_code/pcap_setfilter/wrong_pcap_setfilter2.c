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
    printf("before pcap_setfilter (first call)\n");
    fflush(stdout);

    // This is the direct call to pcap_setfilter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error: Couldn't install filter '%s' on device %s: %s\n", filter_exp, dev, pcap_geterr(handle));
        fflush(stdout);
        pcap_freecode(&fp); // Clean up compiled filter
        pcap_close(handle); // Clean up the handle
        printf("Calling pcap_setfilter fail (first call)\n");
        fflush(stdout);
        return 123;
    } else {
        printf("Calling pcap_setfilter success (first call)\n");
        fflush(stdout);
    }

    // VIOLATION: Close the handle and then attempt to use it again.
    printf("Closing the pcap handle.\n");
    fflush(stdout);
    pcap_close(handle);
    handle = NULL; // Set to NULL to indicate it's closed, though the violation is using the old pointer.

    printf("Attempting to call pcap_setfilter after closing the handle.\n");
    fflush(stdout);

    // This call violates the rule: using a pcap_t handle after it has been closed.
    // The behavior of calling pcap_setfilter on a closed handle is undefined and
    // likely to result in a crash or unexpected behavior.
    if (pcap_setfilter(handle, &fp) == -1) {
        // This error message might not be reached if the program crashes before it.
        fprintf(stderr, "Error: Expected to fail calling pcap_setfilter on a closed handle, but it didn't (or the error message is different): %s\n", pcap_geterr(handle));
        fflush(stdout);
        printf("Calling pcap_setfilter after close (expected to fail or crash)\n");
        fflush(stdout);
    } else {
        // This branch indicates a severe issue, as the function should not succeed on a closed handle.
        printf("Unexpected success calling pcap_setfilter after close!\n");
        fflush(stdout);
    }


    // 5. Clean up resources
    // Note: pcap_freecode(&fp) is still valid as fp is a separate struct.
    pcap_freecode(&fp);
    // pcap_close(handle); // This would be a double close if not for the violation above.
    printf("Resources cleaned up (except for the violated handle).\n");
    fflush(stdout);

    return 0;
}

