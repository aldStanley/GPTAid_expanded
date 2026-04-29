#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    const char *filter_exp = "tcp port 80"; // Example filter expression. Any valid BPF syntax can be used.

    // 1. Initialize pcap handle and compile filter.
    // For a non-interactive example, we'll try to find the first available device.
    char *dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find a default device to open: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Attempting to use device: %s\n", dev);
    fflush(stdout);

    // Open the device for live capture.
    // Parameters: device name, snaplen (max bytes per packet), promiscuous_mode, timeout_ms, error buffer
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s for capturing: %s\n", dev, errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Device opened successfully for live capture.\n");
    fflush(stdout);

    // Compile the filter expression.
    // Parameters: handle, bpf_program structure, filter string, optimize, netmask
    // PCAP_NETMASK_UNKNOWN is used when the network mask is not known or not important for this filter.
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Could not parse filter '%s': %s\n", filter_exp, pcap_geterr(handle));
        fflush(stdout);
        pcap_close(handle);
        return 123;
    }
    printf("Filter expression compiled successfully.\n");
    fflush(stdout);

    // 2. Call pcap_setfilter
    printf("before pcap_setfilter\n");
    fflush(stdout);

    // The pcap_setfilter function applies the compiled filter to the capture handle.
    // It expects a valid pcap_t pointer and a compiled bpf_program structure.
    int result = pcap_setfilter(handle, &fp);

    if (result == 0) {
        printf("Calling pcap_setfilter success\n");
        fflush(stdout);
    } else {
        // If pcap_setfilter fails, it returns -1.
        // pcap_geterr(handle) provides the specific error message.
        fprintf(stderr, "Calling pcap_setfilter fail. Error retrieving: %s\n", pcap_geterr(handle));
        fflush(stdout);
        // Free the compiled filter code as it was successfully compiled but not applied.
        pcap_freecode(&fp);
        pcap_close(handle);
        return 123;
    }

    // 3. Clean up resources.
    // Free the compiled filter code.
    pcap_freecode(&fp);
    // Close the pcap handle.
    pcap_close(handle);
    printf("All resources freed. Program exiting.\n");
    fflush(stdout);

    return 0;
}

