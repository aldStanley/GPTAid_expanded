#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open a pcap device for live capture.
    // We are using a dummy interface name "eth0" as a placeholder.
    // In a real scenario, you would ensure this interface exists and is accessible.
    // If "eth0" does not exist or cannot be opened, pcap_open_live will fail.
    // This is the standard way to get a valid pcap_t pointer.
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening adapter: %s\n", errbuf);
        fflush(stderr);
        return 123;
    }
    printf("Successfully opened pcap handle.\n");
    fflush(stdout);

    // Now, we have a valid pcap_t pointer `handle`.
    // This is the prerequisite for correctly calling pcap_close.

    printf("before pcap_close\n");
    fflush(stdout);

    // Call the pcap_close function with the valid handle.
    pcap_close(handle);

    // pcap_close returns void, so we infer success from the fact that
    // pcap_open_live succeeded and pcap_close was called without crashing.
    // The internal cleanup_op is executed by pcap_close.
    printf("Calling pcap_close success\n");
    fflush(stdout);

    return 0;
}

