#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *interface = "eth0"; // Replace with a valid interface name on your system

    // --- Attempt to open a network interface ---
    // In a real-world scenario, you'd want to handle the case where
    // pcap_lookupdev is not found or an error occurs.
    // For this example, we assume 'eth0' is a valid interface.
    // If 'eth0' is not available, this will fail.
    char *dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Found default device: %s\n", dev);
    fflush(stdout);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Successfully opened device %s\n", dev);
    fflush(stdout);

    // --- Call pcap_close ---
    printf("before pcap_close\n");
    fflush(stdout);

    // --- VIOLATION: Calling pcap_close with a NULL pointer ---
    // We are intentionally setting handle to NULL to violate the rule.
    // In a real scenario, this would happen if pcap_open_live failed
    // and the handle was never assigned a valid pointer.
    handle = NULL;
    pcap_close(handle);

    // pcap_close is a void function, so its success is implied by
    // not crashing. However, we can infer success if the handle
    // was successfully opened and then closed.
    // Since we are intentionally causing a violation, this message
    // might not be reached if the pcap_close call with NULL causes a crash.
    printf("Calling pcap_close success\n");
    fflush(stdout);

    return 0;
}

