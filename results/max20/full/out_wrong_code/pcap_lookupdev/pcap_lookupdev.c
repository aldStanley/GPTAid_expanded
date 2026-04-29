#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


// Assume pcap_new_api is globally accessible or defined elsewhere,
// for the purpose of this example, we'll assume it's defined.
// In a real scenario, you'd need to know how it's managed by libpcap.
// For this example, let's simulate it as if it's NOT set.
// extern int pcap_new_api; // If it's truly global and defined elsewhere.
// For a self-contained example, we can simulate:
int pcap_new_api = 0; // Set to 0 to indicate old API mode.

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;

    // Ensure the errbuf is clear before use
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);

    printf("before pcap_lookupdev\n");
    fflush(stdout); // Flush stdout after the printf

    dev = pcap_lookupdev(errbuf);

    if (dev == NULL) {
        printf("Calling pcap_lookupdev fail\n");
        fflush(stdout); // Flush stdout after the printf
        fprintf(stderr, "Error from pcap_lookupdev: %s\n", errbuf);
        fflush(stderr); // Flush stderr after the fprintf
        return 123;
    } else {
        printf("Calling pcap_lookupdev success\n");
        fflush(stdout); // Flush stdout after the printf
        printf("Found device: %s\n", dev);
        fflush(stdout); // Flush stdout after the printf
    }

    // Example of using the found device with pcap_open_live (optional)
    // This part is not strictly required by the prompt but demonstrates
    // a typical next step.
    pcap_t *handle;
    int snaplen = 1024;
    int promisc = 0; // Not promiscuous mode
    int to_ms = 1000; // Timeout in milliseconds

    handle = pcap_open_live(dev, snaplen, promisc, to_ms, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", dev, errbuf);
        fflush(stderr); // Flush stderr after the fprintf
        return 123;
    } else {
        printf("Successfully opened device %s for live capture.\n", dev);
        fflush(stdout); // Flush stdout after the printf
    }

    pcap_close(handle);

    return 0;
}

