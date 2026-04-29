#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL; // Initialize handle to NULL
    int snaplen_value = 1024; // Example snapshot length
    int status;

    // 1. Open a live capture device
    char *dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Error: Couldn't find default device: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Info: Found network device: %s\n", dev);
    fflush(stdout);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error: Couldn't open device %s: %s\n", dev, errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Info: Successfully opened device %s for live capture.\n", dev);
    fflush(stdout);

    // Task2.6: Add the required printf statement before calling pcap_set_snaplen
    printf("before pcap_set_snaplen\n");
    fflush(stdout);

    // Task2: Call pcap_set_snaplen
    // The analysis from Task 1 correctly identified that pcap_set_snaplen needs to be called
    // before the capture is activated. The provided example correctly places this call
    // after pcap_open_live and before any capture initiation.
    status = pcap_set_snaplen(handle, snaplen_value);

    // Task2.3: Check the call status
    if (status == 0) {
        // Task2.5: Output success message
        printf("Calling pcap_set_snaplen success\n");
        fflush(stdout);
    } else {
        // Task2.5: Output failure message
        printf("Calling pcap_set_snaplen fail\n");
        fflush(stdout);
        // Task2.3: Output error message
        // The error code from pcap_set_snaplen itself is usually PCAP_ERROR_ACTIVATED if it fails.
        // libpcap's error reporting can be subtle here, but we can report the return value.
        fprintf(stderr, "Error: pcap_set_snaplen failed with return status: %d\n", status);
        fflush(stdout);
        // Task2.3: Return 123 on failure
        pcap_close(handle); // Clean up before exiting
        return 123;
    }

    // Close the capture handle to clean up resources.
    pcap_close(handle);
    printf("Info: Successfully closed pcap handle.\n");
    fflush(stdout);

    return 0;
}

