#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int snaplen_value = 1024; // Example snapshot length
    int result;

    // Task2.1 & 2.3: Initialize libpcap handle.
    // We need an activated pcap handle to demonstrate setting snaplen.
    // For non-interactive and non-infinite loop, we'll open a device for live capture,
    // but won't start the capture loop.
    // We'll choose the first available network interface.
    char *dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Found device: %s\n", dev);
    fflush(stdout);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Successfully opened device for live capture.\n");
    fflush(stdout);

    // Task2.6: Add the required printf before the function call.
    printf("before pcap_set_snaplen\n");
    fflush(stdout);

    // Task2.1 & 2.3: Call pcap_set_snaplen.
    // The invocation specification requires that the pcap_t handle must not be activated.
    // pcap_open_live does not activate the handle immediately.
    // pcap_activate() is the function that activates the handle.
    // Since we are not calling pcap_activate(), the handle should not be activated.
    result = pcap_set_snaplen(handle, snaplen_value);

    // Task2.3: Check the call status of pcap_set_snaplen.
    if (result == 0) {
        printf("Calling pcap_set_snaplen success\n");
        fflush(stdout);
    } else {
        printf("Calling pcap_set_snaplen fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_set_snaplen failed with error code: %d\n", result);
        fflush(stdout);
        pcap_close(handle);
        return 123;
    }

    // Task2.3: Check the status of other API calls.
    // For demonstration, we'll also check pcap_close.
    if (handle != NULL) {
        pcap_close(handle);
        printf("Successfully closed pcap handle.\n");
        fflush(stdout);
    }

    return 0;
}

