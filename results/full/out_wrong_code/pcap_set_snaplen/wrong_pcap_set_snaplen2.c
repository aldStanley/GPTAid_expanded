#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>



// Define a smaller error buffer size for demonstration purposes.
// In a real scenario, PCAP_ERRBUF_SIZE is typically 256.
// This smaller size is intended to cause a buffer overflow when a long error message is generated.
#define SMALL_ERRBUF_SIZE 10

// A custom pcap_t structure with a deliberately small errbuf.
// This is for demonstration of the violation. In a real exploit,
// an attacker might try to corrupt an existing pcap_t structure.
typedef struct {
    int activated;
    char errbuf[SMALL_ERRBUF_SIZE]; // Intentionally small errbuf
} pcap_t_small_errbuf;

int main() {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE]; // Standard error buffer for initial operations
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

    // Open the device for live capture.
    // We use a small timeout (1000ms) and non-promiscuous mode (0) for simplicity,
    // though these don't directly affect the errbuf size violation.
    handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
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

    // --- VIOLATION START ---
    // To violate the rule "The pcap_t structure's errbuf must be sufficiently sized
    // to prevent buffer overflows when error messages are written," we will simulate
    // a scenario where the pcap_t handle has a very small error buffer.
    //
    // The pcap_set_snaplen function internally calls pcap_check_activated.
    // If the pcap_t handle is activated, pcap_check_activated will attempt to
    // write an error message to the handle's errbuf if the operation is not allowed.
    //
    // We will create a custom pcap_t_small_errbuf structure and cast it to pcap_t*
    // to pass to pcap_set_snaplen. This custom structure has a deliberately small
    // errbuf (SMALL_ERRBUF_SIZE).
    //
    // We will also simulate the handle being activated by setting the 'activated'
    // field to 1. This will cause pcap_check_activated to attempt to write an
    // error message, which will overflow the small errbuf.

    // Allocate memory for our custom pcap_t with a small errbuf.
    pcap_t_small_errbuf *malicious_p = (pcap_t_small_errbuf *)malloc(sizeof(pcap_t_small_errbuf));
    if (malicious_p == NULL) {
        fprintf(stderr, "Failed to allocate memory for malicious pcap_t.\n");
        fflush(stdout);
        if (handle) pcap_close(handle);
        return 123;
    }

    // Simulate the pcap_t handle being activated.
    malicious_p->activated = 1;

    // Now, call pcap_set_snaplen with our custom, small-errbuf pcap_t.
    // The pcap_set_snaplen function will first call pcap_check_activated.
    // Since malicious_p->activated is 1, pcap_check_activated will try to
    // write an error message like "operation not permitted on activated capture"
    // into malicious_p->errbuf. Because malicious_p->errbuf is only SMALL_ERRBUF_SIZE
    // (10 bytes), this will cause a buffer overflow.
    printf("Attempting to call pcap_set_snaplen with a pcap_t having a small errbuf...\n");
    fflush(stdout);

    // We cast our custom struct to pcap_t* to match the function signature.
    // This is where the violation occurs.
    result = pcap_set_snaplen((pcap_t *)malicious_p, snaplen_value);

    // --- VIOLATION END ---

    // Check the call status of pcap_set_snaplen.
    // Due to the buffer overflow, the behavior might be unpredictable.
    // The function might return an error code, or it might crash.
    // We check the return code for demonstration.
    if (result == 0) {
        printf("Calling pcap_set_snaplen unexpectedly succeeded (this might indicate the overflow didn't trigger an immediate error return).\n");
        fflush(stdout);
    } else {
        printf("Calling pcap_set_snaplen failed as expected due to the violation.\n");
        fflush(stdout);
        // The error message might have been truncated or corrupted due to the overflow.
        // We print the contents of the small errbuf to show the potential corruption.
        printf("Contents of the small errbuf after the call: '%.*s'\n", SMALL_ERRBUF_SIZE, malicious_p->errbuf);
        fflush(stdout);
        fprintf(stderr, "pcap_set_snaplen failed with error code: %d\n", result);
        fflush(stdout);
    }

    // Clean up the allocated memory for our malicious pcap_t.
    free(malicious_p);
    malicious_p = NULL;

    // Close the original pcap handle if it was successfully opened.
    if (handle != NULL) {
        pcap_close(handle);
        printf("Successfully closed original pcap handle.\n");
        fflush(stdout);
    }

    return 0;
}

