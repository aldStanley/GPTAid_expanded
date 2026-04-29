#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int major_version;

    // Task2.7: Placeholder for a file if needed. For pcap_open_offline,
    // we'd need a .pcap file. Since this example is minimal, we'll
    // simulate a device if possible, or a dummy file if not.
    // For demonstration purposes, we'll try to open a live interface
    // or fail gracefully if no interfaces are available.
    // If opening a file is strictly required, uncomment the following lines
    // and ensure 'example.pcap' exists.
    // const char *filename = "example.pcap";
    // handle = pcap_open_offline(filename, errbuf);
    // if (handle == NULL) {
    //     fprintf(stderr, "Could not open file %s: %s\n", filename, errbuf);
    //     return 123;
    // }

    // Attempt to open a live capture device.
    // This is more likely to succeed on a Linux system.
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device eth0: %s\n", errbuf);
        // Try a different common interface if eth0 fails
        handle = pcap_open_live("wlan0", BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device wlan0: %s\n", errbuf);
            // As a fallback, try to find any available interface
            char *dev_list = pcap_lookupdev(errbuf);
            if (dev_list == NULL) {
                fprintf(stderr, "Couldn't find any suitable device: %s\n", errbuf);
                return 123;
            }
            handle = pcap_open_live(dev_list, BUFSIZ, 1, 1000, errbuf);
            if (handle == NULL) {
                fprintf(stderr, "Couldn't open device %s: %s\n", dev_list, errbuf);
                return 123;
            }
        }
    }

    // Task2.6: Add the required printf before calling pcap_major_version
    printf("before pcap_major_version\n");
    fflush(stdout);

    // Task2.1: Ensure the handle is activated before calling pcap_major_version.
    // pcap_open_live or pcap_open_offline activates the handle.
    // The function signature is `int pcap_major_version(pcap_t *p)`.
    // The caller needs to provide a valid, activated `pcap_t` pointer.
    // The function checks `!p->activated`, so we must ensure `p->activated` is true.
    // This is achieved by a successful call to `pcap_open_live` or `pcap_open_offline`.

    // VIOLATION: Pass a NULL pointer to pcap_major_version.
    // This violates the rule that the pcap_t pointer must point to a valid and initialized pcap_t structure.
    // A NULL pointer is not a valid or initialized structure.
    major_version = pcap_major_version(NULL);

    // Task2.3: Check the call status of the API.
    if (major_version < 0) { // pcap_major_version returns PCAP_ERROR_NOT_ACTIVATED or other errors
        // Task2.5: Output failure message
        printf("Calling pcap_major_version fail\n");
        fflush(stdout);

        // Task2.3: Output error message to infer the cause.
        // PCAP_ERROR_NOT_ACTIVATED is a negative value.
        if (major_version == PCAP_ERROR_NOT_ACTIVATED) {
            fprintf(stderr, "Error: pcap_major_version failed because the pcap handle is not activated.\n");
        } else {
            // When passing NULL, pcap_major_version typically returns PCAP_ERROR_NOT_ACTIVATED
            // or a similar error indicating an invalid handle.
            fprintf(stderr, "Error: pcap_major_version returned an unexpected negative value: %d. This might be due to an invalid handle (e.g., NULL).\n", major_version);
        }
        // Task2.3: Return 123 on failure
        return 123;
    } else {
        // Task2.5: Output success message
        printf("Calling pcap_major_version success\n");
        fflush(stdout);

        // Optionally, print the major version to verify
        printf("pcap major version is: %d\n", major_version);
        fflush(stdout);
    }

    // Clean up the pcap handle
    // This part might not be reached if the violation causes an early exit.
    if (handle != NULL) {
        pcap_close(handle);
    }

    return 0; // Indicate success
}

