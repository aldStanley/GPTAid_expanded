#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int result;
    const char *device = pcap_lookupdev(errbuf); // Get a default device for activation

    if (device == NULL) {
        fprintf(stderr, "Could not find a default device: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }

    // Open a live capture handle. This is necessary to activate the pcap_t struct.
    // For a non-interactive and non-looping example, we'll open it, check swapped, and then close it.
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device, errbuf);
        fflush(stdout);
        return 123;
    }

    printf("pcap_t handle opened successfully.\n");
    fflush(stdout);

    // Now that the handle is opened, it should be activated.
    // We can proceed to call pcap_is_swapped.

    printf("before pcap_is_swapped\n");
    fflush(stdout);

    result = pcap_is_swapped(handle);

    // pcap_is_swapped can return PCAP_ERROR_NOT_ACTIVATED if the handle is not activated,
    // or other negative values indicating an error.
    if (result < 0) {
        printf("Calling pcap_is_swapped fail\n");
        fflush(stdout);
        if (result == PCAP_ERROR_NOT_ACTIVATED) {
            // This specific error means the handle wasn't activated as expected.
            fprintf(stderr, "pcap_is_swapped: The pcap_t handle was not activated before calling pcap_is_swapped.\n");
        } else {
            // For other negative return values, pcap_geterr() can provide more info.
            fprintf(stderr, "pcap_is_swapped: An unexpected error occurred. Error code: %d. Details: %s\n", result, pcap_geterr(handle));
        }
        fflush(stdout);
        pcap_close(handle);
        return 123;
    } else {
        // If result is >= 0, the call was successful.
        printf("Calling pcap_is_swapped success\n");
        fflush(stdout);
        if (result == 1) {
            printf("Packet byte order is swapped.\n");
            fflush(stdout);
        } else {
            printf("Packet byte order is not swapped.\n");
            fflush(stdout);
        }
    }

    // Clean up
    pcap_close(handle);
    printf("pcap_t handle closed.\n");
    fflush(stdout);

    return 0;
}

