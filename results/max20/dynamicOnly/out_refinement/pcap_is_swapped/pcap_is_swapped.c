#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int result;

    // Task2.1: Initialize a pcap handle.
    // We need to activate a pcap handle before calling pcap_is_swapped.
    // Using pcap_open_live for demonstration. A real-world scenario might
    // involve pcap_open_offline.
    // For this example, we'll try to open the first available network device.
    // If no network devices are available, this might fail.
    const char *device = pcap_lookupdev(errbuf);
    if (device == NULL) {
        fprintf(stderr, "Error finding default device: %s\n", errbuf);
        return 123;
    }
    printf("Found default device: %s\n", device);
    fflush(stdout);

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device %s: %s\n", device, errbuf);
        return 123;
    }
    printf("Successfully opened device for live capture.\n");
    fflush(stdout);

    // Task2.6: Add the specified output before calling pcap_is_swapped
    printf("before pcap_is_swapped\n");
    fflush(stdout);

    // Task 1: Analyze the function code to find the invocation specification.
    // The function `pcap_is_swapped` requires a valid, activated `pcap_t *p` as input.
    // The first check `if (!p->activated)` indicates that the `pcap_t` structure
    // must have its `activated` member set to true. This is typically done
    // by successful calls to functions like `pcap_open_live` or `pcap_open_offline`.
    // If `p` is NULL or the handle has not been activated, the function returns
    // `PCAP_ERROR_NOT_ACTIVATED` (-1). Otherwise, it returns the value of `p->swapped`.

    // Task2.2: Call the function.
    // Task2.3: Check the call status.
    // Task2.5: Output success or failure messages.
    result = pcap_is_swapped(handle);

    if (result == PCAP_ERROR_NOT_ACTIVATED) {
        printf("Calling pcap_is_swapped fail\n");
        fflush(stdout);
        fprintf(stderr, "Error: pcap_is_swapped called on a non-activated pcap handle.\n");
        // Task2.3: If API call fails, return 123 and output error message.
        pcap_close(handle);
        return 123;
    } else if (result == -1) { // Generic error from pcap_is_swapped itself if not PCAP_ERROR_NOT_ACTIVATED
        printf("Calling pcap_is_swapped fail\n");
        fflush(stdout);
        fprintf(stderr, "Error: pcap_is_swapped returned an unexpected error value.\n");
        pcap_close(handle);
        return 123;
    } else {
        printf("Calling pcap_is_swapped success\n");
        fflush(stdout);
        if (result == 1) {
            printf("The pcap data is byte-swapped.\n");
            fflush(stdout);
        } else {
            printf("The pcap data is not byte-swapped.\n");
            fflush(stdout);
        }
    }

    // Task2.3: Check the call status of other APIs.
    // `pcap_close` doesn't have a direct error return value to check in the same way.
    // We assume successful closure if no immediate issues arise.
    pcap_close(handle);
    printf("Successfully closed pcap handle.\n");
    fflush(stdout);

    return 0;
}

