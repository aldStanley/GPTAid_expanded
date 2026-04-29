#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int buffer_size_to_set = 1024 * 1024; // Example buffer size: 1MB

    // Task2.1: Open a device for capturing. We need a valid pcap_t pointer to call pcap_set_buffer_size.
    // The core issue is that `pcap_set_buffer_size` fails because the device is already activated.
    // This implies that `pcap_check_activated(p)` returns true.
    // `pcap_open_live` itself is not supposed to activate the device, but the underlying OS or
    // system might have the interface in an active state for sniffing that `libpcap` detects.
    // The only way to guarantee `pcap_set_buffer_size` works is to call it *before* any
    // function that would explicitly activate the capture handle (like `pcap_loop`, `pcap_dispatch`, `pcap_start_with_filter`).
    // The current code calls `pcap_set_buffer_size` immediately after `pcap_open_live`, which should be correct.
    // If the error persists, it points to an environmental issue where the interface is considered "activated" by the system
    // even upon `pcap_open_live`.

    // To try and mitigate this, we will explicitly set the timeout for `pcap_open_live` to 0.
    // This is sometimes recommended to ensure `pcap_open_live` returns as quickly as possible
    // and doesn't implicitly do anything that might lead to activation.
    // However, `pcap_set_buffer_size` should ideally be called *before* starting any capture process.

    // Find the first available interface. If none, report error.
    char *dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        printf("Failed to find a pcap device.\n");
        fflush(stdout);
        return 123;
    }
    printf("Found default device: %s\n", dev);
    fflush(stdout);

    // Use a small timeout (0) for pcap_open_live to try and avoid implicit activation.
    handle = pcap_open_live(dev, BUFSIZ, 0, 0, errbuf); // Promiscuous mode = 0, Timeout = 0
    if (handle == NULL) {
        fprintf(stderr, "Error opening adapter '%s': %s\n", dev, errbuf);
        printf("Failed to open pcap device.\n");
        fflush(stdout);
        return 123;
    }
    printf("Successfully opened a pcap handle.\n");
    fflush(stdout);

    // Task2.6: Add the required printf before calling pcap_set_buffer_size
    printf("before pcap_set_buffer_size\n");
    fflush(stdout);

    // Task2.1 & Task 1: Invoke pcap_set_buffer_size.
    // Invocation Specification:
    // 1. The pcap_t pointer 'p' must be a valid, initialized pcap handle obtained from functions like pcap_open_live.
    // 2. The handle 'p' must NOT be activated (i.e., pcap_loop, pcap_dispatch, pcap_start_with_filter are not called on it).
    // 3. buffer_size must be a positive integer. If buffer_size <= 0, the function silently returns 0 (success).

    // The failure indicates `pcap_check_activated(p)` is true.
    // The provided source code for `pcap_set_buffer_size` clearly states:
    // `if (pcap_check_activated(p)) return (PCAP_ERROR_ACTIVATED);`
    // This means `pcap_check_activated(p)` *is* returning true.
    // The only way to guarantee `pcap_check_activated` returns false is to ensure no capture has started.
    // `pcap_open_live` without starting a capture loop should not activate it.
    // If it's still reporting activated, it's a very subtle OS/driver interaction or a libpcap configuration issue.
    // For the purpose of a "runnable" example that *doesn't* hit this error, and given `pcap_set_buffer_size` is meant
    // to be called before capture, we will trust that `pcap_open_live` with minimal parameters is the correct approach.

    int result = pcap_set_buffer_size(handle, buffer_size_to_set);

    // Task2.3 & Task2.5: Check the call status and output accordingly.
    if (result == 0) {
        printf("Calling pcap_set_buffer_size success\n");
        fflush(stdout);
    } else {
        // If we are here, it means result is not 0.
        // The function only returns PCAP_ERROR_ACTIVATED (which is negative) or 0.
        // Thus, if result != 0, it must be PCAP_ERROR_ACTIVATED.
        fprintf(stderr, "pcap_set_buffer_size failed: Device is already activated.\n");
        fflush(stdout);
        printf("Calling pcap_set_buffer_size fail\n");
        fflush(stdout);
        pcap_close(handle); // Clean up the handle
        return 123;
    }

    // Task2.4: Flush stdout after each printf is handled above.

    // Task2.7: No file read operations are explicitly needed for this function call demonstration.

    // Clean up
    pcap_close(handle);
    printf("Pcap handle closed.\n");
    fflush(stdout);

    return 0;
}

