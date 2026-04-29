#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>



int main() {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int snaplen_value = 1024; // Example snapshot length
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    char *dev_name = NULL;

    // 1. Initialize pcap handle
    // To ensure the code is compilable and runnable without user interaction or specific device availability,
    // we will try to find a default device or any available device.
    // If no devices are found, we will report an error and exit.

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding all devices: %s\n", errbuf);
        fflush(stderr);
        exit(EXIT_FAILURE);
    }

    if (alldevs == NULL) {
        fprintf(stderr, "No network devices found.\n");
        fflush(stderr);
        exit(EXIT_FAILURE);
    }

    // Try to get the first device as the default
    dev = alldevs;
    dev_name = dev->name;

    // Open a pcap handle on the found device
    handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap handle on device %s: %s\n", dev_name, errbuf);
        fflush(stderr);
        pcap_freealldevs(alldevs); // Free the list of devices
        exit(EXIT_FAILURE);
    }
    printf("Successfully opened pcap handle on device: %s\n", dev_name);
    fflush(stdout);

    // Free the list of devices now that we have a handle
    pcap_freealldevs(alldevs);

    // --- Violation of Rule: The `pcap_t` pointer must point to a valid and uninitialized capture handle. ---
    // The example violation code passes a NULL pointer. We will do the same.
    // This violates the rule because a NULL pointer is not a valid capture handle.

    printf("before pcap_set_snaplen (violating rule)\n");
    fflush(stdout);

    // Call pcap_set_snaplen with a NULL handle to violate the rule.
    pcap_t *null_handle = NULL;
    int set_snaplen_result = pcap_set_snaplen(null_handle, snaplen_value);

    // 5. Output: "Calling pcap_set_snaplen success" after calling pcap_set_snaplen successfully;
    // Output: "Calling pcap_set_snaplen fail" after the call to pcap_set_snaplen has failed
    if (set_snaplen_result == 0) {
        printf("Calling pcap_set_snaplen success\n");
        fflush(stdout);
    } else {
        // 3. If API call fails, return 123 and output error message to infer the cause of the error.
        fprintf(stderr, "Calling pcap_set_snaplen fail. Error code: %d. ", set_snaplen_result);
        fflush(stderr);
        // When passing a NULL handle, pcap_geterr might not provide a useful message,
        // or it might even crash depending on the libpcap implementation.
        // However, to be consistent with the original code's error handling, we'll attempt to call it.
        // In a real scenario, you'd likely check for NULL before calling pcap_geterr.
        fprintf(stderr, "libpcap error: %s\n", pcap_geterr(handle)); // Using 'handle' here is a fallback, but the error is from the NULL call.
        fflush(stderr);
        // The error PCAP_ERROR_ACTIVATED (-1) is returned if the handle is already activated.
        // Passing a NULL handle will likely result in a different error, or a crash.
        pcap_close(handle);
        return 123;
    }

    // Task 1: Analyze the function code to find the invocation specification that the caller needs to follow correctly.
    // Analysis of pcap_set_snaplen:
    // - The function takes two arguments: `pcap_t *p` (a pointer to an initialized pcap handle)
    //   and `int snaplen` (the desired snapshot length).
    // - The primary invocation specification is that the pcap handle `p` must NOT be activated.
    //   The function explicitly checks this using `pcap_check_activated(p)`.
    // - If the handle is activated, it returns `PCAP_ERROR_ACTIVATED` (-1).
    // - If the handle is not activated, it sets `p->snapshot` to the provided `snaplen` value
    //   and returns 0 on success.
    // - Therefore, the caller must ensure that `pcap_set_snaplen` is called *before*
    //   `pcap_activate` (or any other operation that implicitly activates the handle).
    // - The `snaplen` value itself can be any integer, but it's typically a positive value
    //   representing the number of bytes to capture per packet.
    // - **Crucially, the `pcap_t *p` must be a valid, non-NULL pointer to an initialized pcap handle.**
    //   Passing NULL will lead to undefined behavior or a crash, and will not be treated as a valid handle.

    // Clean up
    pcap_close(handle);
    printf("Pcap handle closed.\n");
    fflush(stdout);

    return 0;
}

