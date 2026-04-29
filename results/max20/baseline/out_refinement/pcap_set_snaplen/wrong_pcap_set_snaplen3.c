#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>



int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *device = pcap_lookupdev(errbuf); // Find a default device

    // Task2.3: Check API call status for pcap_lookupdev
    if (device == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }

    // Open a live capture handle.
    // We will intentionally violate the rule by closing the handle *before*
    // attempting to set the snapshot length. This will result in a use-after-free
    // scenario when pcap_set_snaplen is called.
    handle = pcap_open_live(device, 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        fflush(stdout);
        return 123;
    }

    // VIOLATION: Close the handle before calling pcap_set_snaplen.
    // This makes the 'handle' pointer point to deallocated memory.
    pcap_close(handle);
    handle = NULL; // Set to NULL to make it explicit that it's no longer valid.

    int snapshot_len = 1024; // Example snapshot length to set with pcap_set_snaplen

    // Task2.6: Add specific printf before the function call
    printf("before pcap_set_snaplen\n");
    fflush(stdout);

    // Task2: Call the pcap_set_snaplen function with an invalid handle.
    // This will cause a use-after-free error because 'handle' points to deallocated memory.
    int result = pcap_set_snaplen(handle, snapshot_len);

    // Task2.5: Output success or failure message
    if (result == 0) {
        printf("Calling pcap_set_snaplen success\n");
        fflush(stdout);
    } else {
        printf("Calling pcap_set_snaplen fail\n");
        fflush(stdout);
        // Task2.3: Output error message if API call fails
        // The error code -4 indicates PCAP_ERROR_ACTIVATED. This means pcap_check_activated(handle) returned true.
        // However, in this specific violation, the primary issue is the use-after-free.
        // The error message might be misleading or a consequence of operating on invalid memory.
        fprintf(stderr, "pcap_set_snaplen failed. Error code %d. This is likely due to using a closed or invalid capture handle (use-after-free).\n", result);
        fflush(stdout);
        // Task2.3: Return 123 on failure
        // No need to close 'handle' again as it's already closed and set to NULL.
        return 123;
    }

    // This part of the code will likely not be reached due to the failure above.
    // If it were reached, we would normally close the handle here.
    // pcap_close(handle);

    return 0;
}

