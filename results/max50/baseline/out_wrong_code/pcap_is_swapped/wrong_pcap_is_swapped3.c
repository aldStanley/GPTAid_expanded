#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int result;
    pcap_if_t *alldevs, *dev;
    char dev_name[256];

    // Task2.1: Initialize pcap. We need an activated pcap handle to call pcap_is_swapped.
    // The function `pcap_is_swapped` checks `!p->activated`.
    // If the handle is not activated, it returns PCAP_ERROR_NOT_ACTIVATED.
    // The most reliable way to test this is to create a handle but *not* activate it,
    // or to attempt activation and have it fail.

    // Find all network devices.
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding network devices: %s\n", errbuf);
        fflush(stderr);
        return 123;
    }

    // If no devices are found, we cannot proceed to create a handle.
    if (alldevs == NULL) {
        fprintf(stderr, "No network devices found on this system.\n");
        fflush(stderr);
        return 123;
    }

    // Use the first device found.
    strncpy(dev_name, alldevs->name, sizeof(dev_name) - 1);
    dev_name[sizeof(dev_name) - 1] = '\0'; // Ensure null termination

    // Free the device list as we've got the name.
    pcap_freealldevs(alldevs);

    // Create a pcap handle for the chosen device.
    // Crucially, we are NOT calling pcap_activate() immediately.
    handle = pcap_create(dev_name, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error creating pcap handle for device '%s': %s\n", dev_name, errbuf);
        fflush(stderr);
        return 123;
    }
    printf("pcap_create successful for device '%s'.\n", dev_name);
    fflush(stdout);

    // --- VIOLATION START ---
    // To violate the rule "Ensure the `pcap_t` handle points to a valid and initialized structure",
    // we will close the handle and then attempt to use it. This creates a dangling pointer.
    // This is analogous to the provided violation example where a freed pointer is used.

    printf("Closing the pcap handle before calling pcap_is_swapped.\n");
    fflush(stdout);
    pcap_close(handle);
    handle = NULL; // Set to NULL to avoid double free, but the pointer is still invalid for use.

    // Now, `handle` is either NULL or points to memory that has been deallocated by pcap_close.
    // Calling pcap_is_swapped with this invalid handle will lead to undefined behavior.
    // In this specific case, since we set handle to NULL after closing,
    // pcap_is_swapped will likely receive a NULL pointer.
    // The pcap_is_swapped function checks `p->activated`. If `p` is NULL,
    // dereferencing it will cause a segmentation fault.
    // If pcap_close did not set the internal pointer to NULL and just deallocated,
    // then using `handle` would be a use-after-free, also leading to undefined behavior.

    printf("Attempting to call pcap_is_swapped with an invalid handle.\n");
    fflush(stdout);

    // The following call is expected to cause a crash (segmentation fault)
    // because `handle` is no longer a valid `pcap_t` pointer.
    result = pcap_is_swapped(handle);

    // The code below this point is unlikely to be reached due to the expected crash.
    // However, if it were reached, it would indicate that the crash did not occur,
    // which would be an unexpected outcome for this violation.

    if (result == PCAP_ERROR_NOT_ACTIVATED) {
        printf("Calling pcap_is_swapped fail (unexpectedly returned PCAP_ERROR_NOT_ACTIVATED).\n");
        fflush(stdout);
        fprintf(stderr, "Error: pcap_is_swapped returned PCAP_ERROR_NOT_ACTIVATED for an invalid handle, which is not the expected crash.\n");
        fflush(stderr);
    } else {
        printf("Calling pcap_is_swapped success (unexpectedly returned %d).\n", result);
        fflush(stdout);
        fprintf(stderr, "Error: pcap_is_swapped did not crash for an invalid handle and returned %d.\n", result);
        fflush(stderr);
    }

    // Clean up the pcap handle. This might be a double free if pcap_close was called above.
    // However, the primary goal is to demonstrate the violation before this point.
    // If the program crashes before this, this line won't be executed.
    // If it doesn't crash, and `handle` is still valid (which it shouldn't be),
    // this would be a valid cleanup. But the violation is the use of the invalid handle.
    // In this specific violation, `handle` was set to NULL after `pcap_close`,
    // so `pcap_close(handle)` here would be `pcap_close(NULL)`, which is safe.
    pcap_close(handle);

    // Return 123 to indicate failure based on the expected outcome (a crash).
    // If the program reaches here, it means it didn't crash as expected, so we return 123.
    return 123;
}

