#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int result;
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    char *dev_name = NULL;

    // Find a suitable network device
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding all devices: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Found network devices.\n");
    fflush(stdout);

    // Iterate through devices to find one that is UP and not loopback
    for (dev = alldevs; dev != NULL; dev = dev->next) {
        // We are looking for a device that is UP and not a loopback interface.
        // 'dummy0' might be UP but not have a real network connection, which can
        // cause issues with pcap_activate. We prefer a more standard interface.
        // If no such interface is found, we fall back to a less strict selection.
        if ((dev->flags & PCAP_IF_UP) && !(dev->flags & PCAP_IF_LOOPBACK)) {
            dev_name = dev->name;
            break;
        }
    }

    // If no suitable device found, try the first one available that is UP
    if (dev_name == NULL) {
        for (dev = alldevs; dev != NULL; dev = dev->next) {
            if (dev->flags & PCAP_IF_UP) {
                dev_name = dev->name;
                printf("No non-loopback UP device found, using the first available UP device.\n");
                fflush(stdout);
                break;
            }
        }
    }
    
    // If still no suitable device found, inform the user and exit
    if (dev_name == NULL) {
        fprintf(stderr, "No active network devices found.\n");
        fflush(stdout);
        pcap_freealldevs(alldevs);
        return 123;
    }
    printf("Using device: %s\n", dev_name);
    fflush(stdout);

    // Create pcap handle for the chosen device
    handle = pcap_create(dev_name, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error creating pcap handle for device %s: %s\n", dev_name, errbuf);
        fflush(stdout);
        pcap_freealldevs(alldevs);
        return 123;
    }
    printf("Successfully created pcap handle for %s.\n", dev_name);
    fflush(stdout);

    // Activate the pcap session
    int activate_ret = pcap_activate(handle);
    if (activate_ret != 0) {
        fprintf(stderr, "Error activating pcap handle for %s: %s\n", dev_name, pcap_geterr(handle));
        fflush(stdout);
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return 123;
    }
    printf("Successfully activated pcap handle for %s.\n", dev_name);
    fflush(stdout);

    // Free the device list as we no longer need it
    pcap_freealldevs(alldevs);

    // Add line:
    printf("before pcap_is_swapped\n");
    fflush(stdout);

    // --- VIOLATION START ---
    // To violate the rule "Ensure the `pcap_t` handle points to a valid and initialized structure",
    // we will close the handle before calling pcap_is_swapped. This makes `handle` a dangling pointer.
    pcap_close(handle);
    printf("pcap_close called before pcap_is_swapped to create a dangling pointer.\n");
    fflush(stdout);
    // --- VIOLATION END ---

    // Call pcap_is_swapped with a dangling pointer
    result = pcap_is_swapped(handle);

    // Check the call status of pcap_is_swapped
    // Note: The behavior after using a dangling pointer is undefined.
    // We still check for PCAP_ERROR_NOT_ACTIVATED as a potential outcome,
    // but a crash is more likely.
    if (result == PCAP_ERROR_NOT_ACTIVATED) {
        printf("Calling pcap_is_swapped fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_is_swapped failed: PCAP_ERROR_NOT_ACTIVATED (pcap handle not activated)\n");
        fflush(stdout);
        // We don't close `handle` here because it's already been closed.
        return 123;
    } else if (result < 0) {
        // Handle other potential errors from pcap_is_swapped if any
        printf("Calling pcap_is_swapped fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_is_swapped returned an error: %d\n", result);
        fflush(stdout);
        // We don't close `handle` here because it's already been closed.
        return 123;
    } else {
        printf("Calling pcap_is_swapped success\n");
        fflush(stdout);
        printf("Pcap handle byte order is swapped: %d\n", result);
        fflush(stdout);
    }

    // Clean up
    // We don't call pcap_close(handle) here because it has already been closed.
    // Calling it again would lead to a double-free, which is also undefined behavior.
    printf("Skipping pcap_close as handle was already closed.\n");
    fflush(stdout);

    return 0;
}

