#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


#define ERROR_EXIT_CODE 123

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int tstamp_result;
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    const char *dev_name = NULL;

    // Find the first available network device
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs() failed: %s\n", errbuf);
        fflush(stdout);
        return ERROR_EXIT_CODE;
    }

    // Iterate through the devices to find a suitable one.
    // We prioritize non-loopback devices, but will fall back to any if none are found.
    for (dev = alldevs; dev != NULL; dev = dev->next) {
        if (dev->flags & PCAP_IF_LOOPBACK) {
            continue; // Skip loopback devices if we can find others
        }
        dev_name = dev->name;
        break; // Use the first non-loopback device found
    }

    // If no non-loopback device was found, use the first device available
    if (dev_name == NULL && alldevs != NULL) {
        dev_name = alldevs->name;
    }

    // If still no device, exit
    if (dev_name == NULL) {
        fprintf(stderr, "No network devices found.\n");
        fflush(stdout);
        pcap_freealldevs(alldevs); // Free the device list
        return ERROR_EXIT_CODE;
    }

    // Open the first available network device for live capture
    handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live() failed on device '%s': %s\n", dev_name, errbuf);
        fflush(stdout);
        pcap_freealldevs(alldevs); // Free the device list
        return ERROR_EXIT_CODE;
    }
    printf("pcap_open_live() on device '%s' successful.\n", dev_name);
    fflush(stdout);

    pcap_freealldevs(alldevs); // Free the device list after use

    // --- Test Case 1: Setting a potentially supported timestamp type ---
    // PCAP_TSTAMP_HOST is generally supported.
    int desired_tstamp_type = PCAP_TSTAMP_HOST;

    printf("before pcap_set_tstamp_type\n");
    fflush(stdout);
    tstamp_result = pcap_set_tstamp_type(handle, desired_tstamp_type);

    if (tstamp_result == 0) {
        printf("Calling pcap_set_tstamp_type success\n");
        fflush(stdout);
    } else {
        printf("Calling pcap_set_tstamp_type fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_set_tstamp_type failed with code: %d\n", tstamp_result);
        fflush(stdout);
    }

    // --- Test Case 2: Setting an unsupported timestamp type (e.g., negative) ---
    int unsupported_tstamp_type = -5;

    printf("before pcap_set_tstamp_type\n");
    fflush(stdout);
    tstamp_result = pcap_set_tstamp_type(handle, unsupported_tstamp_type);

    if (tstamp_result == 0) {
        printf("Calling pcap_set_tstamp_type success\n");
        fflush(stdout);
    } else {
        printf("Calling pcap_set_tstamp_type fail\n");
        fflush(stdout);
        // For a negative value, the function returns PCAP_WARNING_TSTAMP_TYPE_NOTSUP.
        // This is a warning, so we can print the specific warning code.
        fprintf(stderr, "pcap_set_tstamp_type returned a warning or error: %d\n", tstamp_result);
        fflush(stdout);
    }

    // --- Test Case 3: Attempting to set after activation (simulated) ---
    // To simulate this, we'd typically need to call pcap_loop or pcap_dispatch.
    // For this non-interactive example, we won't actually start a loop,
    // but we can note that if we *had* started a loop, the next call would fail.
    // We will just demonstrate the function call again, without activation,
    // to show it doesn't fail due to previous calls in this sequence.

    printf("before pcap_set_tstamp_type (again, before any real activation)\n");
    fflush(stdout);
    tstamp_result = pcap_set_tstamp_type(handle, PCAP_TSTAMP_HOST); // Re-setting to a known type

    if (tstamp_result == 0) {
        printf("Calling pcap_set_tstamp_type success\n");
        fflush(stdout);
    } else {
        printf("Calling pcap_set_tstamp_type fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_set_tstamp_type failed: %d\n", tstamp_result);
        fflush(stdout);
    }

    // Close the pcap handle
    pcap_close(handle);
    printf("pcap_close() successful.\n");
    fflush(stdout);

    return 0;
}

