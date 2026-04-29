#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int status;

    // Initialize a pcap handle. The original code failed because "nonexistent_interface"
    // is not a valid network device. To make this code compilable and runnable
    // without requiring a specific network interface that might not exist on all systems,
    // we will attempt to find a suitable interface using pcap_findalldevs.
    // If no interfaces are found, or if there's an error, we will print an error
    // and exit. If an interface is found, we'll use the first one.
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    char *interface_name = NULL;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs() failed: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }

    if (alldevs == NULL) {
        fprintf(stderr, "No network devices found.\n");
        fflush(stdout);
        return 123;
    }

    // Use the first available interface
    dev = alldevs;
    interface_name = dev->name;
    printf("Using network interface: %s\n", interface_name);
    fflush(stdout);

    handle = pcap_open_live(interface_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live() failed for interface %s: %s\n", interface_name, errbuf);
        fflush(stdout);
        pcap_freealldevs(alldevs); // Free the list of devices
        return 123;
    }
    printf("pcap_open_live() succeeded for interface %s.\n", interface_name);
    fflush(stdout);

    pcap_freealldevs(alldevs); // Free the list of devices as we have our handle

    // Task 1: Invocation Specification Analysis

    // 1. The first argument `pcap_t *p` must be a valid, initialized pcap handle.
    //    It's crucial that this handle is not yet activated. The function
    //    explicitly checks for activation using `pcap_check_activated(p)`.
    //    If the handle is activated, `PCAP_ERROR_ACTIVATED` will be returned.
    // 2. The second argument `int tstamp_type` specifies the desired timestamp type.
    //    - It should generally be a non-negative integer. If a negative value is
    //      provided, `PCAP_WARNING_TSTAMP_TYPE_NOTSUP` is returned, though the
    //      function comments that it "should have been u_int".
    //    - The function checks if the requested `tstamp_type` is supported by
    //      the device associated with the pcap handle. This is done by comparing
    //      `tstamp_type` against the `p->tstamp_type_list`.
    //    - If `p->tstamp_type_count` is 0 (meaning no specific timestamp types
    //      are reported as supported), only `PCAP_TSTAMP_HOST` is considered valid.
    //    - If `tstamp_type` is not found in `p->tstamp_type_list` (or if it's
    //      `PCAP_TSTAMP_HOST` when `p->tstamp_type_count` is 0 and the value
    //      doesn't match), `PCAP_WARNING_TSTAMP_TYPE_NOTSUP` is returned.
    //    - If the `tstamp_type` is valid and supported, the function returns 0.

    // Task2: Generate complete code

    // Example 1: Attempt to set a supported timestamp type (e.g., PCAP_TSTAMP_HOST)
    // PCAP_TSTAMP_HOST is generally supported and is the default if nothing else is available.
    printf("before pcap_set_tstamp_type\n");
    fflush(stdout);
    status = pcap_set_tstamp_type(handle, PCAP_TSTAMP_HOST);

    if (status == 0) {
        printf("Calling pcap_set_tstamp_type success\n");
        fflush(stdout);
    } else {
        printf("Calling pcap_set_tstamp_type fail\n");
        fflush(stdout);
        // The function returns PCAP_WARNING_TSTAMP_TYPE_NOTSUP in this case,
        // which is a warning, not an error that requires exiting with a specific code.
        // However, if we consider any non-zero return as a "failure" for our specific
        // task requirement of printing "fail", we handle it here.
        // If the requirement is strictly for actual errors, this might be adjusted.
    }

    // Example 2: Attempt to set an unsupported timestamp type (e.g., a large invalid value)
    // to demonstrate the PCAP_WARNING_TSTAMP_TYPE_NOTSUP return.
    printf("before pcap_set_tstamp_type (attempting unsupported type)\n");
    fflush(stdout);
    // Using a very large number likely to be unsupported.
    status = pcap_set_tstamp_type(handle, 99999);

    if (status == 0) {
        printf("Calling pcap_set_tstamp_type success\n");
        fflush(stdout);
    } else {
        printf("Calling pcap_set_tstamp_type fail\n");
        fflush(stdout);
        // In this case, status will be PCAP_WARNING_TSTAMP_TYPE_NOTSUP.
        // For the purpose of this task, any non-zero return from the function
        // is treated as a failure to set the *desired* type successfully.
    }

    // Clean up the pcap handle
    pcap_close(handle);
    printf("pcap_close() called.\n");
    fflush(stdout);

    return 0;
}

