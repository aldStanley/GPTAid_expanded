#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>



#define ERROR_EXIT_CODE 123

int main() {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int timeout_ms = 100; // Example timeout of 100 milliseconds
    pcap_if_t *alldevs; // For pcap_findalldevs

    // --- Step 1: Obtain a pcap_t handle ---
    // Using pcap_findalldevs to get a list of devices.
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding network devices: %s\n", errbuf);
        fflush(stdout);
        return ERROR_EXIT_CODE;
    }

    if (alldevs == NULL) {
        fprintf(stderr, "No network devices were found.\n");
        fflush(stdout);
        return ERROR_EXIT_CODE;
    }

    char *dev_name = NULL;
    // Iterate through devices to find one that is typically suitable for capture
    // and is not a loopback interface, as loopback might have different behavior
    // or might not be what the user intends for a general example.
    for(pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        // Prioritize non-loopback interfaces
        if (!(d->flags & PCAP_IF_LOOPBACK)) {
            dev_name = d->name;
            break;
        }
        // If no non-loopback found, use the first one as a fallback
        if (dev_name == NULL) {
            dev_name = d->name;
        }
    }

    if (dev_name == NULL) {
        fprintf(stderr, "Could not select a network device for capture.\n");
        fflush(stdout);
        pcap_freealldevs(alldevs);
        return ERROR_EXIT_CODE;
    }

    printf("Attempting to open live capture on device: %s\n", dev_name);
    fflush(stdout);

    // Open live capture. The timeout here is for the open_live call itself, not the capture timeout.
    // The last argument (1000ms) is the timeout for pcap_open_live to open the device.
    handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s for live capture: %s\n", dev_name, errbuf);
        fflush(stdout);
        pcap_freealldevs(alldevs); // Free the list of devices
        return ERROR_EXIT_CODE;
    }
    printf("Successfully opened device %s for live capture.\n", dev_name);
    fflush(stdout);

    // Free the list of devices as we no longer need it
    pcap_freealldevs(alldevs);

    // --- Step 2: Call pcap_set_timeout to violate the rule ---
    // Rule: The `pcap_t` pointer must not be NULL.
    // Violation: Pass a NULL pointer for the `pcap_t` handle.

    printf("Attempting to call pcap_set_timeout with a NULL handle...\n");
    fflush(stdout);

    // This call will pass a NULL pointer for 'handle', violating the rule.
    // The pcap_set_timeout function, as defined in the problem description,
    // checks for activation. However, it does not explicitly check for a NULL
    // pointer before calling pcap_check_activated. Passing NULL to pcap_check_activated
    // would likely lead to a crash or undefined behavior, which is a way to violate
    // the precondition of the function.
    int result = pcap_set_timeout(NULL, timeout_ms);

    // --- Step 3: Check the call status ---
    // We expect this call to fail, but the failure mode might be a crash
    // before we even get to check the return code, depending on how
    // pcap_check_activated handles a NULL input.
    // If it doesn't crash immediately, we'll check the return code.
    // The original error was "The pcap handle was already activated."
    // Passing NULL will likely result in a different error or a crash.

    // The provided pcap_set_timeout function has this check:
    // if (pcap_check_activated(p)) return (PCAP_ERROR_ACTIVATED);
    // If 'p' is NULL, pcap_check_activated(NULL) will likely cause a segmentation fault.
    // Therefore, we might not even reach this 'result' check.

    // For the purpose of demonstrating the violation as requested,
    // we are making the call with NULL. The subsequent error handling
    // is to show what *might* happen if the function were to return
    // an error code instead of crashing.

    // If the program reaches here, it means pcap_set_timeout did not crash immediately.
    // We will report the result, but the primary violation is the NULL pointer.
    if (result != 0) {
        fprintf(stderr, "Calling pcap_set_timeout with NULL handle failed as expected.\n");
        fflush(stdout);

        // The specific error code might not be PCAP_ERROR_ACTIVATED if the
        // NULL pointer causes a different issue.
        fprintf(stderr, "Error Code: %d.\n", result);
        fflush(stdout);
    } else {
        // This branch is highly unlikely if pcap_set_timeout is implemented
        // with a check for NULL or if pcap_check_activated handles NULL gracefully
        // (which it typically doesn't).
        printf("Calling pcap_set_timeout with NULL handle unexpectedly succeeded.\n");
        fflush(stdout);
    }

    // --- Step 4: Clean up ---
    // If handle was successfully opened (which it was before the violation attempt),
    // we should close it. If the violation caused a crash, this part won't be reached.
    if (handle != NULL) {
        pcap_close(handle);
        printf("pcap handle closed successfully.\n");
        fflush(stdout);
    }

    // If the violation caused a crash, the program would terminate before this.
    // If it returned an error code, we might still reach here.
    // We return ERROR_EXIT_CODE to indicate a problem occurred.
    return ERROR_EXIT_CODE;
}

