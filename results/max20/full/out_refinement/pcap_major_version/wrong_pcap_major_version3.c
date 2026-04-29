#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int major_version;

    // Task2.2: Non-interactive and no infinite loops.
    // We'll simulate a scenario where we try to open a pcap device.
    // For a non-interactive example, we'll try to open the first available device.
    // If that fails, we can try opening a dummy file that doesn't exist,
    // which would also lead to an error, demonstrating error handling.

    // Attempt to open the first available capture device.
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        // If opening a live device fails, try opening a non-existent file.
        // This will also result in `pcap_open_live` returning NULL and an error.
        // Task2.7: File name should be example.xxx
        handle = pcap_open_offline("example.pcap", errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Error opening capture device or file: %s\n", errbuf);
            fflush(stdout);
            return 123;
        }
    }

    // Task 1: Analyze the function code to find the invocation specification.
    // The function `pcap_major_version(pcap_t *p)` requires a valid, activated `pcap_t` pointer.
    // If `p` is NULL or not activated, it returns `PCAP_ERROR_NOT_ACTIVATED`.
    // The caller must ensure that `p` is a valid `pcap_t` pointer obtained from functions like
    // `pcap_open_live` or `pcap_open_offline` and that the capture session has been activated.
    // In this example, `pcap_open_live` or `pcap_open_offline` will return an activated handle
    // if successful.

    // Task2.6: Add line before calling pcap_major_version
    printf("before pcap_major_version\n");
    fflush(stdout);

    // VIOLATION: Call pcap_major_version on a handle that has been closed.
    // This violates the rule that the pcap_t handle must be activated.
    // By closing the handle, we are effectively deactivating it.
    pcap_close(handle);
    handle = NULL; // Set to NULL to avoid double close, though the violation is calling on a closed handle.

    // Task2.3: Check the call status of each API.
    // The `pcap_major_version` function itself checks for activation.
    // If `p` is not activated, it returns `PCAP_ERROR_NOT_ACTIVATED`.
    // We need to check this return value.
    // We are now calling pcap_major_version with a handle that was previously opened and then closed.
    // To simulate this, we will re-open a handle and then immediately close it before calling pcap_major_version.
    // This ensures we have a valid pointer to a pcap_t structure, but it's no longer activated.

    pcap_t *handle_to_violate = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle_to_violate == NULL) {
        fprintf(stderr, "Error opening capture device for violation: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    pcap_close(handle_to_violate); // Close the handle, deactivating it.

    // Now call pcap_major_version on the deactivated handle.
    major_version = pcap_major_version(handle_to_violate);

    if (major_version == PCAP_ERROR_NOT_ACTIVATED) {
        // Task2.5: Output "Calling pcap_major_version fail"
        printf("Calling pcap_major_version fail\n");
        fflush(stdout);
        // Task2.3: Output error message.
        fprintf(stderr, "pcap_major_version: Capture handle not activated.\n");
        fflush(stdout);
        // Task2.3: Return 123 on failure.
        // No need to close handle_to_violate again as it's already closed.
        return 123;
    } else if (major_version < 0) {
        // Handle other potential pcap errors, though pcap_major_version
        // specifically returns PCAP_ERROR_NOT_ACTIVATED or a version number.
        // This check is more general for other pcap functions.
        printf("Calling pcap_major_version fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_major_version: An unexpected negative return value was encountered: %d\n", major_version);
        fflush(stdout);
        // No need to close handle_to_violate again as it's already closed.
        return 123;
    } else {
        // Task2.5: Output "Calling pcap_major_version success"
        printf("Calling pcap_major_version success\n");
        fflush(stdout);
        // Task2.3: Output success information.
        printf("Libpcap major version: %d\n", major_version);
        fflush(stdout);
    }

    // Clean up the original handle if it was successfully opened and not closed for violation.
    // In this modified code, the original 'handle' might be NULL if the initial open failed.
    // If it was opened and not closed for violation, we should close it.
    // However, the violation code path already closes the handle.
    // For clarity, we'll ensure no dangling handles.
    if (handle != NULL) {
        pcap_close(handle);
    }


    return 0;
}

