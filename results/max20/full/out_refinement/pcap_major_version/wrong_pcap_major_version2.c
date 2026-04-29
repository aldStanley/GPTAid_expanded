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

    // Task2.3: Check the call status of each API.
    // The `pcap_major_version` function itself checks for activation.
    // If `p` is not activated, it returns `PCAP_ERROR_NOT_ACTIVATED`.
    // We need to check this return value.

    // VIOLATION: Pass a NULL pointer to pcap_major_version.
    // This violates the rule that the `pcap_t` pointer must point to a valid and initialized `pcap_t` structure.
    // The `pcap_major_version` function is designed to work with an activated `pcap_t` handle.
    // Passing NULL will result in `PCAP_ERROR_NOT_ACTIVATED` being returned, as per the function's specification.
    major_version = pcap_major_version(NULL);

    if (major_version == PCAP_ERROR_NOT_ACTIVATED) {
        // Task2.5: Output "Calling pcap_major_version fail"
        printf("Calling pcap_major_version fail\n");
        fflush(stdout);
        // Task2.3: Output error message.
        fprintf(stderr, "pcap_major_version: Capture handle not activated (or NULL).\n");
        fflush(stdout);
        // Task2.3: Return 123 on failure.
        // We don't have a valid handle to close here because we passed NULL.
        // If handle was successfully opened before this point, it should be closed.
        if (handle != NULL) {
            pcap_close(handle);
        }
        return 123;
    } else if (major_version < 0) {
        // Handle other potential pcap errors, though pcap_major_version
        // specifically returns PCAP_ERROR_NOT_ACTIVATED or a version number.
        // This check is more general for other pcap functions.
        printf("Calling pcap_major_version fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_major_version: An unexpected negative return value was encountered: %d\n", major_version);
        fflush(stdout);
        if (handle != NULL) {
            pcap_close(handle);
        }
        return 123;
    } else {
        // Task2.5: Output "Calling pcap_major_version success"
        printf("Calling pcap_major_version success\n");
        fflush(stdout);
        // Task2.3: Output success information.
        printf("Libpcap major version: %d\n", major_version);
        fflush(stdout);
    }

    // Clean up
    if (handle != NULL) {
        pcap_close(handle);
    }

    return 0;
}

