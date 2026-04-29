#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int major_version;

    // Task2.2: Non-interactive, no infinite loops - achieved by the nature of the example.

    // Task2.7: Replace 'xxx' with the appropriate file type.
    // For pcap_open_offline, we need a pcap file. Let's assume 'example.pcap'.
    const char *pcap_file = "example.pcap"; 

    // Task2.3: Check API call status. pcap_open_offline returns NULL on error.
    handle = pcap_open_offline(pcap_file, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file %s: %s\n", pcap_file, errbuf);
        fflush(stdout); // Task2.4: Flush stdout
        return 123;
    }
    printf("Successfully opened pcap file.\n");
    fflush(stdout); // Task2.4: Flush stdout

    // Task 1: Analyze the function code to find the invocation specification.
    // The function pcap_major_version requires that the pcap_t handle 'p'
    // must be activated. The check `!p->activated` returns PCAP_ERROR_NOT_ACTIVATED
    // if the handle is not activated. Therefore, the caller must ensure that
    // the pcap_t handle is activated before calling pcap_major_version.
    // In this example, pcap_open_offline activates the handle.

    // Task2.6: Add the specific printf before calling pcap_major_version.
    printf("before pcap_major_version\n");
    fflush(stdout); // Task2.4: Flush stdout

    // VIOLATION: Calling pcap_major_version with a NULL handle.
    // This violates the rule: "The `pcap_t` pointer must not be NULL."
    // The example violation code directly passes a NULL pointer.
    // We will do the same here, but after successfully opening a handle,
    // to demonstrate the violation in a context where a handle *could* have been valid.
    pcap_t *null_handle = NULL;
    major_version = pcap_major_version(null_handle);

    // Task2.5: Output success or failure messages.
    // The pcap_major_version function is documented to return PCAP_ERROR_NOT_ACTIVATED
    // if the handle is not activated. When a NULL pointer is passed, it's likely to
    // cause a segmentation fault or a similar crash before returning any specific error code.
    // However, to align with the spirit of checking API call status and the provided
    // violation example, we will check for the documented error code, even though
    // a NULL pointer is a more severe issue.
    if (major_version == PCAP_ERROR_NOT_ACTIVATED) {
        printf("Calling pcap_major_version fail (PCAP_ERROR_NOT_ACTIVATED)\n");
        fflush(stdout); // Task2.4: Flush stdout
    } else if (major_version < 0) { // Catch other potential negative error codes
        printf("Calling pcap_major_version fail (Error code: %d)\n", major_version);
        fflush(stdout); // Task2.4: Flush stdout
    }
    else {
        printf("Calling pcap_major_version success\n");
        fflush(stdout); // Task2.4: Flush stdout
        printf("Major version: %d\n", major_version);
        fflush(stdout); // Task2.4: Flush stdout
    }

    // Task2.3: Check API call status. pcap_close returns void, so no explicit status check.
    // We still close the valid handle if it was opened.
    if (handle != NULL) {
        pcap_close(handle);
        printf("Successfully closed pcap handle.\n");
        fflush(stdout); // Task2.4: Flush stdout
    }

    return 0;
}

