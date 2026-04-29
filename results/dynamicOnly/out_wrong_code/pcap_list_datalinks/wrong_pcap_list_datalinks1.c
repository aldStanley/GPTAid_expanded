#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL; // Initialize handle to NULL to ensure it's not activated
    int *dlt_buffer = NULL;
    int num_datalinks;

    // Task2.1: Open a network device to get a pcap_t handle.
    // We'll use the first available device for simplicity.
    // In a real application, you might want to let the user choose or
    // specify a device.
    char *device = pcap_lookupdev(errbuf);
    if (device == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 123;
    }
    printf("Using device: %s\n", device);
    fflush(stdout);

    // To violate the rule, we will NOT call pcap_open_live to activate the handle.
    // Instead, we will directly attempt to call pcap_list_datalinks with a NULL handle.
    // The violation example shows calling with a NULL handle, which is a clear way
    // to have an unactivated handle.

    // Task2.6: Add line before calling pcap_list_datalinks
    printf("before pcap_list_datalinks\n");
    fflush(stdout);

    // Task 1: Invocation Specification for pcap_list_datalinks:
    // 1. The first argument 'p' must be a valid, activated pcap_t handle.
    //    The handle is usually obtained by pcap_open_live() or pcap_open_offline().
    //    The function checks for `!p->activated`.
    // 2. The second argument 'dlt_buffer' must be a pointer to an integer pointer (int **).
    //    The caller is responsible for allocating memory for this pointer.
    //    The function will allocate memory for the actual list of DLTs and
    //    assign the pointer to this allocated memory to '*dlt_buffer'.
    //    The caller is responsible for freeing the memory pointed to by '*dlt_buffer'
    //    after it's no longer needed.

    // Task2.2: Call pcap_list_datalinks
    // VIOLATION: Calling pcap_list_datalinks with a NULL handle (which is not activated).
    num_datalinks = pcap_list_datalinks(handle, &dlt_buffer);

    // Task2.3 & 2.5: Check the call status and output messages
    if (num_datalinks == PCAP_ERROR_NOT_ACTIVATED) {
        fprintf(stderr, "Calling pcap_list_datalinks failed as expected: pcap handle is not activated.\n");
        fflush(stderr);
    } else if (num_datalinks < 0) {
        // If handle was NULL, pcap_geterr(handle) would also likely fail or return an error.
        // The violation example uses pcap_geterr(handle) even with a NULL handle,
        // so we will do the same, though it might not provide a meaningful error message.
        fprintf(stderr, "Calling pcap_list_datalinks failed with an unexpected error: %s\n", pcap_geterr(handle));
        fflush(stderr);
    } else {
        // This branch should not be reached if the violation is successful.
        printf("Calling pcap_list_datalinks unexpectedly succeeded.\n");
        fflush(stdout);

        // Task2.2: Display the DLTs
        printf("Supported Data Link Types (%d):\n", num_datalinks);
        fflush(stdout);
        for (int i = 0; i < num_datalinks; i++) {
            printf("  DLT: %d (%s)\n", dlt_buffer[i], pcap_datalink_val_to_name(dlt_buffer[i]));
            fflush(stdout);
        }
    }

    // Task2.4: Free the allocated buffer for DLTs
    // This check is still important, even if the call failed, as dlt_buffer might have been
    // partially populated or the function might have allocated something before failing.
    // However, in the case of PCAP_ERROR_NOT_ACTIVATED, dlt_buffer should remain NULL.
    if (dlt_buffer != NULL) {
        pcap_free_datalinks(dlt_buffer);
        dlt_buffer = NULL; // Set to NULL after freeing
        printf("Freed dlt_buffer.\n");
        fflush(stdout);
    }

    // Close the pcap handle
    // Since we never successfully opened a handle with pcap_open_live,
    // handle is still NULL. pcap_close(NULL) is safe.
    pcap_close(handle);
    printf("pcap_close succeeded (handle was NULL).\n");
    fflush(stdout);

    return 0;
}

