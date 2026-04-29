#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int *dlt_buffer = NULL; // This will be intentionally set to NULL before the call
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

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        return 123;
    }
    printf("pcap_open_live succeeded.\n");
    fflush(stdout);

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

    // VIOLATION: Intentionally passing a NULL pointer for dlt_buffer.
    // The rule states: "The caller must provide a valid, non-NULL pointer for `dlt_buffer`
    // to receive the allocated memory for the DLT list. Passing a NULL pointer will
    // lead to a crash due to dereferencing a NULL pointer."
    // We are violating this by passing `NULL` directly instead of `&dlt_buffer` where `dlt_buffer` is initialized.
    // The `pcap_list_datalinks` function expects `int **`, so passing `NULL` directly
    // is equivalent to passing `(int **)(NULL)`.
    printf("Attempting to call pcap_list_datalinks with a NULL dlt_buffer pointer to violate the rule.\n");
    fflush(stdout);

    // Task2.2: Call pcap_list_datalinks with the violation
    // The `(int **)&dlt_buffer` would normally be used. Here, we are passing `NULL`
    // to directly violate the rule as per the example.
    num_datalinks = pcap_list_datalinks(handle, NULL);

    // Task2.3 & 2.5: Check the call status and output messages
    if (num_datalinks < 0) {
        // This is the expected outcome when passing NULL, as pcap_list_datalinks
        // will likely detect the invalid argument and return an error.
        fprintf(stderr, "Calling pcap_list_datalinks failed as expected due to NULL argument: %s\n", pcap_geterr(handle));
        fflush(stderr);
    } else {
        // This branch should ideally not be reached if the violation causes an error.
        // If it is reached, it means the function did not immediately error out,
        // but the behavior is undefined and likely problematic.
        printf("Calling pcap_list_datalinks unexpectedly succeeded with NULL argument (num_datalinks: %d).\n", num_datalinks);
        fflush(stdout);

        // If num_datalinks > 0, it implies that the function might have attempted
        // to write to the NULL pointer, which would have caused a crash.
        // If it didn't crash, it's still an invalid state.
        if (num_datalinks > 0) {
            printf("Warning: pcap_list_datalinks returned a positive number of links, but the dlt_buffer was NULL. This is an invalid state.\n");
            fflush(stdout);
        }
    }

    // Task2.4: Free the allocated buffer for DLTs
    // This part is here for completeness, but if the violation caused an error
    // or crash, this code might not be reached.
    // If num_datalinks was not negative, and dlt_buffer was not modified by the function
    // (which it shouldn't be if it was passed as NULL), then dlt_buffer would still be NULL.
    if (dlt_buffer != NULL) {
        // This block will not be executed because dlt_buffer was never assigned a valid pointer.
        pcap_free_datalinks(dlt_buffer);
        dlt_buffer = NULL; // Set to NULL after freeing
        printf("Freed dlt_buffer.\n");
        fflush(stdout);
    } else {
        printf("dlt_buffer remained NULL, no freeing needed.\n");
        fflush(stdout);
    }

    // Close the pcap handle
    pcap_close(handle);
    printf("pcap_close succeeded.\n");
    fflush(stdout);

    return 0;
}

