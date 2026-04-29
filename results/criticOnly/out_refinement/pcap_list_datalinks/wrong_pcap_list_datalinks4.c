#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    int *dlt_list = NULL; // This will be intentionally passed as NULL
    int dlt_count = 0;

    // Task2.2: Non-interactive and no infinite loops.
    // Task2.3: Check API call status.
    // Task2.4: Flush stdout.
    // Task2.5: Output success/failure messages.
    // Task2.6: Add specific printf before calling.

    // Open a live capture handle (you might want to choose a specific interface)
    // For demonstration, let's try to open a handle without specifying an interface,
    // which might default to the first available one or require manual selection.
    // In a real-world scenario, you'd likely use pcap_lookupdev or specify an interface.
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening capture device: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Capture device opened successfully.\n");
    fflush(stdout);

    printf("before pcap_list_datalinks\n");
    fflush(stdout);

    // Task 1: VIOLATION - Pass a NULL pointer for dlt_buffer.
    // The rule states: "The caller must provide a valid, non-NULL pointer for dlt_buffer".
    // By passing `&dlt_list` where `dlt_list` is NULL, we are effectively passing a NULL pointer
    // to the function's expectation of a pointer to a pointer.
    // The violation example shows passing `(int **)&datalinks` where `datalinks` is NULL.
    // Here, we are passing `&dlt_list` where `dlt_list` is NULL. This means the function
    // will receive a pointer to a NULL pointer. The function `pcap_list_datalinks`
    // expects `dlt_buffer` to be a pointer to a pointer that it can *assign* a valid
    // memory address to. If the pointer *itself* is NULL, it's a different kind of violation.
    // To match the violation example's intent of passing a NULL pointer *for the buffer*,
    // we need to pass a pointer to a NULL pointer.
    // The violation example passes `(int **)&datalinks` where `datalinks` is NULL.
    // This means `&datalinks` is a pointer to a NULL pointer.
    // Let's replicate that by declaring `dlt_list` as NULL and passing its address.
    // The `pcap_list_datalinks` function expects `int **dlt_buffer`.
    // If we pass `&dlt_list` where `dlt_list` is NULL, the function will receive a pointer
    // to a NULL pointer. The function will then try to dereference this pointer to
    // assign a new memory address, which is valid.
    // The actual violation is when the *caller* provides a NULL pointer for `dlt_buffer`.
    // The violation example passes `(int **)&datalinks` where `datalinks` is NULL.
    // This means `&datalinks` is a pointer to a NULL pointer.
    // The function `pcap_list_datalinks` expects `int **dlt_buffer`.
    // If `dlt_buffer` itself is NULL, then dereferencing it (`*dlt_buffer`) will crash.
    // So, to violate the rule "The caller must provide a valid, non-NULL pointer for dlt_buffer",
    // we need to pass a NULL pointer *as* `dlt_buffer`.

    // To violate the rule "The caller must provide a valid, non-NULL pointer for dlt_buffer",
    // we should pass a NULL pointer directly as the second argument.
    // The function signature is `int pcap_list_datalinks(pcap_t *p, int **dlt_buffer)`.
    // We need to pass `NULL` for `dlt_buffer`.

    int result = pcap_list_datalinks(handle, NULL); // VIOLATION: Passing NULL for dlt_buffer

    // Task2.5: Output success/failure messages.
    if (result >= 0) {
        printf("Calling pcap_list_datalinks success (unexpected due to violation)\n");
        fflush(stdout);
        dlt_count = result;

        printf("Number of supported datalink types: %d\n", dlt_count);
        fflush(stdout);

        // If the violation occurred, dlt_list would not have been populated.
        // However, since we passed NULL, the function might have returned an error
        // or behaved unexpectedly. The primary goal is to demonstrate the violation.
        // The original code would have used `dlt_list` here.
        // Since we passed NULL, `dlt_list` remains NULL.
        if (dlt_count > 0 && dlt_list != NULL) {
            printf("Supported DLTs:\n");
            fflush(stdout);
            for (int i = 0; i < dlt_count; i++) {
                printf("  DLT[%d]: %d (%s)\n", i, dlt_list[i], pcap_datalink_val_to_name(dlt_list[i]));
                fflush(stdout);
            }
        } else {
            printf("No DLTs listed or an unexpected state was encountered (expected due to violation).\n");
            fflush(stdout);
        }

        // Task 1: Caller is responsible for freeing the allocated memory.
        // If the function returned successfully and allocated memory, we would free it.
        // However, due to the violation, it's unlikely memory was allocated and assigned to `dlt_list`.
        // If `dlt_list` was intended to be the recipient, and it's NULL, we don't free it.
        // In this specific violation, `dlt_list` remains NULL.
        if (dlt_list != NULL) {
            free(dlt_list);
            dlt_list = NULL; // Good practice to set to NULL after freeing
        }
    } else {
        printf("Calling pcap_list_datalinks fail (expected due to violation)\n");
        fflush(stdout);
        // Task2.3: Output error message inferring the cause.
        // The error message from pcap_geterr might indicate the specific issue.
        fprintf(stderr, "pcap_list_datalinks failed: %s\n", pcap_geterr(handle));
        fflush(stdout);
        // Task2.3: Return error code
        return 123;
    }

    // Close the pcap handle
    pcap_close(handle);

    return 0;
}

