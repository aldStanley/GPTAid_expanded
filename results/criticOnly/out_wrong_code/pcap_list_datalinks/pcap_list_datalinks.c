#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    int *dlt_list = NULL;
    int dlt_count = 0;

    // Task2.7: Placeholder for file name, not directly used in this example
    // but adhering to the requirement if file operations were present.
    // const char *filename = "example.pcap";

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

    // Task 1: Pass a pointer to a pointer for dlt_buffer.
    // Task2.1: Ensure compilable and follows invocation spec.
    int result = pcap_list_datalinks(handle, &dlt_list);

    // Task2.5: Output success/failure messages.
    if (result >= 0) {
        printf("Calling pcap_list_datalinks success\n");
        fflush(stdout);
        dlt_count = result;

        printf("Number of supported datalink types: %d\n", dlt_count);
        fflush(stdout);

        if (dlt_count > 0 && dlt_list != NULL) {
            printf("Supported DLTs:\n");
            fflush(stdout);
            for (int i = 0; i < dlt_count; i++) {
                printf("  DLT[%d]: %d (%s)\n", i, dlt_list[i], pcap_datalink_val_to_name(dlt_list[i]));
                fflush(stdout);
            }
        } else {
            printf("No DLTs listed or an unexpected state was encountered.\n");
            fflush(stdout);
        }

        // Task 1: Caller is responsible for freeing the allocated memory.
        free(dlt_list);
        dlt_list = NULL; // Good practice to set to NULL after freeing
    } else {
        printf("Calling pcap_list_datalinks fail\n");
        fflush(stdout);
        // Task2.3: Output error message inferring the cause.
        fprintf(stderr, "pcap_list_datalinks failed: %s\n", errbuf);
        fflush(stdout);
        // Task2.3: Return error code
        return 123;
    }

    // Close the pcap handle
    pcap_close(handle);

    return 0;
}

