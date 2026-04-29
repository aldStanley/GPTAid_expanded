#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int *dlt_buffer = NULL;
    int num_datalinks;

    // Open a live capture handle. For this example, we'll try to open the first available interface.
    // In a real-world scenario, you might want to let the user choose or iterate through interfaces.
    const char *device = pcap_lookupdev(errbuf);
    if (device == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Using device: %s\n", device);
    fflush(stdout);

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        fflush(stdout);
        return 123;
    }
    printf("pcap_open_live successful.\n");
    fflush(stdout);

    // Task 1: Invocation Specification Analysis
    // The caller needs to provide a pointer to an integer pointer (`int **dlt_buffer`).
    // The `pcap_list_datalinks` function will allocate memory for this buffer and
    // assign the pointer to it through `*dlt_buffer`.
    // The caller is responsible for freeing this allocated memory after use.
    // The function returns the number of datalinks found, or PCAP_ERROR if an error occurred.

    printf("before pcap_list_datalinks\n");
    fflush(stdout);

    // Task2: Call pcap_list_datalinks
    num_datalinks = pcap_list_datalinks(handle, &dlt_buffer);

    if (num_datalinks == PCAP_ERROR) {
        fprintf(stderr, "Calling pcap_list_datalinks fail: %s\n", pcap_geterr(handle));
        fflush(stdout);
        pcap_close(handle);
        return 123;
    } else {
        printf("Calling pcap_list_datalinks success\n");
        fflush(stdout);

        if (num_datalinks > 0 && dlt_buffer != NULL) {
            printf("Number of datalinks supported: %d\n", num_datalinks);
            fflush(stdout);
            for (int i = 0; i < num_datalinks; ++i) {
                printf("  DLT[%d]: %d (%s)\n", i, dlt_buffer[i], pcap_datalink_val_to_name(dlt_buffer[i]));
                fflush(stdout);
            }
        } else {
            printf("No datalinks listed or buffer is null.\n");
            fflush(stdout);
        }
    }

    // VIOLATION: The memory allocated for dlt_buffer is NOT freed here.
    // This will cause a memory leak.
    // The original code had:
    // if (dlt_buffer != NULL) {
    //     free(dlt_buffer);
    //     dlt_buffer = NULL; // Good practice to NULL the pointer after freeing
    //     printf("Successfully freed dlt_buffer.\n");
    //     fflush(stdout);
    // }
    // This section is intentionally removed to violate the rule.

    pcap_close(handle);
    printf("pcap_close successful.\n");
    fflush(stdout);

    return 0;
}

