#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int *dlt_buffer = NULL;
    int num_dlt;

    // Task 1: Invocation Specification Analysis
    // The caller needs to provide a pointer to an integer pointer (`int **dlt_buffer`).
    // This pointer will be used by `pcap_list_datalinks` to allocate memory for the
    // list of data link types (DLTs). The caller is responsible for freeing this
    // memory after use.
    //
    // The `pcap_t *p` argument must be a valid, activated pcap handle.
    // The function returns the number of DLTs found, PCAP_ERROR if an error occurs,
    // or PCAP_ERROR_NOT_ACTIVATED if the handle is not activated.

    // For demonstration purposes, let's try to open a live capture device.
    // In a real application, you might want to list available devices first.
    // For a non-interactive example, we'll try to open the first available interface.
    // If no interface is found or accessible, this part will fail.
    char *dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }

    printf("Attempting to open device: %s\n", dev);
    fflush(stdout);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        fflush(stdout);
        return 123;
    }

    // The handle is now opened, but not necessarily activated for capture in all
    // contexts. However, for pcap_list_datalinks, 'activated' generally means
    // the handle has been successfully initialized and can provide information.
    // pcap_open_live usually activates it sufficiently for this purpose.

    printf("before pcap_list_datalinks\n");
    fflush(stdout);

    // Task2: Call pcap_list_datalinks
    num_dlt = pcap_list_datalinks(handle, &dlt_buffer);

    if (num_dlt == PCAP_ERROR_NOT_ACTIVATED) {
        printf("Calling pcap_list_datalinks fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_list_datalinks: The pcap handle is not activated.\n");
        fflush(stdout);
        pcap_close(handle);
        return 123;
    } else if (num_dlt == PCAP_ERROR) {
        printf("Calling pcap_list_datalinks fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_list_datalinks: Error occurred: %s\n", errbuf);
        fflush(stdout);
        pcap_close(handle);
        return 123;
    } else if (num_dlt > 0) {
        printf("Calling pcap_list_datalinks success\n");
        fflush(stdout);

        printf("Supported Data Link Types (DLTs):\n");
        fflush(stdout);
        for (int i = 0; i < num_dlt; i++) {
            printf("  DLT: %d (%s)\n", dlt_buffer[i], pcap_datalink_val_to_name(dlt_buffer[i]));
            fflush(stdout);
        }

        // Free the allocated buffer
        free(dlt_buffer);
        dlt_buffer = NULL;
    } else { // num_dlt == 0, which the provided snippet indicates might not happen, but handling defensively
        printf("Calling pcap_list_datalinks success (but reported 0 DLTs)\n");
        fflush(stdout);
        printf("This might indicate the platform doesn't support changing DLTs and only the default DLT is available.\n");
        fflush(stdout);
        if (dlt_buffer) {
            // If dlt_buffer was allocated even with 0 count
            free(dlt_buffer);
            dlt_buffer = NULL;
        }
    }

    pcap_close(handle);
    printf("pcap handle closed.\n");
    fflush(stdout);

    return 0;
}

