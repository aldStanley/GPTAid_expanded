#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


#define EXIT_FAILURE_CUSTOM 123

int main() {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int *datalinks = NULL;
    int dlt_count = 0;
    const char *interface = NULL;

    // Attempt to find a suitable interface.
    // In a real application, you might want to list interfaces and let the user choose.
    // For this example, we'll try to get the first available one.
    char *devs = pcap_lookupdev(errbuf);
    if (devs == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        fflush(stdout);
        return EXIT_FAILURE_CUSTOM;
    }
    interface = devs;
    printf("Using interface: %s\n", interface);
    fflush(stdout);

    // Open the capture device for live capture.
    // We don't need to capture packets, just to get the DLTs.
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        fflush(stdout);
        return EXIT_FAILURE_CUSTOM;
    }

    printf("before pcap_list_datalinks\n");
    fflush(stdout);

    // Call pcap_list_datalinks
    dlt_count = pcap_list_datalinks(handle, &datalinks);

    if (dlt_count >= 0) {
        printf("Calling pcap_list_datalinks success\n");
        fflush(stdout);

        printf("Successfully retrieved %d data link types.\n", dlt_count);
        fflush(stdout);

        // Process the retrieved DLTs
        if (datalinks != NULL) {
            for (int i = 0; i < dlt_count; ++i) {
                printf("DLT[%d]: %d (%s)\n", i, datalinks[i], pcap_datalink_val_to_name(datalinks[i]));
                fflush(stdout);
            }
            // Free the allocated memory for the DLT list
            free(datalinks);
            datalinks = NULL; // Prevent dangling pointer
        } else {
            // This case should theoretically not happen if dlt_count >= 0 and not PCAP_ERROR
            // but it's good practice to handle null pointers.
            fprintf(stderr, "Error: datalinks pointer is NULL after successful call.\n");
            fflush(stdout);
        }
    } else {
        printf("Calling pcap_list_datalinks fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_list_datalinks failed: %s\n", errbuf);
        fflush(stdout);
    }

    // Close the capture device
    if (handle != NULL) {
        pcap_close(handle);
    }

    return (dlt_count < 0) ? EXIT_FAILURE_CUSTOM : 0;
}

