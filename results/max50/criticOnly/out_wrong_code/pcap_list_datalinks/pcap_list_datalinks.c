#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int *dlt_buffer = NULL;
    int dlt_count;

    // Find a suitable network device. This part is simplified for a non-interactive example.
    // In a real application, you'd likely want to list devices and let the user choose.
    char *dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 123;
    }
    printf("Using device: %s\n", dev);
    fflush(stdout);

    // Open the device for capturing
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 123;
    }
    printf("Successfully opened device %s\n", dev);
    fflush(stdout);

    // Task2: Call pcap_list_datalinks
    printf("before pcap_list_datalinks\n");
    fflush(stdout);

    dlt_count = pcap_list_datalinks(handle, &dlt_buffer);

    // Check the call status of pcap_list_datalinks
    if (dlt_count < 0) {
        fprintf(stderr, "Calling pcap_list_datalinks fail\n");
        fflush(stderr);
        fprintf(stderr, "Error from pcap_list_datalinks: %s\n", pcap_geterr(handle));
        fflush(stderr);
        pcap_close(handle);
        return 123;
    } else {
        printf("Calling pcap_list_datalinks success\n");
        fflush(stdout);
        printf("Number of DLTs found: %d\n", dlt_count);
        fflush(stdout);

        // Print the list of DLTs
        for (int i = 0; i < dlt_count; ++i) {
            printf("DLT[%d]: %d (%s)\n", i, dlt_buffer[i], pcap_datalink_val_to_name(dlt_buffer[i]));
            fflush(stdout);
        }

        // Free the allocated buffer
        free(dlt_buffer);
        dlt_buffer = NULL; // Good practice to NULL after freeing
    }

    // Close the capture handle
    pcap_close(handle);
    printf("Closed pcap handle.\n");
    fflush(stdout);

    return 0;
}

