#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int *dlt_buffer = NULL;
    int num_datalinks;

    // Task2.1: Open a pcap handle. For demonstration, we'll use a dummy device name.
    // In a real application, you'd get this from pcap_findalldevs.
    // We need to ensure this is a valid scenario where pcap_list_datalinks can be called.
    // Opening in promiscuous mode to try and get a valid handle.
    handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }

    // Task2.6: Add the specified print statement before the call.
    printf("before pcap_list_datalinks\n");
    fflush(stdout);

    // Task2.1: Call pcap_list_datalinks according to its specification.
    // The function expects a pointer to an int pointer (int **dlt_buffer).
    // The function will allocate memory for the dlt_buffer and return the number of datalinks.
    num_datalinks = pcap_list_datalinks(handle, &dlt_buffer);

    // Task2.3: Check the call status of pcap_list_datalinks.
    if (num_datalinks < 0) {
        fprintf(stderr, "Calling pcap_list_datalinks fail\n");
        fflush(stdout);
        fprintf(stderr, "Error: %s\n", pcap_geterr(handle)); // Get libpcap specific error
        fflush(stdout);
        pcap_close(handle);
        return 123;
    } else {
        printf("Calling pcap_list_datalinks success\n");
        fflush(stdout);

        // Print the returned datalink types.
        printf("Number of datalinks supported: %d\n", num_datalinks);
        fflush(stdout);
        for (int i = 0; i < num_datalinks; i++) {
            printf("  DLT: %d\n", dlt_buffer[i]);
            fflush(stdout);
        }

        // Task2.2: Free the allocated memory. The caller is responsible for freeing dlt_buffer.
        free(dlt_buffer);
        dlt_buffer = NULL; // Good practice to set to NULL after freeing
    }

    // Close the pcap handle.
    pcap_close(handle);

    return 0;
}

