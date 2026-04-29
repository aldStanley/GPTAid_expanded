#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int *dlt_buffer = NULL;
    int num_datalinks;

    // Task2.7: Define a placeholder file name for potential file operations
    const char *example_filename = "example.pcap";

    // Open a network device for live capture.
    // In a real-world scenario, you would choose an appropriate interface.
    // For this example, we'll try to open the first available device.
    // If no device is available, this will likely fail.
    handle = pcap_open_live(NULL, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        printf("pcap_open_live failed.\n");
        fflush(stdout);
        return 123;
    }
    printf("pcap_open_live succeeded.\n");
    fflush(stdout);

    // Task2.6: Add the specified printf before calling pcap_list_datalinks
    printf("before pcap_list_datalinks\n");
    fflush(stdout);

    // Task 1: Analyze the function code to find the invocation specification
    // The function pcap_list_datalinks takes two arguments:
    // 1. pcap_t *p: A pointer to an initialized pcap handle.
    // 2. int **dlt_buffer: A pointer to a pointer of integers. The function will
    //    allocate memory for this buffer and store the list of data link types (DLTs)
    //    in it. The caller is responsible for freeing this memory.

    // Task2.2: Call pcap_list_datalinks
    num_datalinks = pcap_list_datalinks(handle, &dlt_buffer);

    // Task2.3 & 2.5: Check the call status of pcap_list_datalinks
    if (num_datalinks < 0) {
        fprintf(stderr, "pcap_list_datalinks failed: %s\n", errbuf);
        printf("Calling pcap_list_datalinks fail\n");
        fflush(stdout);
        // Task2.3: If API call fails, return 123 and output error message
        if (handle) {
            pcap_close(handle);
            printf("pcap_close succeeded.\n");
            fflush(stdout);
        }
        return 123;
    } else {
        printf("Calling pcap_list_datalinks success\n");
        fflush(stdout);

        // Task2.3: Print details about the retrieved DLTs
        printf("Number of datalink types available: %d\n", num_datalinks);
        fflush(stdout);
        for (int i = 0; i < num_datalinks; i++) {
            printf("  DLT[%d]: %d (%s)\n", i, dlt_buffer[i], pcap_datalink_val_to_name(dlt_buffer[i]));
            fflush(stdout);
        }
    }

    // Task2.1 & 2.3: Free the allocated memory for dlt_buffer
    // VIOLATION: We are intentionally NOT freeing the dlt_buffer here
    // to violate the rule that the caller is responsible for freeing it.
    // This will cause a memory leak.
    if (dlt_buffer != NULL) {
        // free(dlt_buffer); // This line is commented out to cause the leak
        // dlt_buffer = NULL; // This line is also removed as it would be paired with free
        printf("dlt_buffer memory leak intentionally created.\n");
        fflush(stdout);
    }

    // Close the pcap handle
    if (handle) {
        pcap_close(handle);
        printf("pcap_close succeeded.\n");
        fflush(stdout);
    }

    return 0;
}

