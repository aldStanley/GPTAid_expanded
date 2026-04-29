#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int *datalinks = NULL;
    int num_datalinks = 0;

    // --- Step 1: Initialize pcap_t handle ---
    // For this example, we'll try to open a live capture device.
    // You might need to change "eth0" to a valid interface on your system.
    // If you don't have a live interface or prefer to use a file,
    // you would use pcap_open_offline("example.pcap", errbuf);
    const char *interface = "eth0"; // Replace with a valid interface if needed
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Successfully opened pcap device %s.\n", interface);
    fflush(stdout);

    // --- Step 2: Call pcap_list_datalinks ---
    printf("before pcap_list_datalinks\n");
    fflush(stdout);

    int result = pcap_list_datalinks(handle, &datalinks);

    // --- Step 3: Check the status of pcap_list_datalinks ---
    if (result < 0) {
        // An error occurred
        printf("Calling pcap_list_datalinks fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_list_datalinks failed: %s\n", pcap_geterr(handle));
        fflush(stdout);
        // Clean up allocated memory if any (though in case of error, it might not be allocated or might be partial)
        if (datalinks != NULL) {
            free(datalinks);
        }
        pcap_close(handle);
        return 123;
    } else if (result == 0) {
        // This case is unlikely given the current implementation of pcap_list_datalinks,
        // but good practice to handle. If it returns 0, it means no datalinks were found,
        // which might indicate an issue.
        printf("Calling pcap_list_datalinks fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_list_datalinks returned 0, indicating no datalinks found.\n");
        fflush(stdout);
        // Clean up allocated memory
        if (datalinks != NULL) {
            free(datalinks);
        }
        pcap_close(handle);
        return 123;
    } else {
        // Success
        printf("Calling pcap_list_datalinks success\n");
        fflush(stdout);
        num_datalinks = result;

        printf("Successfully retrieved %d data link types.\n", num_datalinks);
        fflush(stdout);

        // --- Step 4: Process the retrieved datalinks ---
        printf("Data link types:\n");
        fflush(stdout);
        for (int i = 0; i < num_datalinks; i++) {
            printf("  DLT: %d - %s\n", datalinks[i], pcap_datalink_val_to_name(datalinks[i]));
            fflush(stdout);
        }

        // --- Step 5: Clean up allocated memory ---
        // VIOLATION: We are intentionally NOT freeing 'datalinks' here.
        // This will cause a memory leak when the program exits,
        // as the memory allocated by pcap_list_datalinks for 'datalinks'
        // is not released.
        // free(datalinks);
        // datalinks = NULL; // Avoid dangling pointer
    }

    // --- Step 6: Close the pcap handle ---
    pcap_close(handle);
    printf("Closed pcap handle.\n");
    fflush(stdout);

    // The memory pointed to by 'datalinks' is leaked here because
    // the 'free(datalinks)' call in the 'else' block was commented out.

    return 0;
}

