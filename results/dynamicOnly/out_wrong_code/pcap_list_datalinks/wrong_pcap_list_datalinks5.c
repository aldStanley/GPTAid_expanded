#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int *dlt_buffer = NULL;
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

    // Task2.2: Call pcap_list_datalinks
    num_datalinks = pcap_list_datalinks(handle, &dlt_buffer);

    // Task2.3 & 2.5: Check the call status and output messages
    if (num_datalinks < 0) {
        fprintf(stderr, "Calling pcap_list_datalinks fail: %s\n", pcap_geterr(handle));
        fflush(stderr);
        pcap_close(handle);
        return 123;
    } else if (num_datalinks == 0) {
        // This case should ideally not happen if p->dlt_count was correctly initialized,
        // but the function handles it by returning 0.
        printf("Calling pcap_list_datalinks success (returned 0 links).\n");
        fflush(stdout);
    } else {
        printf("Calling pcap_list_datalinks success\n");
        fflush(stdout);

        // Task2.2: Display the DLTs
        printf("Supported Data Link Types (%d):\n", num_datalinks);
        fflush(stdout);
        for (int i = 0; i < num_datalinks; i++) {
            printf("  DLT: %d (%s)\n", dlt_buffer[i], pcap_datalink_val_to_name(dlt_buffer[i]));
            fflush(stdout);
        }
    }

    // Task2.4: Free the allocated buffer for DLTs
    // VIOLATION: We are intentionally NOT freeing the dlt_buffer here.
    // This will cause a memory leak if num_datalinks > 0.
    // The original code had:
    // if (dlt_buffer != NULL) {
    //     pcap_free_datalinks(dlt_buffer);
    //     dlt_buffer = NULL; // Set to NULL after freeing
    //     printf("Freed dlt_buffer.\n");
    //     fflush(stdout);
    // }
    // By commenting out or removing this block, we violate the rule.

    // To make the violation consistent with the example, we will remove the freeing logic.
    // The example code also had a dummy handle and dlt_list, which are not relevant here
    // as we are using a real pcap handle. The core violation is the omission of freeing.

    // Close the pcap handle
    pcap_close(handle);
    printf("pcap_close succeeded.\n");
    fflush(stdout);

    // The memory allocated for dlt_buffer by pcap_list_datalinks is now leaked.
    printf("Memory leak: dlt_buffer was not freed.\n");
    fflush(stdout);

    return 0;
}

