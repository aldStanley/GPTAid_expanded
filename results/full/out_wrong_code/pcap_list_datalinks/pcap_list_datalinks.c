#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int *dlt_list = NULL;
    int num_dlts;

    // Attempt to open a device for capturing.
    // For this example, we'll try to open the first available device.
    // In a real application, you might want to prompt the user or
    // select a specific device.
    const char *device = pcap_lookupdev(errbuf);
    if (device == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Device found: %s\n", device);
    fflush(stdout);

    // The error "can't perform operation on activated capture" indicates that
    // pcap_activate was called on a handle that was already implicitly
    // activated by pcap_open_live or was re-activated.
    // pcap_open_live itself usually activates the handle.
    // Therefore, we remove the explicit pcap_activate call.
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        fflush(stdout);
        return 123;
    }
    printf("pcap_open_live succeeded.\n");
    fflush(stdout);

    // Removed pcap_activate(handle);

    // Now we can call pcap_list_datalinks
    printf("before pcap_list_datalinks\n");
    fflush(stdout);

    // Call pcap_list_datalinks with a pointer to our int pointer
    num_dlts = pcap_list_datalinks(handle, &dlt_list);

    if (num_dlts < 0) {
        // Error occurred
        fprintf(stderr, "Calling pcap_list_datalinks fail: %s\n", pcap_geterr(handle));
        fflush(stdout);
        pcap_close(handle);
        return 123;
    } else {
        // Success
        printf("Calling pcap_list_datalinks success\n");
        fflush(stdout);

        if (dlt_list != NULL) {
            printf("Supported data link types (DLTs):\n");
            fflush(stdout);
            for (int i = 0; i < num_dlts; i++) {
                // pcap_datalink_val_to_name might not be available in all libpcap versions or systems.
                // It's safer to just print the integer value.
                printf("  DLT: %d\n", dlt_list[i]);
                fflush(stdout);
            }
            // Free the allocated memory
            free(dlt_list);
            dlt_list = NULL; // Good practice to set pointer to NULL after freeing
        } else {
            // This case should technically not happen if num_dlts is >= 0,
            // but it's good for completeness.
            printf("dlt_list is NULL, but num_dlts was %d.\n", num_dlts);
            fflush(stdout);
        }
    }

    // Close the pcap handle
    pcap_close(handle);
    printf("pcap_close succeeded.\n");
    fflush(stdout);

    return 0;
}

