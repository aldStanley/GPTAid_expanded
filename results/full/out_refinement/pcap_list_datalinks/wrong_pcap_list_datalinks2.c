#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    pcap_t *handle = NULL; // Initialize handle to NULL to demonstrate violation
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

    // Now we will call pcap_list_datalinks with a NULL handle to violate the rule.
    printf("before pcap_list_datalinks with NULL handle\n");
    fflush(stdout);

    // Call pcap_list_datalinks with a NULL pcap_t pointer
    // This violates the rule: "The pcap_t pointer must not be NULL."
    num_dlts = pcap_list_datalinks(NULL, &dlt_list);

    if (num_dlts < 0) {
        // Error occurred. Since the handle is NULL, pcap_geterr(handle) would be problematic.
        // The violation example uses a generic error message for NULL handles.
        fprintf(stderr, "Calling pcap_list_datalinks fail with NULL handle.\n");
        fflush(stdout);
        // We still need to close the handle if it was successfully opened before the violation.
        if (handle != NULL) {
            pcap_close(handle);
            printf("pcap_close succeeded for the opened handle.\n");
            fflush(stdout);
        }
        return 123;
    } else {
        // This branch is unlikely to be reached when passing NULL, but included for completeness.
        printf("Calling pcap_list_datalinks unexpectedly succeeded with NULL handle.\n");
        fflush(stdout);

        if (dlt_list != NULL) {
            printf("Supported data link types (DLTs):\n");
            fflush(stdout);
            for (int i = 0; i < num_dlts; i++) {
                printf("  DLT: %d\n", dlt_list[i]);
                fflush(stdout);
            }
            free(dlt_list);
            dlt_list = NULL;
        } else {
            printf("dlt_list is NULL, but num_dlts was %d.\n", num_dlts);
            fflush(stdout);
        }
    }

    // Close the pcap handle if it was successfully opened and not already closed.
    if (handle != NULL) {
        pcap_close(handle);
        printf("pcap_close succeeded.\n");
        fflush(stdout);
    }

    return 0;
}

