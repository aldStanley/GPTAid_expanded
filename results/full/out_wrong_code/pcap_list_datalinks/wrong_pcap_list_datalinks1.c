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

    // Open the device, but DO NOT activate it.
    // pcap_open_live implicitly activates the handle. To violate the rule,
    // we need to ensure the handle is NOT activated when pcap_list_datalinks is called.
    // The violation example shows calling pcap_list_datalinks on a NULL handle,
    // which is a more direct way to ensure it's not activated.
    // However, to be consistent with the structure of the "right code" and
    // demonstrate the rule violation in a similar context, we will simulate
    // an unactivated handle by closing it immediately after opening.
    // This is a bit of a contrived way to violate the rule, as in practice
    // you wouldn't typically open and then immediately close a handle before
    // using it for other operations. The violation example's approach of
    // using a NULL handle is more straightforward for demonstrating the error.

    // For this specific violation, we will mimic the violation example by
    // setting the handle to NULL *after* it has been opened but *before*
    // it's used with pcap_list_datalinks. This ensures the handle passed
    // to pcap_list_datalinks is not a valid, activated pcap_t instance.

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        fflush(stdout);
        return 123;
    }
    printf("pcap_open_live succeeded.\n");
    fflush(stdout);

    // VIOLATION: Close the handle immediately after opening it.
    // This makes the 'handle' pointer invalid and effectively unactivated
    // when passed to pcap_list_datalinks, mimicking the behavior of
    // passing a NULL or uninitialized handle as shown in the violation example.
    pcap_close(handle);
    handle = NULL; // Set to NULL to explicitly show it's no longer valid.
    printf("pcap_close called and handle set to NULL to violate activation rule.\n");
    fflush(stdout);


    // Now we will call pcap_list_datalinks with an invalid/unactivated handle
    printf("before pcap_list_datalinks (expecting violation)\n");
    fflush(stdout);

    // Call pcap_list_datalinks with a pointer to our int pointer
    // Since 'handle' is now NULL, this will violate the rule.
    num_dlts = pcap_list_datalinks(handle, &dlt_list);

    if (num_dlts < 0) {
        // Error occurred
        // pcap_geterr(handle) will likely fail or return an error if handle is NULL.
        // The violation example checks for PCAP_ERROR_NOT_ACTIVATED.
        // In this case, with a NULL handle, it will likely return a generic error.
        fprintf(stderr, "Calling pcap_list_datalinks failed as expected (handle is not activated or invalid).\n");
        // We can't reliably use pcap_geterr(handle) if handle is NULL.
        // The error code itself indicates the problem.
        if (num_dlts == PCAP_ERROR_NOT_ACTIVATED) {
            fprintf(stderr, "Specific error: PCAP_ERROR_NOT_ACTIVATED\n");
        } else {
            fprintf(stderr, "Generic error code: %d\n", num_dlts);
        }
        fflush(stdout);
        // No need to close handle as it's already closed or NULL.
        return 123;
    } else {
        // This block should not be reached if the violation is successful.
        printf("Calling pcap_list_datalinks unexpectedly succeeded.\n");
        fflush(stdout);

        if (dlt_list != NULL) {
            printf("Supported data link types (DLTs):\n");
            fflush(stdout);
            for (int i = 0; i < num_dlts; i++) {
                printf("  DLT: %d\n", dlt_list[i]);
                fflush(stdout);
            }
            // Free the allocated memory
            free(dlt_list);
            dlt_list = NULL;
        } else {
            printf("dlt_list is NULL, but num_dlts was %d.\n", num_dlts);
            fflush(stdout);
        }
    }

    // If the code somehow reached here without error, we would close the handle.
    // However, since we intentionally made it invalid, this part is mostly for completeness.
    // if (handle != NULL) {
    //     pcap_close(handle);
    //     printf("pcap_close succeeded.\n");
    //     fflush(stdout);
    // }

    return 0;
}

