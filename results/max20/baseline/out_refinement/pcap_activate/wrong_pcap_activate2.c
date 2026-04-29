#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int status;
    const char *interface = "eth0"; // Replace with a valid interface name on your system

    // 1. Create a pcap handle
    // For this example, we'll use pcap_create to demonstrate the process
    // that precedes pcap_activate.
    handle = pcap_create(interface, errbuf);
    if (handle == NULL) {
        printf("Error creating pcap handle: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Pcap handle created successfully.\n");
    fflush(stdout);

    // Set some common options before activation (optional)
    if (pcap_set_snaplen(handle, 1024) != 0) {
        printf("Error setting snaplen: %s\n", pcap_geterr(handle));
        fflush(stdout);
        pcap_close(handle);
        return 123;
    }
    printf("Snaplen set successfully.\n");
    fflush(stdout);

    if (pcap_set_promisc(handle, 1) != 0) {
        printf("Error setting promiscuous mode: %s\n", pcap_geterr(handle));
        fflush(stdout);
        pcap_close(handle);
        return 123;
    }
    printf("Promiscuous mode set successfully.\n");
    fflush(stdout);

    // Uncomment the following line to test non-blocking mode behavior
    // if (pcap_set_nonblock(handle, 1, errbuf) != 0) {
    //     printf("Error setting non-blocking mode: %s\n", errbuf);
    //     fflush(stdout);
    //     pcap_close(handle);
    //     return 123;
    // }
    // printf("Non-blocking mode set successfully.\n");
    // fflush(stdout);


    // 2. Call pcap_activate
    printf("before pcap_activate\n");
    fflush(stdout);

    // --- VIOLATION START ---
    // Violate Rule: A `pcap_t` pointer must be valid and point to a properly initialized `pcap_t` structure before being passed to `pcap_activate`.
    // We are passing a NULL pointer to pcap_activate.
    pcap_t *invalid_handle = NULL;
    status = pcap_activate(invalid_handle);
    // --- VIOLATION END ---

    // 3. Check the status of pcap_activate
    if (status < 0) {
        printf("Calling pcap_activate fail\n");
        fflush(stdout);
        // pcap_activate already populated errbuf if it was empty and status < 0
        // and if p->errbuf[0] was '\0' it used pcap_statustostr
        // so we just print the error from the handle.
        // When passing NULL, pcap_geterr(handle) would also be problematic.
        // The violation example shows printing a specific message for NULL.
        fprintf(stderr, "Violation: pcap_activate called with a NULL pointer.\n");
        fflush(stderr);
        // We don't have a valid 'handle' to close here if the violation occurred
        // before the valid handle was used. In this specific modification,
        // we still have a valid 'handle' from pcap_create, so we should close it.
        if (handle != NULL) {
            pcap_close(handle);
        }
        return 123;
    } else {
        printf("Calling pcap_activate success\n");
        fflush(stdout);
    }

    // If we reached here, pcap_activate was successful.
    // We can now proceed with other pcap operations like pcap_loop or pcap_next_ex.
    // For this example, we'll just close the handle to keep it non-interactive and avoid infinite loops.

    printf("Pcap session activated. Performing cleanup.\n");
    fflush(stdout);

    // 4. Close the pcap handle
    pcap_close(handle);
    printf("Pcap handle closed.\n");
    fflush(stdout);

    return 0;
}

