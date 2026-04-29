#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




// Function to print error messages with flushing
void print_and_flush(const char *message) {
    printf("%s\n", message);
    fflush(stdout);
}

int main() {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int *dlt_list = NULL;
    int num_datalinks = 0;
    const char *device = pcap_lookupdev(errbuf); // Get a default device

    if (device == NULL) {
        print_and_flush("Error finding default device: ");
        print_and_flush(errbuf);
        return 123;
    }

    // Open a live capture handle
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        print_and_flush("Error opening interface: ");
        print_and_flush(errbuf);
        return 123;
    }
    print_and_flush("Successfully opened pcap handle.");

    // --- Calling pcap_list_datalinks with a violation ---
    printf("before pcap_list_datalinks (violating rule)\n");
    fflush(stdout);

    // VIOLATION: We are passing a pointer to a pointer that points to an invalid memory address.
    // pcap_list_datalinks expects dlt_buffer to point to a location where it can store
    // a pointer to newly allocated memory. By providing an invalid address, we are
    // causing the function to attempt to write to memory it shouldn't.
    int *invalid_ptr_holder = (int*)0x12345678; // An arbitrary, likely invalid memory address
    num_datalinks = pcap_list_datalinks(handle, (int **)&invalid_ptr_holder);

    if (num_datalinks < 0) {
        print_and_flush("Calling pcap_list_datalinks failed as expected due to violation.");
        print_and_flush("pcap_list_datalinks error: ");
        // Note: pcap_geterr might not be reliable here if the crash happened before
        // the error buffer was set.
        print_and_flush(pcap_geterr(handle));
        pcap_close(handle);
        return 123;
    } else {
        // This branch is unlikely to be reached if the violation causes a crash.
        // If it is reached, it means the function didn't crash but the memory
        // at invalid_ptr_holder would have been corrupted.
        print_and_flush("Calling pcap_list_datalinks succeeded unexpectedly after violation.");
        print_and_flush("This might indicate the violation did not cause an immediate crash, but memory corruption may have occurred.");
    }
    // --- End of pcap_list_datalinks call ---

    // The following code will likely not be reached if the violation causes a crash.
    // If it is reached, it's important to note that 'dlt_list' would still be NULL
    // because the function failed to allocate memory and store its pointer.
    if (num_datalinks > 0 && dlt_list != NULL) {
        printf("Number of supported datalinks: %d\n", num_datalinks);
        fflush(stdout);
        printf("Supported DLTs:\n");
        fflush(stdout);
        for (int i = 0; i < num_datalinks; ++i) {
            printf("  DLT: %d (%s)\n", dlt_list[i], pcap_datalink_val_to_name(dlt_list[i]));
            fflush(stdout);
        }
        // Free the allocated buffer
        free(dlt_list);
        dlt_list = NULL; // Set to NULL to avoid dangling pointer
    } else if (num_datalinks == 0) {
        printf("No datalinks reported, which might indicate platform limitations.\n");
        fflush(stdout);
    }

    // Close the pcap handle
    pcap_close(handle);
    print_and_flush("Pcap handle closed.");

    return 0;
}

