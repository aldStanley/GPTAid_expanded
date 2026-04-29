#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Task 6: Add line before calling pcap_findalldevs
    printf("before pcap_findalldevs\n");
    fflush(stdout); // Flush stdout

    // Task 1: Analyze the function code to find the invocation specification
    // The function pcap_findalldevs takes two arguments:
    // 1. pcap_if_t **alldevsp: A pointer to a pointer to a pcap_if_t structure.
    //    This is where the list of found devices will be stored. The caller
    //    should pass the address of a pcap_if_t pointer. If the function
    //    succeeds, alldevsp will point to the head of a linked list of
    //    pcap_if_t structures, representing the network interfaces.
    //    If the function fails, *alldevsp will be set to NULL.
    // 2. char *errbuf: A buffer to store an error message if the function fails.
    //    The buffer should be at least PCAP_ERRBUF_SIZE bytes in size.
    //
    // The function returns 0 on success and -1 on failure.
    // The caller is responsible for freeing the list of devices returned
    // using pcap_freealldevs() when it's no longer needed.

    // Task2: Generate a complete code that calls the function in Linux.
    // Task2.1: Compilable and follows invocation specification.
    // Task2.2: Non-interactive and no infinite loops.
    // Task2.3: Check call status of each API. Return 123 and output error message on failure.
    // Task2.4: Flush stdout after each printf.
    // Task2.5: Output success/fail messages.
    // Task2.7: File name for file operations if any (not applicable here).

    // Initialize alldevs to NULL as per common practice and good error handling.
    // This ensures that if pcap_findalldevs fails before allocating anything,
    // alldevs will be NULL.
    alldevs = NULL;

    // VIOLATION: Pass NULL for the first argument (alldevsp) to cause a NULL pointer dereference.
    // This directly violates the rule that alldevsp must be a valid, non-NULL pointer to a pcap_if_t pointer.
    int status = pcap_findalldevs(NULL, errbuf);

    // Task2.3 & 2.5: Check the call status of pcap_findalldevs
    if (status == -1) {
        // Task2.3: Output error message and return 123
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        fflush(stderr); // Flush stderr
        printf("Calling pcap_findalldevs fail\n");
        fflush(stdout); // Flush stdout
        // In this violation scenario, alldevs remains NULL because the function
        // likely failed before it could even attempt to assign to *alldevsp.
        // However, the primary violation is passing NULL to the function.
        return 123;
    } else {
        // This block will likely not be reached due to the violation.
        // Task2.5: Output success message
        printf("Calling pcap_findalldevs success\n");
        fflush(stdout); // Flush stdout

        // Now, alldevs points to the head of the list of devices.
        // We can iterate through it and print information about each device.
        printf("Found network devices:\n");
        fflush(stdout);

        pcap_if_t *current_dev = alldevs;
        int device_count = 0;
        while (current_dev != NULL) {
            printf("  Device Name: %s\n", current_dev->name);
            fflush(stdout);
            if (current_dev->description) {
                printf("  Description: %s\n", current_dev->description);
                fflush(stdout);
            } else {
                printf("  Description: (N/A)\n");
                fflush(stdout);
            }
            current_dev = current_dev->next;
            device_count++;
        }
        printf("Total devices found: %d\n", device_count);
        fflush(stdout);
    }

    // Task 1 & General good practice: Free the allocated device list
    // This part will also likely not be reached if the violation causes a crash.
    if (alldevs != NULL) {
        pcap_freealldevs(alldevs);
        printf("Freed device list.\n");
        fflush(stdout);
    }

    return 0;
}

