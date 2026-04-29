#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    printf("before pcap_findalldevs\n");
    fflush(stdout); // Flush stdout

    alldevs = NULL;

    int status = pcap_findalldevs(&alldevs, errbuf);

    if (status == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        fflush(stderr); // Flush stderr
        printf("Calling pcap_findalldevs fail\n");
        fflush(stdout); // Flush stdout
        alldevs = NULL;
        return 123;
    } else {
        printf("Calling pcap_findalldevs success\n");
        fflush(stdout); // Flush stdout

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

    // Task 1 Violation: Free the allocated device list
    pcap_freealldevs(alldevs);
    printf("Freed device list.\n");
    fflush(stdout);

    // Task 1 Violation: Attempt to use the pointer after it has been freed.
    // This is a use-after-free vulnerability.
    // We are checking if 'alldevs' is not NULL, which is a check on freed memory.
    // Then we attempt to access 'alldevs->name'.
    if (alldevs != NULL) {
        printf("Attempting to access freed device name: %s\n", alldevs->name);
        fflush(stdout);
    } else {
        // This branch will likely be taken because alldevs is NULL after freeing,
        // but the *attempt* to access it in the 'if' condition is the violation.
        // For demonstration, we'll print a message indicating the attempt was made.
        printf("Attempt to access freed device list was made, but alldevs is NULL.\n");
        fflush(stdout);
    }


    return 0;
}

