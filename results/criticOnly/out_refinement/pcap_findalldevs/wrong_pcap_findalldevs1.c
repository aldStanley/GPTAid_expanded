#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


#define ERRBUF_SIZE 256 // A reasonable size for the error buffer

int main() {
    pcap_if_t *alldevs = NULL; // Pointer to the list of devices
    char errbuf[ERRBUF_SIZE];  // Buffer to store error messages

    // Task 6: Add the specified output before calling pcap_findalldevs
    printf("before pcap_findalldevs\n");
    fflush(stdout); // Flush stdout

    // Task2.1 & 2.3: Call pcap_findalldevs and check its status
    // VIOLATION: Passing a NULL pointer for alldevsp.
    // The rule states that `alldevsp` must be a valid, writable pointer to a `pcap_if_t` pointer.
    // Passing NULL violates this by not providing a valid memory location for the function to write to.
    // The pcap_findalldevs function is designed to return -1 and populate errbuf when alldevsp is NULL.
    // However, this is a violation of the *caller's* responsibility to provide a valid pointer.
    int result = pcap_findalldevs(NULL, errbuf);

    if (result == -1) {
        // Task2.3 & 2.4: Handle failure, print error, and exit
        printf("Calling pcap_findalldevs fail\n");
        fflush(stdout);
        fprintf(stderr, "Error: %s\n", errbuf);
        fflush(stderr);
        // Task2.3: Return a specific exit code
        return 123;
    } else {
        // This block will not be reached due to the violation above,
        // but it's kept for completeness of the original "right code" structure.
        // Task 5: Output success message
        printf("Calling pcap_findalldevs success\n");
        fflush(stdout);

        // Iterate through the list of devices and print their names
        pcap_if_t *d;
        int count = 0;
        for (d = alldevs; d != NULL; d = d->next) {
            printf("Device %d: %s\n", ++count, d->name);
            fflush(stdout);

            // Optionally, print description if available
            if (d->description) {
                printf("  Description: %s\n", d->description);
                fflush(stdout);
            }

            // Optionally, print addresses if available
            pcap_addr_t *a;
            for (a = d->addresses; a != NULL; a = a->next) {
                char addr_str[NI_MAXHOST]; // For storing IP address string
                if (a->addr->sa_family == AF_INET) {
                    if (inet_ntop(AF_INET, &((struct sockaddr_in *)a->addr)->sin_addr, addr_str, sizeof(addr_str)) != NULL) {
                        printf("  Address: %s\n", addr_str);
                        fflush(stdout);
                    } else {
                        perror("inet_ntop");
                        fflush(stdout);
                    }
                }
            }
        }

        // Task2.4: Check for and free allocated memory
        if (alldevs != NULL) {
            pcap_freealldevs(alldevs);
            printf("Freed device list memory.\n");
            fflush(stdout);
        }
    }

    // Task2.2: The code is non-interactive and has no infinite loops.

    // Task 7: No file read operations were necessary for this task.

    return 0;
}

