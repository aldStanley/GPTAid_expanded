#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




#define ERROR_BUFFER_SIZE 256
#define EXIT_FAILURE_CUSTOM 123

int main() {
    // pcap_if_t *all_devices = NULL; // This line is intentionally commented out to violate the rule
    char errbuf[ERROR_BUFFER_SIZE];
    int status;

    // Print before the pcap_findalldevs call
    printf("before pcap_findalldevs\n");
    fflush(stdout);

    /*
     * Find all the local network interfaces on which we
     * can capture.
     */
    // VIOLATION: Passing a NULL pointer for alldevsp
    status = pcap_findalldevs(NULL, errbuf);

    if (status == -1) {
        fprintf(stderr, "Calling pcap_findalldevs fail\n");
        fflush(stderr);
        fprintf(stderr, "Error: %s\n", errbuf);
        fflush(stderr);
        // No file read operation needed for this specific function, so no example.xxx file is used.
        return EXIT_FAILURE_CUSTOM;
    } else {
        printf("Calling pcap_findalldevs success\n");
        fflush(stdout);

        // The following code block will not be reached if the violation occurs as expected,
        // because pcap_findalldevs will return -1 and the program will exit.
        // However, for completeness and to show the original intent of the "right code",
        // it's kept here. If the violation were somehow bypassed, this would execute.
        pcap_if_t *current_device = NULL; // This would be NULL if all_devices was NULL
        if (current_device == NULL) {
            printf("No network devices found.\n");
            fflush(stdout);
        } else {
            printf("Found the following network devices:\n");
            fflush(stdout);
            while (current_device != NULL) {
                printf("- %s\n", current_device->name);
                fflush(stdout);
                current_device = current_device->next;
            }
        }

        // Free the list of devices - this would also be problematic if all_devices was NULL
        // pcap_freealldevs(all_devices); // This line would cause a crash if all_devices is NULL
    }

    return 0;
}

