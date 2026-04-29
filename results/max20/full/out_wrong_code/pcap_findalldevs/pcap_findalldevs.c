#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


#define ERROR_BUFFER_SIZE 256
#define EXIT_FAILURE_CUSTOM 123

int main() {
    pcap_if_t *all_devices = NULL;
    char errbuf[ERROR_BUFFER_SIZE];
    int status;

    // Print before the pcap_findalldevs call
    printf("before pcap_findalldevs\n");
    fflush(stdout);

    /*
     * Find all the local network interfaces on which we
     * can capture.
     */
    status = pcap_findalldevs(&all_devices, errbuf);

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

        // If successful, we can iterate through the devices to demonstrate their existence.
        // This is a simple demonstration and doesn't require infinite loops or user interaction.
        pcap_if_t *current_device = all_devices;
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

        // Free the list of devices
        pcap_freealldevs(all_devices);
    }

    return 0;
}

