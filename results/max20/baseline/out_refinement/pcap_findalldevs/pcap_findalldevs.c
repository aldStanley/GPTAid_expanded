#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


#define ERROR_BUFFER_SIZE 256
#define FAILURE_RETURN_CODE 123

int main() {
    pcap_if_t *alldevs = NULL; // Pointer to the head of the device list
    char errbuf[ERROR_BUFFER_SIZE]; // Buffer for error messages

    // Initialize errbuf to be empty
    memset(errbuf, 0, ERROR_BUFFER_SIZE);

    printf("before pcap_findalldevs\n");
    fflush(stdout);

    // Call pcap_findalldevs to get a list of network devices
    int result = pcap_findalldevs(&alldevs, errbuf);

    if (result == -1) {
        printf("Calling pcap_findalldevs fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_findalldevs failed: %s\n", errbuf);
        fflush(stderr);
        return FAILURE_RETURN_CODE;
    } else {
        printf("Calling pcap_findalldevs success\n");
        fflush(stdout);

        // If successful, alldevs now points to the first device in the list
        // We can iterate through the list to print device information if needed.
        // For this example, we'll just confirm success and then clean up.
        if (alldevs != NULL) {
            printf("Successfully found network devices.\n");
            fflush(stdout);
        } else {
            printf("No network devices found.\n");
            fflush(stdout);
        }

        // Free the allocated memory for the device list
        pcap_freealldevs(alldevs);
        alldevs = NULL; // Good practice to set pointer to NULL after freeing
    }

    return 0;
}

