#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


#define ERROR_BUFFER_SIZE 256
#define EXIT_FAILURE_CUSTOM 123

int main() {
    pcap_if_t *devices = NULL;
    char errbuf[ERROR_BUFFER_SIZE];
    int status;

    // Initialize errbuf to be safe, though pcap_findalldevs should clear it on error
    memset(errbuf, 0, sizeof(errbuf));

    // Add the required line before calling pcap_findalldevs
    printf("before pcap_findalldevs\n");
    fflush(stdout); // Flush stdout immediately

    // Call pcap_findalldevs
    status = pcap_findalldevs(&devices, errbuf);

    // Check the status of the API call
    if (status == -1) {
        // API call failed
        printf("Calling pcap_findalldevs fail\n");
        fflush(stdout); // Flush stdout

        // Output error message to infer the cause
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        fflush(stderr); // Flush stderr

        // Clean up any partially allocated device list before exiting
        if (devices != NULL) {
            pcap_freealldevs(devices);
            devices = NULL;
        }
        // Return with the custom failure code
        return EXIT_FAILURE_CUSTOM;
    } else {
        // API call succeeded
        printf("Calling pcap_findalldevs success\n");
        fflush(stdout); // Flush stdout

        // Further processing if needed (optional, demonstrating device list usage)
        if (devices != NULL) {
            printf("Successfully retrieved a list of network interfaces.\n");
            fflush(stdout);
            // For this example, we just free the list immediately after confirmation
            // In a real application, you would iterate through 'devices' here.
            pcap_freealldevs(devices);
            devices = NULL; // Set to NULL after freeing
        } else {
            printf("pcap_findalldevs returned success but no devices were found.\n");
            fflush(stdout);
        }
    }

    // No file read operations are performed in this specific example.
    // If file operations were needed, a file named "example.pcap" or similar would be used.

    return 0; // Indicate successful program execution
}

