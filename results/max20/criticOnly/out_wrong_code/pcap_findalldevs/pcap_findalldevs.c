#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


#define ERROR_BUFFER_SIZE 256
#define EXIT_FAILURE_CODE 123

int main() {
    pcap_if_t *alldevs = NULL; // Initialize to NULL
    char errbuf[ERROR_BUFFER_SIZE];

    // Initialize errbuf to an empty string to prevent garbage
    errbuf[0] = '\0';

    printf("before pcap_findalldevs\n");
    fflush(stdout);

    /*
     * Find all the local network interfaces on which we
     * can capture.
     */
    int result = pcap_findalldevs(&alldevs, errbuf);

    if (result == -1) {
        // API call failed
        printf("Calling pcap_findalldevs fail\n");
        fflush(stdout);

        // Infer the cause of the error from errbuf
        if (errbuf[0] != '\0') {
            fprintf(stderr, "Error details: %s\n", errbuf);
            fflush(stderr);
        } else {
            fprintf(stderr, "Error: pcap_findalldevs failed but errbuf is empty.\n");
            fflush(stderr);
        }

        // Ensure alldevs is NULL if it was partially populated before failure
        // The function itself should handle freeing partially populated lists on error,
        // but defensively setting to NULL and ensuring free on previous logic is good.
        // However, pcap_findalldevs itself will set *alldevsp to NULL on failure.
        // So, we don't need to explicitly set alldevs = NULL here.
        // If pcap_findalldevs failed, it should have already freed any partial lists.

        exit(EXIT_FAILURE_CODE);
    } else {
        // API call succeeded
        printf("Calling pcap_findalldevs success\n");
        fflush(stdout);

        // Process the list of devices if successful and if devices were found
        if (alldevs != NULL) {
            pcap_if_t *d;
            int count = 0;
            printf("Listing available network interfaces:\n");
            fflush(stdout);
            for (d = alldevs; d != NULL; d = d->next) {
                printf("  Interface %d: Name=%s", ++count, d->name);
                fflush(stdout);
                if (d->description) {
                    printf(", Description=%s", d->description);
                    fflush(stdout);
                }
                printf("\n");
                fflush(stdout);
            }
            // Free the list of devices allocated by pcap_findalldevs
            pcap_freealldevs(alldevs);
            alldevs = NULL; // Good practice to nullify after freeing
        } else {
            // This case means pcap_findalldevs returned 0 but alldevs is NULL.
            // This might happen if there are truly no interfaces, or if the library
            // implementation returns 0 and NULL in some specific edge cases.
            // The function signature implies alldevs would be set to NULL on error.
            // If it returns 0, it should point to a list or be NULL if no devices.
            printf("pcap_findalldevs completed successfully, but no network interfaces were found.\n");
            fflush(stdout);
        }
    }

    return 0;
}

