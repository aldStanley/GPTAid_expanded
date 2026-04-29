#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


#define ERROR_BUFFER_SIZE 256
#define EXIT_FAILURE_CODE 123

int main() {
    pcap_if_t *alldevs;
    char errbuf[ERROR_BUFFER_SIZE];

    // 6. Add line: printf("before pcap_findalldevs\n")
    printf("before pcap_findalldevs\n");
    fflush(stdout);

    // Call pcap_findalldevs
    int status = pcap_findalldevs(&alldevs, errbuf);

    // 5. Output: "Calling pcap_findalldevs success" or "Calling pcap_findalldevs fail"
    if (status == 0) {
        printf("Calling pcap_findalldevs success\n");
        fflush(stdout);

        // Optional: Print the names of the found devices to demonstrate success
        pcap_if_t *d;
        printf("Available network devices:\n");
        fflush(stdout);
        for (d = alldevs; d != NULL; d = d->next) {
            printf("  %s\n", d->name);
            fflush(stdout);
        }

        // Free the list of devices when done
        pcap_freealldevs(alldevs);
    } else {
        // 5. Output: "Calling pcap_findalldevs fail"
        printf("Calling pcap_findalldevs fail\n");
        fflush(stdout);

        // 3. If API call fails, return 123 and output error message
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        fflush(stderr);
        return EXIT_FAILURE_CODE;
    }

    return 0;
}

