#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int *tstamp_types = NULL;
    int count;

    // Open a dummy pcap device for demonstration purposes.
    // In a real scenario, you would open a specific device or a file.
    // Using "any" device here assumes it's available and writable for list_tstamp_types.
    handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("pcap_open_live succeeded.\n");
    fflush(stdout);

    printf("before pcap_list_tstamp_types\n");
    fflush(stdout);

    // Call pcap_list_tstamp_types
    count = pcap_list_tstamp_types(handle, &tstamp_types);

    if (count < 0) { // pcap_list_tstamp_types returns PCAP_ERROR on failure
        fprintf(stderr, "Calling pcap_list_tstamp_types fail: %s\n", errbuf);
        fflush(stdout);
        pcap_close(handle);
        return 123;
    } else {
        printf("Calling pcap_list_tstamp_types success\n");
        fflush(stdout);

        printf("Number of timestamp types supported: %d\n", count);
        fflush(stdout);

        if (tstamp_types != NULL) {
            printf("Supported timestamp types:\n");
            fflush(stdout);
            for (int i = 0; i < count; i++) {
                printf("  Type %d: %d\n", i + 1, tstamp_types[i]);
                fflush(stdout);
            }
            free(tstamp_types); // Free the allocated memory
        } else {
             // This case should ideally not happen if count is >= 0, but for completeness
             printf("tstamp_types pointer is NULL after successful call.\n");
             fflush(stdout);
        }
    }

    pcap_close(handle);
    printf("pcap_close succeeded.\n");
    fflush(stdout);

    return 0;
}

