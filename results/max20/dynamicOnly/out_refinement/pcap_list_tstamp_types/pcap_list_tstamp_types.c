#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int *tstamp_types = NULL;
    int num_types;

    // Open a dummy pcap handle for demonstration purposes.
    // In a real application, you would open a specific interface or file.
    // We are opening a non-existent file to ensure we get the default behavior
    // where tstamp_type_count is 0.
    handle = pcap_open_offline("example.pcap", errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open dummy pcap handle: %s\n", errbuf);
        return 123;
    }
    printf("Dummy pcap handle opened successfully.\n");
    fflush(stdout);

    printf("before pcap_list_tstamp_types\n");
    fflush(stdout);

    num_types = pcap_list_tstamp_types(handle, &tstamp_types);

    if (num_types == PCAP_ERROR) {
        fprintf(stderr, "Calling pcap_list_tstamp_types fail\n");
        fflush(stderr);
        fprintf(stderr, "Error from pcap_list_tstamp_types: %s\n", errbuf);
        fflush(stderr);
        pcap_close(handle);
        return 123;
    } else {
        printf("Calling pcap_list_tstamp_types success\n");
        fflush(stdout);

        if (tstamp_types != NULL) {
            printf("Number of supported timestamp types: %d\n", num_types);
            fflush(stdout);
            for (int i = 0; i < num_types; ++i) {
                printf("Timestamp type %d: %d\n", i, tstamp_types[i]);
                fflush(stdout);
            }
            free(tstamp_types);
        } else {
            fprintf(stderr, "tstamp_types pointer is NULL unexpectedly.\n");
            fflush(stderr);
            pcap_close(handle);
            return 123;
        }
    }

    pcap_close(handle);
    printf("Pcap handle closed.\n");
    fflush(stdout);

    return 0;
}

