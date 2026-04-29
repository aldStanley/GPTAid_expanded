#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *device = NULL;

    printf("before pcap_lookupdev\n");
    fflush(stdout); // Ensure the output is immediately visible

    device = pcap_lookupdev(errbuf);

    if (device == NULL) {
        printf("Calling pcap_lookupdev fail\n");
        fflush(stdout);
        fprintf(stderr, "Error from pcap_lookupdev: %s\n", errbuf);
        fflush(stderr);
        return 123; // Indicate failure
    } else {
        printf("Calling pcap_lookupdev success\n");
        fflush(stdout);
        printf("Found network device: %s\n", device);
        fflush(stdout);
    }

    return 0; // Indicate success
}

