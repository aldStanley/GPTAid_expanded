#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int major_version;

    // Open a live capture device. For this example, we'll try to open the first available one.
    // In a real application, you would typically list available devices and let the user choose.
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("pcap_open_live success\n");
    fflush(stdout);

    // pcap_major_version requires the pcap handle to be activated.
    // pcap_open_live() activates the handle. So, we can directly call pcap_major_version.

    printf("before pcap_major_version\n");
    fflush(stdout);

    major_version = pcap_major_version(handle);

    if (major_version == PCAP_ERROR_NOT_ACTIVATED) {
        printf("Calling pcap_major_version fail\n");
        fflush(stdout);
        fprintf(stderr, "Error: pcap handle is not activated.\n");
        fflush(stdout);
        pcap_close(handle);
        return 123;
    } else if (major_version < 0) {
        // pcap_major_version itself can return negative values for other errors,
        // though the provided implementation only returns PCAP_ERROR_NOT_ACTIVATED.
        // It's good practice to handle potential negative return values.
        printf("Calling pcap_major_version fail\n");
        fflush(stdout);
        fprintf(stderr, "An unexpected error occurred while getting major version: %d\n", major_version);
        fflush(stdout);
        pcap_close(handle);
        return 123;
    } else {
        printf("Calling pcap_major_version success\n");
        fflush(stdout);
        printf("Major version of libpcap: %d\n", major_version);
        fflush(stdout);
    }

    // Close the pcap handle
    pcap_close(handle);
    printf("pcap_close success\n");
    fflush(stdout);

    return 0;
}

