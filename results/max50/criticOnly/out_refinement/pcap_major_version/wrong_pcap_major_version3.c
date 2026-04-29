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

    // --- VIOLATION START ---
    // To violate the rule, we will call pcap_major_version *before* the handle is activated.
    // pcap_open_live() activates the handle. By calling pcap_major_version *after*
    // pcap_open_live() but *before* any packet capturing or other operations that
    // might implicitly activate it (though pcap_open_live is usually sufficient),
    // we are demonstrating a scenario where the handle might not be considered fully "activated"
    // in a way that pcap_major_version expects, or more directly, we can simulate
    // an unactivated handle.

    // The most direct way to violate the rule as per the example is to simulate
    // an unactivated handle. We'll do this by closing the handle *before* calling
    // pcap_major_version. This makes the handle effectively unactivated.

    printf("Closing the handle before calling pcap_major_version to violate the rule.\n");
    fflush(stdout);
    pcap_close(handle); // Close the handle, making it unactivated.

    // Now, call pcap_major_version on the closed (unactivated) handle.
    printf("before pcap_major_version on unactivated handle\n");
    fflush(stdout);

    // This call is expected to fail because the handle is no longer activated.
    major_version = pcap_major_version(handle);

    if (major_version == PCAP_ERROR_NOT_ACTIVATED) {
        printf("Calling pcap_major_version fail as expected (handle is not activated).\n");
        fflush(stdout);
        fprintf(stderr, "Error: pcap handle is not activated.\n");
        fflush(stdout);
        // We don't need to close the handle again as it's already closed.
        return 0; // Exit successfully as we've demonstrated the violation.
    } else if (major_version < 0) {
        printf("Calling pcap_major_version fail with an unexpected error.\n");
        fflush(stdout);
        fprintf(stderr, "An unexpected error occurred while getting major version: %d\n", major_version);
        fflush(stdout);
        return 123;
    } else {
        printf("Calling pcap_major_version success unexpectedly.\n");
        fflush(stdout);
        printf("Major version of libpcap: %d\n", major_version);
        fflush(stdout);
        // This case should not happen if the violation is successful.
        return 123;
    }
    // --- VIOLATION END ---

    // The following lines would be part of the "right code" but are unreachable
    // in this violation example because we return early.
    // printf("pcap_close success\n");
    // fflush(stdout);

    // return 0;
}

