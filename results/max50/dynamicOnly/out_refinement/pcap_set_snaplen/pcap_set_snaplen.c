#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    int snaplen_value = 100; // Example snapshot length
    int result;

    // Open a dummy interface. "any" is a good choice for testing as it
    // tries to get a promiscuous mode on any interface.
    // If "any" fails, it might be due to permissions or system configuration.
    // For a robust test, consider falling back to a known interface if "any" fails,
    // but for this specific exercise, we focus on demonstrating pcap_set_snaplen.
    handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening dummy pcap handle with 'any': %s. Trying a common interface like 'eth0'...\n", errbuf);
        fflush(stdout);
        // Fallback to a common interface if "any" fails. This is for better
        // chances of execution in different environments.
        handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Error opening pcap handle with 'eth0': %s. Cannot proceed.\n", errbuf);
            fflush(stdout);
            return 123;
        }
    }
    printf("Successfully opened a pcap handle.\n");
    fflush(stdout);

    // Task2.6: Add the required printf before calling pcap_set_snaplen
    printf("before pcap_set_snaplen\n");
    fflush(stdout);

    // Task2.1 & 2.3: Call pcap_set_snaplen and check its status
    // The function `pcap_set_snaplen` itself checks if the handle is activated.
    // Since `pcap_open_live` does not activate the handle, this call should succeed.
    result = pcap_set_snaplen(handle, snaplen_value);

    // Task2.5: Output success or failure message
    if (result == 0) {
        printf("Calling pcap_set_snaplen success\n");
        fflush(stdout);
    } else {
        // Task2.3: Output error message
        fprintf(stderr, "Calling pcap_set_snaplen fail with code: %d. Error message: %s\n", result, pcap_geterr(handle));
        fflush(stdout);
        // Task2.3: Return error code
        pcap_close(handle); // Clean up the handle before exiting
        return 123;
    }

    // Task2.3: Check other API call status (e.g., pcap_close)
    // Although pcap_close doesn't return an error code in the same way,
    // we will ensure it's called and consider successful execution.
    pcap_close(handle);
    printf("Pcap handle closed successfully.\n");
    fflush(stdout);

    return 0;
}

