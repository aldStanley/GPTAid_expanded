#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int promisc_value = 1; // Set to 1 for promiscuous mode, 0 for non-promiscuous

    // Open a network device for sniffing.
    // We'll use the first available device for simplicity.
    char *device = pcap_lookupdev(errbuf);
    if (device == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }

    handle = pcap_open_live(device, BUFSIZ, 0, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        fflush(stdout);
        return 123;
    }

    // Task2: Generate a complete code that calls the function in Linux.
    // 1. The code is required to be compilable and follow the invocation specification of this function.
    //    The invocation specification for pcap_set_promisc is:
    //    - The pcap_t *p parameter must be a valid, non-activated pcap handle.
    //    - The int promisc parameter should be 1 for promiscuous mode or 0 for non-promiscuous mode.
    //    The function itself checks if the handle is activated and returns PCAP_ERROR_ACTIVATED if it is.
    // 2. This code needs to be non-interactive and no infinite loops.
    // 3. The code needs to check the call status of each API after the API returns.
    //    If API call fails, return 123 and output error message to infer the cause of the error.
    //    Every printf needs to be different.
    // 4. After any printf, please flush the stdout.
    // 5. Output: "Calling pcap_set_promisc success" after calling pcap_set_promisc successfully;
    //    Output: "Calling pcap_set_promisc fail" after the call to pcap_set_promisc has failed.
    // 6. Add line: printf("before pcap_set_promisc\n") before calling pcap_set_promisc.
    //    Make sure that there are no other function calls between this output and the calling to pcap_set_promisc.
    // 7. If there are some file read operations in the code, the file name should be example.xxx.
    //    (No file read operations in this code.)

    printf("Attempting to set promiscuous mode.\n");
    fflush(stdout);

    // Before calling pcap_set_promisc
    printf("before pcap_set_promisc\n");
    fflush(stdout);

    // Calling the target function
    int set_promisc_result = pcap_set_promisc(handle, promisc_value);

    if (set_promisc_result == 0) {
        printf("Calling pcap_set_promisc success\n");
        fflush(stdout);
    } else {
        fprintf(stderr, "Calling pcap_set_promisc fail: %d\n", set_promisc_result);
        fflush(stdout);
        if (set_promisc_result == PCAP_ERROR_ACTIVATED) {
            fprintf(stderr, "Error: The pcap handle is already activated.\n");
            fflush(stdout);
        } else {
            fprintf(stderr, "An unknown error occurred while setting promiscuous mode.\n");
            fflush(stdout);
        }
        pcap_close(handle);
        return 123;
    }

    // Clean up
    pcap_close(handle);
    printf("Pcap handle closed.\n");
    fflush(stdout);

    return 0;
}

