#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




// Function to print error messages and exit
void print_error_and_exit(const char *message, pcap_t *handle, const char *api_name) {
    fprintf(stderr, "%s: %s - %s\n", message, api_name, pcap_geterr(handle));
    fflush(stdout);
    if (handle) {
        pcap_close(handle);
    }
    exit(123);
}

// Helper to print error messages for pcap_open_live
void print_pcap_open_error(const char *message, const char *device, char *errbuf) {
    fprintf(stderr, "%s: %s - %s\n", message, device, errbuf);
    fflush(stdout);
    exit(123);
}

// Helper to print error messages for pcap_compile
void print_pcap_compile_error(const char *message, const char *filter_exp, pcap_t *handle) {
    fprintf(stderr, "%s: %s - %s\n", message, filter_exp, pcap_geterr(handle));
    fflush(stdout);
    if (handle) {
        pcap_close(handle);
    }
    exit(123);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL; // Initialize handle to NULL
    struct bpf_program fp;
    const char *device = NULL;
    const char *filter_exp = "tcp port 80"; // Example filter

    // 1. Find a network device (non-interactive, choose the first available)
    device = pcap_lookupdev(errbuf);
    if (device == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("Using network device: %s\n", device);
    fflush(stdout);

    // 2. Open a live capture session
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        print_pcap_open_error("Couldn't open device", device, errbuf);
    }
    printf("Successfully opened device for live capture.\n");
    fflush(stdout);

    // 3. Compile the filter expression
    if (pcap_compile(handle, &fp, filter_exp, 1, 0) == -1) {
        print_pcap_compile_error("Couldn't parse filter", filter_exp, handle);
    }
    printf("Successfully compiled filter expression: %s\n", filter_exp);
    fflush(stdout);

    // 4. Set the filter
    printf("before pcap_setfilter\n");
    fflush(stdout);

    // VIOLATION: We are intentionally passing a NULL pcap_t handle to pcap_setfilter.
    // This violates the rule that the pcap_t handle must be a valid and initialized capture descriptor.
    if (pcap_setfilter(NULL, &fp) == -1) {
        // pcap_setfilter returns -1 on failure.
        // When passing NULL, pcap_geterr might return an empty string or a generic error.
        // The exact behavior can vary slightly between libpcap versions.
        fprintf(stderr, "Calling pcap_setfilter with NULL handle failed as expected.\n");
        fflush(stdout);
        // Cleanup before exiting. Note that 'handle' is still valid here,
        // but we are demonstrating the violation of passing NULL to pcap_setfilter.
        pcap_freecode(&fp);
        pcap_close(handle); // Close the valid handle
        return 123;
    }

    // This part will not be reached due to the intentional failure above.
    printf("Calling pcap_setfilter success (this should not be printed)\n");
    fflush(stdout);

    // 5. Cleanup
    pcap_freecode(&fp);
    pcap_close(handle);

    printf("Cleanup complete.\n");
    fflush(stdout);

    return 0;
}

