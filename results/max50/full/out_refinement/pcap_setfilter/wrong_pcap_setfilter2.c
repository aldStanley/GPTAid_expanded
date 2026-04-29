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
    pcap_t *handle = NULL;
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
    printf("before pcap_setfilter (first call)\n");
    fflush(stdout);

    if (pcap_setfilter(handle, &fp) == -1) {
        // pcap_setfilter returns -1 on failure
        fprintf(stderr, "Calling pcap_setfilter fail (first call): %s\n", pcap_geterr(handle));
        fflush(stdout);
        // Cleanup before exiting
        pcap_freecode(&fp);
        pcap_close(handle);
        return 123;
    }

    printf("Calling pcap_setfilter success (first call)\n");
    fflush(stdout);

    // VIOLATION: Close the handle and then attempt to use it again.
    printf("Closing the pcap handle.\n");
    fflush(stdout);
    pcap_close(handle);
    handle = NULL; // Set handle to NULL to indicate it's closed

    // Attempt to set the filter again on a closed handle
    printf("Attempting to call pcap_setfilter on a closed handle.\n");
    fflush(stdout);

    // This call is expected to fail or have undefined behavior,
    // but it demonstrates the violation of using a closed handle.
    // We are not checking the return value here to ensure the violation occurs.
    // In a real scenario, you would check for errors.
    pcap_setfilter(handle, &fp); // VIOLATION: Using a closed handle

    // The following lines will likely not be reached or will exhibit
    // unexpected behavior due to the violation.
    printf("This message might not be printed if the violation caused a crash or exit.\n");
    fflush(stdout);

    // 5. Cleanup (this part might not be reached if the violation causes termination)
    // pcap_freecode(&fp); // fp is still valid and needs to be freed
    // pcap_close(handle); // handle is already closed and set to NULL

    // Free the compiled filter program
    pcap_freecode(&fp);

    printf("Cleanup complete (if reached).\n");
    fflush(stdout);

    return 0;
}

