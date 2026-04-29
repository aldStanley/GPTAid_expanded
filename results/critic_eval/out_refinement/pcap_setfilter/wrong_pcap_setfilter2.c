#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




// Define a specific error code for our custom exit
#define CUSTOM_EXIT_CODE 123

int main() {
    pcap_t *handle;          // Packet capture handle
    struct bpf_program *fp;  // Compiled filter program
    char errbuf[PCAP_ERRBUF_SIZE]; // Error buffer for pcap functions
    char *interface = "eth0"; // Example interface, change if needed
    char *filter_exp = "tcp port 80"; // Example filter expression

    // 1. Initialize pcap_t handle
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening interface %s: %s\n", interface, errbuf);
        fflush(stdout);
        return CUSTOM_EXIT_CODE;
    }
    printf("Successfully opened interface.\n");
    fflush(stdout);

    // 2. Compile the filter expression
    fp = (struct bpf_program *)malloc(sizeof(struct bpf_program));
    if (fp == NULL) {
        fprintf(stderr, "Memory allocation for bpf_program failed.\n");
        fflush(stdout);
        pcap_close(handle); // Clean up the handle
        return CUSTOM_EXIT_CODE;
    }

    // Using "tcp port 80" as a sample filter.
    // In a real scenario, you might want to read this from a file or configuration.
    if (pcap_compile(handle, fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        fflush(stdout);
        pcap_close(handle);
        free(fp); // Free allocated memory
        return CUSTOM_EXIT_CODE;
    }
    printf("Successfully compiled filter expression.\n");
    fflush(stdout);

    // 3. Call pcap_setfilter
    printf("before pcap_setfilter\n");
    fflush(stdout);

    int status = pcap_setfilter(handle, fp);

    if (status == 0) { // pcap_setfilter returns 0 on success
        printf("Calling pcap_setfilter success\n");
        fflush(stdout);
    } else {
        fprintf(stderr, "Calling pcap_setfilter fail: %s\n", pcap_geterr(handle));
        fflush(stdout);
        pcap_close(handle);
        pcap_freecode(fp); // Free the compiled filter program
        free(fp); // Free the allocated struct bpf_program
        return CUSTOM_EXIT_CODE;
    }

    // --- VIOLATION START ---
    // Close the handle
    pcap_close(handle);
    printf("pcap_close called.\n");
    fflush(stdout);

    // Attempt to set the filter again on the closed handle
    printf("Attempting to call pcap_setfilter after pcap_close...\n");
    fflush(stdout);
    status = pcap_setfilter(handle, fp); // VIOLATION: Using handle after it's closed

    if (status == 0) {
        // This part should ideally not be reached if the violation is detected
        printf("Unexpected success calling pcap_setfilter after pcap_close.\n");
        fflush(stdout);
    } else {
        fprintf(stderr, "Calling pcap_setfilter after pcap_close failed as expected: %s\n", pcap_geterr(handle));
        fflush(stdout);
    }
    // --- VIOLATION END ---


    // 4. Clean up
    // Note: pcap_freecode(fp) and free(fp) are still called for good practice,
    // even though the program might have exited due to the violation.
    // In a real scenario, the program would likely terminate before reaching here
    // after the violation.
    pcap_freecode(fp); // Free the compiled filter program
    free(fp); // Free the allocated struct bpf_program
    // pcap_close(handle); // This is already called above to cause the violation
    printf("Cleanup complete.\n");
    fflush(stdout);

    return 0; // Success (if the violation didn't cause an early exit)
}

