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
    // The original code allocated memory for fp and then compiled into it.
    // To violate the rule by passing an uninitialized struct bpf_program,
    // we will allocate memory but not compile into it, or even better,
    // we will pass a pointer to a struct bpf_program that has not been
    // successfully compiled.

    // VIOLATION: We will allocate memory for fp, but then we will
    // intentionally skip the pcap_compile step and pass this uninitialized
    // struct bpf_program to pcap_setfilter. This is consistent with the
    // violation example which passes a NULL pointer, implying an invalid
    // or uninitialized program.

    fp = (struct bpf_program *)malloc(sizeof(struct bpf_program));
    if (fp == NULL) {
        fprintf(stderr, "Memory allocation for bpf_program failed.\n");
        fflush(stdout);
        pcap_close(handle); // Clean up the handle
        return CUSTOM_EXIT_CODE;
    }

    // VIOLATION: We are skipping the pcap_compile call.
    // The 'fp' pointer now points to a struct bpf_program that has not been
    // populated with a valid compiled filter.

    printf("before pcap_setfilter (violating by passing uninitialized fp)\n");
    fflush(stdout);

    // 3. Call pcap_setfilter with an uninitialized fp
    int status = pcap_setfilter(handle, fp);

    if (status == 0) { // pcap_setfilter returns 0 on success
        // This branch should ideally not be reached if the violation
        // causes an error, but we include it for completeness.
        printf("Calling pcap_setfilter success (unexpected for this violation)\n");
        fflush(stdout);
    } else {
        // This is the expected outcome of the violation.
        fprintf(stderr, "Calling pcap_setfilter fail as expected: %s\n", pcap_geterr(handle));
        fflush(stdout);
        pcap_close(handle);
        // In a real scenario, if pcap_compile had succeeded, we would call pcap_freecode.
        // Since it didn't, and we are intentionally violating, we might not call it.
        // However, to be safe and clean up allocated memory, we still free fp.
        free(fp); // Free allocated memory
        return CUSTOM_EXIT_CODE;
    }

    // 4. Clean up
    // If pcap_setfilter had succeeded, we would call pcap_freecode(fp) here.
    // Since we are violating and expect failure, this cleanup might not be
    // reached or might be handled differently. For this specific violation,
    // we've already handled cleanup in the error path.
    // If the violation *didn't* cause an error (which is unlikely),
    // we would need to free the compiled code.
    // For this example, we'll assume the error path is taken and cleanup is done there.
    // If we were to reach here, it would imply the violation didn't cause an error,
    // which is not the intended outcome for demonstrating the rule violation.

    // To ensure cleanup even if the error path wasn't taken (though it should be),
    // we'll add a conditional free.
    if (fp != NULL) {
        // pcap_freecode(fp); // This would be called if pcap_compile succeeded.
        free(fp); // Free the allocated struct bpf_program
    }
    pcap_close(handle); // Close the capture handle
    printf("Cleanup complete.\n");
    fflush(stdout);

    return 0; // Success (though the violation is expected to lead to failure)
}

