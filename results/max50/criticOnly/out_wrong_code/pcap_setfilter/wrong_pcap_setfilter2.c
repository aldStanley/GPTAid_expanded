#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




// Note: The definition of pcap_setfilter is provided by libpcap.
// We will not redefine it here.

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    struct bpf_program fp;
    int result;

    // Task2.1: The code needs to be compilable and follow the invocation specification.
    // The invocation specification for pcap_setfilter is:
    // 1. `pcap_t *p`: A valid pointer to a pcap handle obtained from `pcap_open_live` or `pcap_open_offline`.
    // 2. `struct bpf_program *fp`: A pointer to a compiled BPF program. This program must be compiled using `pcap_compile` or `pcap_compile_nopcap`.

    // Task2.2: Non-interactive and no infinite loops.
    // Task2.3: Check the call status of each API.
    // Task2.4: Flush stdout after each printf.
    // Task2.5: Output success/failure messages for pcap_setfilter.
    // Task2.6: Add specific printf before pcap_setfilter.
    // Task2.7: File name for read operations. (Not applicable here as we are simulating a pcap handle and filter compilation).

    // For this example, we need to obtain a valid pcap handle and compile a filter.
    // We'll use pcap_open_live to get a handle. For simplicity, we'll try to open
    // the loopback interface. If it's not available, we'll try to find another.
    // A real application might have more robust interface selection.

    printf("Attempting to find a network interface...\n");
    fflush(stdout);

    char *dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        fflush(stderr);
        return 123; // Task2.3: Return 123 on failure
    }
    printf("Found network interface: %s\n", dev);
    fflush(stdout);

    // Open the device for sniffing.
    // We set a snapshot length and a timeout.
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        fflush(stderr);
        return 123; // Task2.3: Return 123 on failure
    }
    printf("Successfully opened network interface for sniffing.\n");
    fflush(stdout);

    // Compile the filter expression.
    // We will use a simple filter: "tcp port 80"
    const char *filter_exp = "tcp port 80";
    printf("Compiling filter expression: \"%s\"\n", filter_exp);
    fflush(stdout);

    if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        fflush(stderr);
        pcap_close(handle); // Clean up the handle
        return 123; // Task2.3: Return 123 on failure
    }
    printf("Filter compiled successfully.\n");
    fflush(stdout);

    // --- Calling pcap_setfilter ---
    printf("before pcap_setfilter\n");
    fflush(stdout);

    result = pcap_setfilter(handle, &fp);

    if (result == -1) { // pcap_setfilter returns -1 on error
        printf("Calling pcap_setfilter fail\n");
        fflush(stdout);
        // Task2.3: Output error message for failure
        fprintf(stderr, "pcap_setfilter failed: Error setting the filter on the capture handle. The error message from libpcap is: %s\n", pcap_geterr(handle));
        fflush(stderr);
        // Clean up resources before exiting
        pcap_freecode(&fp);
        pcap_close(handle);
        return 123; // Task2.3: Return 123 on failure
    } else {
        printf("Calling pcap_setfilter success\n");
        fflush(stdout);
    }

    // --- VIOLATION: Using a pcap_t handle after closing it ---
    printf("Closing pcap handle.\n");
    fflush(stdout);
    pcap_close(handle); // Close the handle

    // Now, attempt to set the filter again on the closed handle.
    // This violates the rule: "The `pcap_t` handle (`p`) must not be used after it has been closed by `pcap_close`."
    printf("Attempting to call pcap_setfilter again after closing the handle.\n");
    fflush(stdout);

    // The `handle` pointer is now dangling. Calling `pcap_setfilter` with it is undefined behavior and likely to cause a crash or incorrect results.
    result = pcap_setfilter(handle, &fp);

    if (result == -1) {
        printf("Calling pcap_setfilter again after closing the handle failed as expected.\n");
        fflush(stdout);
        // Task2.3: Output error message for failure
        // Note: pcap_geterr might behave unexpectedly or crash after pcap_close.
        // For demonstration, we'll print a generic message.
        fprintf(stderr, "pcap_setfilter failed after closing handle. This is expected behavior for a dangling pointer.\n");
        fflush(stderr);
    } else {
        // This branch should ideally not be reached if the violation is effective.
        printf("Calling pcap_setfilter again after closing the handle unexpectedly succeeded.\n");
        fflush(stdout);
    }
    // --- END OF VIOLATION ---


    // --- Cleanup ---
    // Free the compiled filter program
    pcap_freecode(&fp);
    printf("Freed compiled filter code.\n");
    fflush(stdout);

    // The handle was already closed above. Calling pcap_close again is generally safe
    // as it's often a no-op after the first close, but it's good practice to avoid.
    // For this specific violation demonstration, we've already closed it.

    return 0;
}

