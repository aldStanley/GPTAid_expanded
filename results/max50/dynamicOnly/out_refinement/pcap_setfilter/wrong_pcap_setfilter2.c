#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




// Function to handle errors and exit
void handle_error(const char* message, pcap_t* handle, struct bpf_program* compiled_filter) {
    if (handle) {
        fprintf(stderr, "%s: %s\n", message, pcap_geterr(handle));
        pcap_close(handle);
    } else {
        fprintf(stderr, "%s\n", message);
    }
    if (compiled_filter) {
        // In a real scenario, you'd also free compiled_filter->bf_insns if allocated dynamically
        // For this example, we assume pcap_compile handles its own memory if successful
    }
    exit(123);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    struct bpf_program compiled_filter;
    const char *interface = "eth0"; // Replace with a valid interface on your system
    const char *filter_expression = "tcp port 80"; // Example filter

    // 1. Open a live capture handle
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening interface %s: %s\n", interface, errbuf);
        printf("pcap_open_live failed.\n");
        fflush(stdout);
        return 123;
    }
    printf("pcap_open_live success.\n");
    fflush(stdout);

    // 2. Compile the filter expression
    // The file name requirement is for file read operations.
    // pcap_compile does not perform file reads in this context.
    if (pcap_compile(handle, &compiled_filter, filter_expression, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        printf("pcap_compile failed.\n");
        fflush(stdout);
        pcap_close(handle);
        return 123;
    }
    printf("pcap_compile success.\n");
    fflush(stdout);

    // 3. Call pcap_setfilter for the first time (valid call)
    printf("before first pcap_setfilter\n");
    fflush(stdout);

    int setfilter_result = pcap_setfilter(handle, &compiled_filter);

    // 4. Check the call status of the first pcap_setfilter
    if (setfilter_result == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        printf("Calling first pcap_setfilter fail\n");
        fflush(stdout);
        pcap_freecode(&compiled_filter); // Free compiled filter
        pcap_close(handle);
        return 123;
    } else {
        printf("Calling first pcap_setfilter success\n");
        fflush(stdout);
    }

    // VIOLATION: Close the handle
    printf("Closing the pcap handle.\n");
    fflush(stdout);
    pcap_close(handle);
    handle = NULL; // Set handle to NULL to indicate it's closed

    // 5. Attempt to call pcap_setfilter again on the closed handle
    printf("before second pcap_setfilter (on closed handle)\n");
    fflush(stdout);

    // This call will violate the rule because 'handle' is now NULL (or points to a closed resource)
    // The behavior of pcap_setfilter with a NULL handle is undefined, but typically leads to an error.
    // For the purpose of demonstrating the violation, we will proceed with the call.
    // In a real application, you would never do this.
    setfilter_result = pcap_setfilter(handle, &compiled_filter);

    // 6. Check the call status of the second pcap_setfilter
    // This check is here to show that the operation failed as expected due to the violation.
    if (setfilter_result == -1) {
        // We expect an error here because the handle is closed.
        // The error message might vary depending on the pcap implementation.
        fprintf(stderr, "Expected error setting filter on closed handle: %s\n", pcap_geterr(handle)); // Note: pcap_geterr might behave unexpectedly with a NULL handle
        printf("Calling second pcap_setfilter (on closed handle) failed as expected.\n");
        fflush(stdout);
    } else {
        // This branch should ideally not be reached if the violation is correctly demonstrated.
        printf("Unexpected success calling second pcap_setfilter (on closed handle).\n");
        fflush(stdout);
    }

    // Clean up
    // pcap_freecode should still be called if compiled_filter was successfully compiled.
    // If pcap_compile failed, this would have been handled earlier.
    pcap_freecode(&compiled_filter);

    printf("pcap_setfilter example finished.\n");
    fflush(stdout);

    return 0;
}

