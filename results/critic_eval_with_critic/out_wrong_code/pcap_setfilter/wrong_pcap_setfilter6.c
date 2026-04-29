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
    // VIOLATION: We are allocating memory for fp, but we are NOT compiling it.
    // The violation example shows declaring a struct bpf_program and passing its address
    // without compilation. To be consistent with that, we will declare fp as a local
    // variable and pass its address without calling pcap_compile.
    struct bpf_program compiled_filter; // Declared but not compiled

    // 3. Call pcap_setfilter
    printf("before pcap_setfilter (violating rule)\n");
    fflush(stdout);

    // VIOLATION: Passing an uninitialized and uncompiled struct bpf_program.
    // The pcap_setfilter function expects a pointer to a compiled filter program.
    // By passing the address of 'compiled_filter' without calling pcap_compile,
    // we are violating the rule.
    int status = pcap_setfilter(handle, &compiled_filter);

    if (status == 0) { // pcap_setfilter returns 0 on success
        printf("Calling pcap_setfilter success (unexpected in this violation)\n");
        fflush(stdout);
    } else {
        fprintf(stderr, "Calling pcap_setfilter fail: %s\n", pcap_geterr(handle));
        fflush(stdout);
        pcap_close(handle);
        // No need to free compiled_filter as it was not dynamically allocated
        return CUSTOM_EXIT_CODE;
    }

    // 4. Clean up
    // In a real scenario, if pcap_compile were successful, we would call pcap_freecode.
    // Since we are violating the rule by not compiling, we don't need to call it.
    pcap_close(handle); // Close the capture handle
    printf("Cleanup complete.\n");
    fflush(stdout);

    return 0; // Success
}

