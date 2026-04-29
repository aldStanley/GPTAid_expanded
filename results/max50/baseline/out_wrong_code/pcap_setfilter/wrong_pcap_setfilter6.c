#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




// Define a custom error code for pcap_setfilter failure
#define PCAP_SETFILTER_ERROR_CODE 123

int main() {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp; // To store compiled filter program
    const char *filter_exp;
    const char *interface = "eth0"; // Replace with a valid interface on your system

    // 1. Open a live capture handle
    printf("Attempting to open pcap handle on interface %s\n", interface);
    fflush(stdout);

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", interface, errbuf);
        fflush(stderr);
        return 123;
    }
    printf("Successfully opened pcap handle.\n");
    fflush(stdout);

    // 2. Compile the filter expression
    filter_exp = "tcp";
    printf("Compiling filter expression: \"%s\"\n", filter_exp);
    fflush(stdout);

    // *** VIOLATION START ***
    // The violation example shows a struct bpf_program declared but not compiled.
    // The provided "run result" indicates that pcap_setfilter fails with "BPF program is not valid"
    // and then AddressSanitizer reports a "bad-free" on pcap_freecode.
    // This suggests that even though pcap_setfilter fails, the program proceeds to call pcap_freecode
    // on an uninitialized struct, which is problematic.
    // To strictly follow the violation example and address the ASan error, we will:
    // 1. Declare `fp` but *not* call `pcap_compile`.
    // 2. Ensure that `pcap_freecode` is *only* called if `pcap_compile` was successful.
    //    Since we are intentionally skipping `pcap_compile`, `pcap_freecode` should not be called.
    //    However, the original "right code" *does* call `pcap_freecode` in the cleanup section.
    //    To make the violation consistent with the example and the ASan error, we will remove
    //    the `pcap_freecode` call from the cleanup if `pcap_compile` was not performed.
    //    But the prompt asks to *violate* the rule, and the example shows `pcap_setfilter` being called
    //    with an uninitialized `fp`. The ASan error is a consequence of the subsequent `pcap_freecode`.
    //    Therefore, to match the violation example's *intent* of passing an uninitialized `fp` to `pcap_setfilter`,
    //    we will keep the structure of the original "right code" but omit the `pcap_compile` call.
    //    The ASan error in the run result is a consequence of the *cleanup* in the original "right code"
    //    attempting to free an uninitialized `fp`. To *violate* the rule as per the example,
    //    we must pass the uninitialized `fp` to `pcap_setfilter`. The subsequent cleanup is a separate issue.
    //    The most direct violation of the rule "Ensure that the struct bpf_program (fp) has been properly initialized and compiled... before being passed to pcap_setfilter"
    //    is to simply *not* compile it before passing it.

    // We will declare fp, but skip the pcap_compile call.
    // The original code had:
    // if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) { ... }
    // printf("Filter compiled successfully.\n");
    // We are removing this block to create the violation.

    // *** VIOLATION END ***

    // 3. Set the compiled filter
    printf("before pcap_setfilter\n");
    fflush(stdout);

    // This call to pcap_setfilter will now receive an uninitialized 'fp'.
    // This is the core violation of the rule.
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Calling pcap_setfilter fail: %s\n", pcap_geterr(handle));
        fflush(stderr);
        // The original "right code" called pcap_freecode(&fp) here.
        // Since fp was never compiled, pcap_freecode might be problematic.
        // The ASan error in the run result occurred because pcap_freecode was called
        // in the cleanup section *after* pcap_setfilter failed.
        // To match the violation example's structure and the ASan error's context,
        // we will *not* call pcap_freecode here, but we will ensure it's not called
        // in the cleanup either, as fp was never properly initialized.
        // The violation is in passing the uninitialized fp to pcap_setfilter.
        pcap_close(handle); // Close the pcap handle
        return PCAP_SETFILTER_ERROR_CODE; // Use the specific error code
    }

    printf("Calling pcap_setfilter success\n");
    fflush(stdout);

    // 4. Cleanup
    // In the original "right code", pcap_freecode(&fp) was called here.
    // Since we intentionally skipped pcap_compile, 'fp' is uninitialized.
    // Calling pcap_freecode on an uninitialized struct leads to the ASan error.
    // To *violate* the rule as per the example, we pass an uninitialized struct.
    // The ASan error is a consequence of the cleanup.
    // To make the code *runnable* without ASan errors while still violating the rule
    // (by passing an uninitialized struct to pcap_setfilter), we must avoid calling
    // pcap_freecode on an uninitialized struct.
    // Therefore, we will *not* call pcap_freecode here, as it was never compiled.
    // The violation is the call to pcap_setfilter with an uninitialized fp.
    pcap_close(handle); // Close the pcap handle
    printf("Pcap handle closed.\n");
    fflush(stdout);

    return 0; // Success
}

