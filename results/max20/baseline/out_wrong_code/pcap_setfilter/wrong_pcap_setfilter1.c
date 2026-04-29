#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    const char *filter_exp = "tcp port 80"; // Example filter expression
    const char *interface = "eth0"; // Replace with a valid network interface on your system

    // 1. Open a network device
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        fflush(stdout);
        return 123;
    }
    printf("pcap_open_live success\n");
    fflush(stdout);

    // 2. Compile the filter expression
    if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        fflush(stdout);
        pcap_close(handle);
        return 123;
    }
    printf("pcap_compile success\n");
    fflush(stdout);

    // Task 6: Add the specified printf before pcap_setfilter
    printf("before pcap_setfilter\n");
    fflush(stdout);

    // 3. Apply the filter
    // The pcap_setfilter function requires a valid pcap_t handle and a compiled bpf_program.
    // The bpf_program must be successfully compiled using pcap_compile.

    // VIOLATION: We are intentionally passing a NULL pcap_t handle to pcap_setfilter.
    // This violates the rule that the pcap_t handle must be a valid and initialized capture descriptor.
    pcap_t *invalid_handle = NULL;
    if (pcap_setfilter(invalid_handle, &fp) == -1) {
        // Task 5: Output "Calling pcap_setfilter fail"
        printf("Calling pcap_setfilter fail\n");
        fflush(stdout);
        // Note: pcap_geterr(handle) would fail here because handle is NULL.
        // We can't get a meaningful error message from pcap_geterr in this specific violation.
        // The pcap_setfilter function itself will likely return an error code.
        fprintf(stderr, "pcap_setfilter called with a NULL handle.\n");
        fflush(stdout);
        pcap_freecode(&fp); // Free the compiled filter
        // pcap_close(handle); // We should not close a NULL handle, but the original handle is still valid.
        // However, to demonstrate the violation clearly, we'll proceed as if the original handle was never intended to be used after this point.
        // In a real scenario, you'd likely have already exited or handled the error before reaching this point.
        // For this exercise, we'll close the original valid handle if it was opened.
        if (handle) {
            pcap_close(handle);
        }
        return 123;
    }

    // This part will not be reached due to the violation above.
    // Task 5: Output "Calling pcap_setfilter success"
    printf("Calling pcap_setfilter success\n");
    fflush(stdout);

    // Clean up
    pcap_freecode(&fp);
    pcap_close(handle);
    printf("Cleanup complete\n");
    fflush(stdout);

    return 0;
}

