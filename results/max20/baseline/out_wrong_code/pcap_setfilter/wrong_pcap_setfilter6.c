#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp; // Declared but will not be compiled
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

    // 2. Compile the filter expression (THIS STEP IS INTENTIONALLY SKIPPED TO VIOLATE THE RULE)
    // if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1) {
    //     fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    //     fflush(stdout);
    //     pcap_close(handle);
    //     return 123;
    // }
    // printf("pcap_compile success\n");
    // fflush(stdout);

    // Task 6: Add the specified printf before pcap_setfilter
    printf("before pcap_setfilter\n");
    fflush(stdout);

    // 3. Apply the filter
    // The pcap_setfilter function requires a valid pcap_t handle and a compiled bpf_program.
    // The bpf_program must be successfully compiled using pcap_compile.
    // VIOLATION: Passing an uninitialized struct bpf_program 'fp' to pcap_setfilter.
    if (pcap_setfilter(handle, &fp) == -1) {
        // Task 5: Output "Calling pcap_setfilter fail"
        printf("Calling pcap_setfilter fail\n");
        fflush(stdout);
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        fflush(stdout);
        // pcap_freecode(&fp); // This would be called if pcap_compile was successful
        pcap_close(handle);
        return 123;
    }

    // Task 5: Output "Calling pcap_setfilter success"
    printf("Calling pcap_setfilter success\n");
    fflush(stdout);

    // Clean up
    // pcap_freecode(&fp); // This would be called if pcap_compile was successful
    pcap_close(handle);
    printf("Cleanup complete\n");
    fflush(stdout);

    return 0;
}

