#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    const char *filter_exp = "tcp port 80"; // Example filter expression

    // Task2.2: Non-interactive and no infinite loops.
    // Task2.3: Check call status of each API.

    // Open a network device for sniffing.
    // For simplicity, we'll try to open the first available device.
    // In a real-world scenario, you might want to list devices and let the user choose.
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        fflush(stdout);
        return 123;
    }
    printf("pcap_open_live successful.\n");
    fflush(stdout);

    // Compile the filter expression into a BPF program.
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        fflush(stdout);
        pcap_close(handle);
        return 123;
    }
    printf("pcap_compile successful.\n");
    fflush(stdout);

    // Task2.6: Add line before calling pcap_setfilter
    printf("before pcap_setfilter\n");
    fflush(stdout);

    // Task 1: Analyze the function code to find the invocation specification that the caller needs to follow correctly.
    // The function `pcap_setfilter` takes two arguments:
    // 1. `pcap_t *p`: A pointer to a pcap session handle. This handle must have been
    //    successfully opened using functions like `pcap_open_live` or `pcap_open_offline`.
    // 2. `struct bpf_program *fp`: A pointer to a compiled BPF program structure. This structure
    //    must have been successfully populated by a call to `pcap_compile`.
    // The caller must ensure that both `p` and `fp` are valid and have been initialized correctly.
    // `p` should point to an active pcap session, and `fp` should contain a compiled filter.

    // Set the filter for the pcap session.
    int result = pcap_setfilter(handle, &fp);

    // Task2.5: Output success or failure messages.
    if (result == -1) {
        fprintf(stderr, "Calling pcap_setfilter fail: %s\n", pcap_geterr(handle));
        fflush(stdout);
        pcap_freecode(&fp); // Free compiled filter on failure
        pcap_close(handle);
        return 123;
    } else {
        printf("Calling pcap_setfilter success\n");
        fflush(stdout);
    }

    // Clean up
    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}

