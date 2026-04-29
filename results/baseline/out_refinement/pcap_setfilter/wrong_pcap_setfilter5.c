#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp; // This will be intentionally uninitialized before use
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

    // VIOLATION: We are intentionally skipping the pcap_compile step.
    // This means the `fp` structure is not initialized with a compiled BPF program.
    // The `pcap_compile` function is responsible for populating `fp`.
    // By not calling `pcap_compile`, `fp` remains in an uninitialized state.

    // Set the filter for the pcap session.
    // This call will likely fail or crash because `fp` is not a valid, compiled BPF program.
    int result = pcap_setfilter(handle, &fp);

    // Task2.5: Output success or failure messages.
    if (result == -1) {
        fprintf(stderr, "Calling pcap_setfilter fail: %s\n", pcap_geterr(handle));
        fflush(stdout);
        // In a real scenario, if pcap_compile had been called and failed, we would free it.
        // Since it wasn't called, there's nothing to free here in terms of compiled code.
        pcap_close(handle);
        return 123;
    } else {
        printf("Calling pcap_setfilter success\n");
        fflush(stdout);
    }

    // Clean up
    // If pcap_setfilter had succeeded (which it shouldn't in this violation),
    // we would free the compiled filter.
    // pcap_freecode(&fp); // This would be called if pcap_compile was successful.
    pcap_close(handle);

    return 0;
}

