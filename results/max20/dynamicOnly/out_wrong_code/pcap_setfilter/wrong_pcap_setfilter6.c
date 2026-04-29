#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




// Define a custom error code for this program
#define CUSTOM_ERROR_CODE 123

int main() {
    pcap_t *handle; // Packet capture handle
    char errbuf[PCAP_ERRBUF_SIZE]; // Error buffer for libpcap
    struct bpf_program fp; // Compiled filter program
    const char *filter_exp = "tcp port 80"; // Example filter expression
    // Using a loopback interface for common availability and less disruptive testing.
    // You might need to change this to a valid interface on your system, e.g., "eth0", "wlan0".
    // If you are testing with a file, you would use pcap_open_offline.
    const char *interface = "lo";

    // 1. Open a network interface for live capture
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        fflush(stdout);
        return CUSTOM_ERROR_CODE;
    }
    printf("Successfully opened network device %s.\n", interface);
    fflush(stdout);

    // 2. VIOLATION: Do NOT compile the filter expression.
    // The `pcap_compile` call is intentionally omitted here.
    // This will result in `fp` being an uninitialized `struct bpf_program`.
    //
    // Original code had:
    // if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
    //     fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    //     fflush(stdout);
    //     pcap_close(handle);
    //     return CUSTOM_ERROR_CODE;
    // }
    // printf("Successfully compiled filter expression '%s'.\n", filter_exp);
    // fflush(stdout);

    printf("Skipping filter compilation to violate the rule.\n");
    fflush(stdout);

    // 3. Call pcap_setfilter with an uninitialized bpf_program
    printf("before pcap_setfilter (expecting failure)\n");
    fflush(stdout);

    // This call is expected to fail because `fp` is not properly initialized.
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Calling pcap_setfilter failed as expected: %s\n", pcap_geterr(handle));
        fflush(stdout);
        // No need to call pcap_freecode(&fp) as it was never compiled.
        pcap_close(handle); // Close the capture handle
        return CUSTOM_ERROR_CODE;
    }

    // This part of the code should ideally not be reached if the violation
    // causes pcap_setfilter to return an error.
    printf("Calling pcap_setfilter unexpectedly succeeded (this is not the intended violation behavior).\n");
    fflush(stdout);

    // 4. Cleanup
    // If pcap_setfilter somehow succeeded, we would free the code.
    // However, in the intended violation scenario, this line won't be reached.
    // pcap_freecode(&fp);
    pcap_close(handle); // Close the capture handle
    printf("Cleaned up resources.\n");
    fflush(stdout);

    return 0; // Indicate successful execution (though the violation is expected to cause an error)
}

