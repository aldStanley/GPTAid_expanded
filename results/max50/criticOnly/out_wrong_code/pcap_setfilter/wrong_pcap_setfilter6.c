#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




// Note: The definition of pcap_setfilter is provided by libpcap.
// We will not redefine it here.

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    struct bpf_program fp; // Declared but will not be compiled
    int result;

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

    // --- VIOLATION ---
    // The following code VIOLATES the rule by passing an uninitialized
    // struct bpf_program to pcap_setfilter. The `fp` variable is declared
    // but `pcap_compile` is NOT called to initialize and compile the filter.
    // This is consistent with the provided violation example.

    // Compile the filter expression.
    // We will use a simple filter: "tcp port 80"
    const char *filter_exp = "tcp port 80";
    printf("Skipping filter compilation to intentionally violate the rule.\n");
    fflush(stdout);

    // --- Calling pcap_setfilter ---
    printf("before pcap_setfilter\n");
    fflush(stdout);

    // The `fp` variable is not initialized by pcap_compile.
    result = pcap_setfilter(handle, &fp);

    if (result == -1) { // pcap_setfilter returns -1 on error
        printf("Calling pcap_setfilter fail\n");
        fflush(stdout);
        // Task2.3: Output error message for failure
        fprintf(stderr, "pcap_setfilter failed: Error setting the filter on the capture handle. The error message from libpcap is: %s\n", pcap_geterr(handle));
        fflush(stderr);
        // Clean up resources before exiting
        // Note: pcap_freecode(&fp) would be called here if fp was compiled.
        // Since it wasn't, we skip it to maintain consistency with the violation.
        pcap_close(handle);
        return 123; // Task2.3: Return 123 on failure
    } else {
        printf("Calling pcap_setfilter success\n");
        fflush(stdout);
    }

    // --- Cleanup ---
    // Free the compiled filter program
    // This line would cause a crash or undefined behavior if `fp` was not
    // properly initialized by pcap_compile. We will skip it to avoid
    // immediate crashes and focus on the `pcap_setfilter` violation.
    // pcap_freecode(&fp);
    // printf("Freed compiled filter code.\n");
    // fflush(stdout);

    // Close the pcap handle
    pcap_close(handle);
    printf("Closed pcap handle.\n");
    fflush(stdout);

    return 0;
}

