#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int snaplen_value = 96; // Example snapshot length

    // Open a dummy device for demonstration purposes.
    // In a real scenario, you'd open a valid network interface.
    // For simplicity and to avoid requiring a live interface for compilation,
    // we'll attempt to open a loopback interface which is usually available.
    // If 'any' is not available, 'lo' is a common alternative.
    // We open it in a non-activated state initially.
    handle = pcap_open_live("lo", BUFSIZ, 0, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device 'lo': %s\n", errbuf);
        printf("Failed to initialize pcap handle.\n");
        fflush(stdout);
        return 123;
    }
    printf("Successfully initialized pcap handle.\n");
    fflush(stdout);

    // Task 1: Invocation Specification Analysis
    // The function `pcap_set_snaplen` can only be called *before* the pcap handle
    // has been activated. Activation typically occurs when functions like
    // `pcap_loop`, `pcap_next_ex`, `pcap_sendpacket` are called.
    // The function checks this using `pcap_check_activated(p)`.
    // The original code was likely calling `pcap_open_live` with a `promisc` value
    // that implicitly activated the handle or a subsequent call that we missed.
    // By setting `promisc` to 0 in `pcap_open_live`, we ensure the handle is not
    // immediately activated, allowing `pcap_set_snaplen` to be called.

    printf("before pcap_set_snaplen\n");
    fflush(stdout);

    // Task2: Call the function
    int ret = pcap_set_snaplen(handle, snaplen_value);

    if (ret == 0) {
        printf("Calling pcap_set_snaplen success\n");
        fflush(stdout);
    } else {
        printf("Calling pcap_set_snaplen fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_set_snaplen failed with error code: %d\n", ret);
        fflush(stderr);
        // Attempt to get a more descriptive error message if available from libpcap
        char *pcap_error = pcap_geterr(handle);
        if (pcap_error && strlen(pcap_error) > 0) {
            fprintf(stderr, "libpcap error: %s\n", pcap_error);
            fflush(stderr);
        }
        pcap_close(handle);
        return 123;
    }

    // To make the handle useful and demonstrate activation, we can activate it now.
    // However, for the purpose of *just* testing pcap_set_snaplen,
    // we don't need to start a capture loop. We just need to ensure
    // pcap_set_snaplen is called *before* any activation.
    // If we were to call pcap_loop or similar here, it would fail because
    // pcap_set_snaplen would have already been called and the handle is now "activated"
    // in a way that doesn't allow snaplen changes.
    // The previous error "can't perform operation on activated capture"
    // suggests that `pcap_open_live` itself might have activated the handle
    // in a way that prevented `pcap_set_snaplen`. Setting `promisc` to 0
    // is the standard way to ensure it's not activated initially.

    // Clean up the pcap handle
    pcap_close(handle);
    printf("Successfully cleaned up pcap handle.\n");
    fflush(stdout);

    return 0;
}

