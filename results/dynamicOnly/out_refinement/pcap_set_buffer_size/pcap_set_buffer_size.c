#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




// Define PCAP_ERROR_ACTIVATED if not already defined by pcap.h
#ifndef PCAP_ERROR_ACTIVATED
#define PCAP_ERROR_ACTIVATED -1
#endif

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    const char *device = "eth0"; // Example device, adjust if needed
    int snaplen = 65535;
    int promisc = 1;
    int to_ms = 1000;
    int desired_buffer_size = 1024 * 1024; // 1MB

    // --- Create a pcap_t handle without activating it ---
    handle = pcap_create(device, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error creating pcap handle for device %s: %s\n", device, errbuf);
        printf("pcap_create failed\n");
        fflush(stdout);
        return 123;
    }
    printf("pcap_create succeeded\n");
    fflush(stdout);

    // --- Set other options before activation ---
    if (pcap_set_snaplen(handle, snaplen) != 0) {
        fprintf(stderr, "Error setting snaplen: %s\n", pcap_geterr(handle));
        printf("pcap_set_snaplen failed\n");
        fflush(stdout);
        pcap_close(handle);
        return 123;
    }
    printf("pcap_set_snaplen succeeded\n");
    fflush(stdout);

    if (pcap_set_promisc(handle, promisc) != 0) {
        fprintf(stderr, "Error setting promiscuous mode: %s\n", pcap_geterr(handle));
        printf("pcap_set_promisc failed\n");
        fflush(stdout);
        pcap_close(handle);
        return 123;
    }
    printf("pcap_set_promisc succeeded\n");
    fflush(stdout);

    if (pcap_set_timeout(handle, to_ms) != 0) {
        fprintf(stderr, "Error setting timeout: %s\n", pcap_geterr(handle));
        printf("pcap_set_timeout failed\n");
        fflush(stdout);
        pcap_close(handle);
        return 123;
    }
    printf("pcap_set_timeout succeeded\n");
    fflush(stdout);

    // --- Set the buffer size before activation ---
    // The provided pcap_set_buffer_size function checks if the handle is activated.
    // We are calling it before pcap_activate, so it should succeed.
    // Note: This function signature might be internal or not officially exposed
    // in all libpcap versions. For robustness, using pcap_set_buffer_size if available
    // is the direct way to fulfill the request. If it's not directly callable,
    // it implies a different mechanism might be intended for buffer size control.
    // Based on the provided function, we call it directly.

    // Add the specified printf before calling
    printf("before pcap_set_buffer_size\n");
    fflush(stdout);

    // Call pcap_set_buffer_size and check status
    int result = pcap_set_buffer_size(handle, desired_buffer_size);

    if (result == 0) {
        printf("Calling pcap_set_buffer_size success\n");
        fflush(stdout);
    } else {
        // Infer cause of error based on return code
        if (result == PCAP_ERROR_ACTIVATED) {
            // This branch should ideally not be hit if called before activate
            fprintf(stderr, "Error: pcap_set_buffer_size failed because the pcap handle is already activated.\n");
            printf("Calling pcap_set_buffer_size fail\n");
            fflush(stdout);
            // Clean up and exit with error code
            pcap_close(handle);
            return 123;
        } else {
            fprintf(stderr, "Error: pcap_set_buffer_size returned an unexpected error code: %d. Error details: %s\n", result, pcap_geterr(handle));
            printf("Calling pcap_set_buffer_size fail\n");
            fflush(stdout);
            // Clean up and exit with error code
            pcap_close(handle);
            return 123;
        }
    }

    // --- Activate the pcap handle ---
    int activate_result = pcap_activate(handle);
    if (activate_result != 0) {
        fprintf(stderr, "Error activating pcap handle: %s\n", pcap_geterr(handle));
        printf("pcap_activate failed\n");
        fflush(stdout);
        pcap_close(handle);
        return 123;
    }
    printf("pcap_activate succeeded\n");
    fflush(stdout);

    // --- Clean up resources ---
    pcap_close(handle);
    printf("pcap_close succeeded\n");
    fflush(stdout);

    return 0;
}

