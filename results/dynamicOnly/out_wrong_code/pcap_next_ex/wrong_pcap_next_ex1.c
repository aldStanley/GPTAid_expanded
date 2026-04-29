#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




#define EXIT_FAILURE_CUSTOM 123

int main() {
    pcap_t *handle = NULL; // Initialize handle to NULL
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *header_ptr_for_api; // Renamed to avoid confusion with internal pcap_header
    const u_char **packet_ptr_for_api;      // Renamed to avoid confusion with internal pcap_data

    // Prepare pointers that pcap_next_ex will populate
    struct pcap_pkthdr *header = NULL;
    const u_char *packet = NULL;

    /*
     * Open a live capture device. Replace "eth0" with your actual network interface name.
     * If you don't have a live interface readily available or want to test with a file,
     * you could use pcap_open_offline("example.pcap", errbuf) instead.
     */
    // For this violation, we will intentionally not open a device,
    // leaving `handle` as NULL.
    // handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    // if (handle == NULL) {
    //     fprintf(stderr, "Couldn't open device: %s\n", errbuf);
    //     fflush(stdout);
    //     return EXIT_FAILURE_CUSTOM;
    // }
    // printf("Successfully opened network interface.\n");
    // fflush(stdout);

    // We need to pass pointers to pointers to `pcap_next_ex`
    // The library will then assign its internal pointers to these.
    packet_ptr_for_api = (const u_char **)malloc(sizeof(const u_char *));
    if (packet_ptr_for_api == NULL) {
        fprintf(stderr, "Memory allocation failed for packet_ptr_for_api.\n");
        fflush(stdout);
        // No need to close handle as it's NULL
        return EXIT_FAILURE_CUSTOM;
    }

    printf("before pcap_next_ex (handle is NULL)\n");
    fflush(stdout);

    // Call pcap_next_ex with a NULL pcap_t handle to violate the rule.
    // We pass the address of `header` (a struct pcap_pkthdr *)
    // and the address of `packet_ptr_for_api` (which is a `const u_char **`)
    int status = pcap_next_ex(handle, &header, packet_ptr_for_api);

    // The behavior of pcap_next_ex with a NULL handle is undefined,
    // but it's likely to cause a crash or return an error.
    // We'll check for a negative status code, which typically indicates an error.
    if (status > 0) {
        // This block is unlikely to be reached with a NULL handle.
        printf("Calling pcap_next_ex success (unexpected with NULL handle)\n");
        fflush(stdout);
        packet = *packet_ptr_for_api; // Dereference to get the actual packet data pointer

        printf("Packet captured: %u bytes\n", header->len);
        fflush(stdout);

        // Example of accessing packet data (e.g., first few bytes)
        printf("First 10 bytes of packet data: ");
        fflush(stdout);
        for (int i = 0; i < header->len && i < 10; i++) {
            printf("%02x ", packet[i]);
            fflush(stdout);
        }
        printf("\n");
        fflush(stdout);
    } else if (status == 0) {
        // Timeout occurred (for live captures)
        printf("Calling pcap_next_ex fail (timeout) (unexpected with NULL handle)\n");
        fflush(stdout);
    } else if (status == -1) {
        // Error occurred. This is the expected outcome when handle is NULL.
        // pcap_geterr might also behave unexpectedly or crash with a NULL handle.
        // We'll print a generic error message.
        fprintf(stderr, "Calling pcap_next_ex fail (error): Expected error with NULL handle.\n");
        fflush(stdout);
        // No need to close handle as it's NULL
        free(packet_ptr_for_api); // Free the allocated memory
        return EXIT_FAILURE_CUSTOM;
    } else if (status == -2) {
        // EOF occurred (for offline captures) or breakloop called
        printf("Calling pcap_next_ex fail (EOF or breakloop) (unexpected with NULL handle)\n");
        fflush(stdout);
    } else {
        // Catch any other unexpected return values
        fprintf(stderr, "Calling pcap_next_ex returned an unexpected status: %d\n", status);
        fflush(stdout);
        // No need to close handle as it's NULL
        free(packet_ptr_for_api); // Free the allocated memory
        return EXIT_FAILURE_CUSTOM;
    }

    // Clean up
    // No need to close handle as it's NULL
    free(packet_ptr_for_api); // Free the allocated memory
    printf("Memory freed. Pcap handle was NULL.\n");
    fflush(stdout);

    // If we reached here without an explicit error return, it means status was not <= 0.
    // However, with a NULL handle, we expect status <= 0.
    // If status > 0, it's an anomaly, but we'll still return 0 for success in that case.
    if (status <= 0) {
        return EXIT_FAILURE_CUSTOM;
    }

    return 0; // Indicate success (though unlikely with NULL handle)
}

