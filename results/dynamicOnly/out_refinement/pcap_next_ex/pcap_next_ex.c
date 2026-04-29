#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


#define EXIT_FAILURE_CUSTOM 123

int main() {
    pcap_t *handle;
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
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        fflush(stdout);
        return EXIT_FAILURE_CUSTOM;
    }
    printf("Successfully opened network interface.\n");
    fflush(stdout);

    // We need to pass pointers to pointers to `pcap_next_ex`
    // The library will then assign its internal pointers to these.
    packet_ptr_for_api = (const u_char **)malloc(sizeof(const u_char *));
    if (packet_ptr_for_api == NULL) {
        fprintf(stderr, "Memory allocation failed for packet_ptr_for_api.\n");
        fflush(stdout);
        pcap_close(handle);
        return EXIT_FAILURE_CUSTOM;
    }

    printf("before pcap_next_ex\n");
    fflush(stdout);

    // Call pcap_next_ex
    // We pass the address of `header` (a struct pcap_pkthdr *)
    // and the address of `packet_ptr_for_api` (which is a `const u_char **`)
    int status = pcap_next_ex(handle, &header, packet_ptr_for_api);

    if (status > 0) {
        // Packet captured successfully
        printf("Calling pcap_next_ex success\n");
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
        printf("Calling pcap_next_ex fail (timeout)\n");
        fflush(stdout);
    } else if (status == -1) {
        // Error occurred
        fprintf(stderr, "Calling pcap_next_ex fail (error): %s\n", pcap_geterr(handle));
        fflush(stdout);
        pcap_close(handle);
        free(packet_ptr_for_api); // Free the allocated memory
        return EXIT_FAILURE_CUSTOM;
    } else if (status == -2) {
        // EOF occurred (for offline captures) or breakloop called
        printf("Calling pcap_next_ex fail (EOF or breakloop)\n");
        fflush(stdout);
    }

    // Clean up
    pcap_close(handle);
    free(packet_ptr_for_api); // Free the allocated memory
    printf("Pcap handle closed and memory freed.\n");
    fflush(stdout);

    if (status <= 0) { // If the status was not a success (status > 0)
        return EXIT_FAILURE_CUSTOM;
    }

    return 0; // Indicate success
}

