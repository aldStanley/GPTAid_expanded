#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




// Define the exit code for failure
#define EXIT_FAILURE_CODE 123

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr *header;
    // const u_char *packet; // This variable will not be used to avoid dereferencing NULL
    int packet_count = 0;

    // --- Step 1: Open a live capture device ---
    // Replace "eth0" with an actual network interface on your system if needed.
    // You might need root privileges to open a live capture device.
    const char *interface = "eth0"; // Or any other interface like "wlan0"
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening adapter '%s': %s\n", interface, errbuf);
        fflush(stdout);
        return EXIT_FAILURE_CODE;
    }
    printf("Successfully opened network interface '%s'.\n", interface);
    fflush(stdout);

    // --- Step 2: Call pcap_next_ex once, violating the rule ---
    // As per requirement 6: Add the line before calling pcap_next_ex
    printf("before pcap_next_ex\n");
    fflush(stdout);

    // Call pcap_next_ex to get the next packet, violating the rule by passing NULL for pkt_data
    // VIOLATION: Passing a NULL pointer for pkt_data.
    // The underlying read operation will attempt to write to *pkt_data,
    // which is NULL, causing a NULL pointer dereference.
    printf("Calling pcap_next_ex with NULL pkt_data...\n");
    fflush(stdout);
    int status = pcap_next_ex(handle, &header, NULL); // VIOLATION: NULL passed for pkt_data

    // --- Step 3: Check the status of pcap_next_ex ---
    // The behavior after this call is undefined and likely a crash.
    // We check the return code, but the crash might have already occurred.
    if (status > 0) {
        // Packet successfully captured (highly unlikely with NULL pkt_data)
        printf("Calling pcap_next_ex success (unexpected with NULL pkt_data)\n");
        fflush(stdout);
        printf("Packet captured successfully! Packet number: %d\n", ++packet_count);
        fflush(stdout);
        // We cannot safely access header->len or header->caplen here if header is also NULL
        // or if the crash has already occurred.
        if (header) {
            printf("Packet length: %u bytes\n", header->len);
            fflush(stdout);
            printf("Captured length: %u bytes\n", header->caplen);
            fflush(stdout);
        } else {
            fprintf(stderr, "Header pointer is NULL after pcap_next_ex.\n");
            fflush(stdout);
        }

    } else if (status == 0) {
        // Timeout occurred (for live capture)
        printf("Calling pcap_next_ex fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_next_ex: Timeout occurred, no packet received before timeout.\n");
        fflush(stdout);
        return EXIT_FAILURE_CODE;
    } else if (status == -1) {
        // Error occurred
        printf("Calling pcap_next_ex fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_next_ex: Error reading the packets (likely due to NULL pkt_data): %s\n", pcap_geterr(handle));
        fflush(stdout);
        return EXIT_FAILURE_CODE;
    } else if (status == -2) {
        // End of file for offline capture (not applicable for pcap_open_live)
        printf("Calling pcap_next_ex fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_next_ex: End of file reached unexpectedly.\n");
        fflush(stdout);
        return EXIT_FAILURE_CODE;
    } else if (status == -3) {
        // Capture loop was broken
        printf("Calling pcap_next_ex fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_next_ex: Capture loop was broken.\n");
        fflush(stdout);
        return EXIT_FAILURE_CODE;
    }

    // --- Step 4: Close the pcap handle ---
    pcap_close(handle);
    printf("Closed pcap handle.\n");
    fflush(stdout);

    return 0; // Success (though the program might have crashed before reaching here)
}

