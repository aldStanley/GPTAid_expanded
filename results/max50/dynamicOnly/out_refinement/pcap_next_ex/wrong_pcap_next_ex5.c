#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




// Define the exit code for failure
#define EXIT_FAILURE_CODE 123

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    // struct pcap_pkthdr *header; // This variable is no longer needed for the violation
    const u_char *packet;
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

    // Call pcap_next_ex to get the next packet, VIOLATING the rule by passing NULL for pkt_header
    // The rule states: "The caller must provide a valid, non-NULL pointer for pkt_header to receive the packet header information."
    // By passing NULL, we are violating this rule.
    int status = pcap_next_ex(handle, NULL, &packet);

    // --- Step 3: Check the status of pcap_next_ex ---
    // The logic here will likely not execute as expected due to the violation,
    // but we keep it to show the program flow after the call.
    if (status > 0) {
        // Packet successfully captured (this branch is unlikely to be reached with the violation)
        printf("Calling pcap_next_ex success\n");
        fflush(stdout);
        printf("Packet captured successfully! Packet number: %d\n", ++packet_count);
        fflush(stdout);
        // The following lines would cause a crash or undefined behavior because 'header' is NULL
        // printf("Packet length: %u bytes\n", header->len);
        // fflush(stdout);
        // printf("Captured length: %u bytes\n", header->caplen);
        // fflush(stdout);
    } else if (status == 0) {
        // Timeout occurred (for live capture)
        printf("Calling pcap_next_ex fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_next_ex: Timeout occurred, no packet received before timeout.\n");
        fflush(stdout);
        // In a real scenario, a timeout might happen, but the violation is in the call itself.
        // We still return failure as the intended operation was not performed correctly.
        return EXIT_FAILURE_CODE;
    } else if (status == -1) {
        // Error occurred
        printf("Calling pcap_next_ex fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_next_ex: Error reading the packets: %s\n", pcap_geterr(handle));
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
    } else {
        // Handle any other unexpected return values
        printf("Calling pcap_next_ex fail\n");
        fflush(stdout);
        fprintf(stderr, "pcap_next_ex: Unexpected return value: %d\n", status);
        fflush(stdout);
        return EXIT_FAILURE_CODE;
    }

    // --- Step 4: Close the pcap handle ---
    pcap_close(handle);
    printf("Closed pcap handle.\n");
    fflush(stdout);

    return 0; // Success (though the operation was flawed)
}

