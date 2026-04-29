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

    // --- Step 2: Call pcap_next_ex once ---
    // As per requirement 6: Add the line before calling pcap_next_ex
    printf("before pcap_next_ex\n");
    fflush(stdout);

    // --- VIOLATION: Call pcap_next_ex with a NULL pcap_t pointer ---
    // This violates the rule that 'p' must be a properly initialized pcap_t.
    // Passing NULL will lead to undefined behavior.
    int status = pcap_next_ex(NULL, &header, &packet);

    // --- Step 3: Check the status of pcap_next_ex ---
    // The behavior after passing NULL is undefined, so these checks might not
    // be reached or might behave unexpectedly.
    if (status > 0) {
        // Packet successfully captured
        printf("Calling pcap_next_ex success\n");
        fflush(stdout);
        printf("Packet captured successfully! Packet number: %d\n", ++packet_count);
        fflush(stdout);
        printf("Packet length: %u bytes\n", header->len);
        fflush(stdout);
        printf("Captured length: %u bytes\n", header->caplen);
        fflush(stdout);
        // You can further process 'header' and 'packet' here if needed.
        // For this example, we'll just print basic info and exit.

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
        // Note: pcap_geterr(handle) might also cause issues if handle is NULL.
        // However, the primary violation is passing NULL to pcap_next_ex.
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
    }

    // --- Step 4: Close the pcap handle ---
    // This line might not be reached if the program crashes due to the violation.
    pcap_close(handle);
    printf("Closed pcap handle.\n");
    fflush(stdout);

    return 0; // Success
}

