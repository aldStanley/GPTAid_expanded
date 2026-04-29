#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




// Function to print error messages and exit
void handle_error(const char* message, pcap_t* handle) {
    fprintf(stderr, "%s: %s\n", message, pcap_geterr(handle));
    fflush(stderr);
    if (handle) {
        pcap_close(handle);
    }
    exit(123);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    // struct pcap_pkthdr *header; // This variable is no longer needed for the violation
    const u_char *packet;
    int status;

    // 1. Open a network interface for live capture
    // Replace "eth0" with the desired network interface.
    // You might need to list interfaces using pcap_findalldevs() for a real application.
    const char *interface = "eth0";
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        fflush(stderr);
        return 123;
    }
    printf("Successfully opened device %s\n", interface);
    fflush(stdout);

    // 2. Call pcap_next_ex to capture a single packet, violating the rule
    printf("before pcap_next_ex (violating rule)\n");
    fflush(stdout);
    // VIOLATION: Passing NULL for the pkt_header parameter.
    // The rule states: "The caller must provide a valid, non-NULL pointer for pkt_header to receive the packet header information."
    status = pcap_next_ex(handle, NULL, &packet);

    // 3. Check the status of pcap_next_ex
    if (status == 1) {
        // Packet successfully captured
        printf("Calling pcap_next_ex success (but header info is lost due to violation)\n");
        fflush(stdout);
        // We cannot print packet details like header->len and header->caplen
        // because header is NULL. Accessing it would lead to a crash.
        printf("Packet captured, but header information is unavailable due to the violation.\n");
        fflush(stdout);
    } else if (status == 0) {
        // Timeout occurred (live capture)
        printf("Calling pcap_next_ex fail\n");
        fflush(stdout);
        printf("Timeout: No packet received before the timeout expired.\n");
        fflush(stdout);
    } else if (status == -1) {
        // Error occurred
        printf("Calling pcap_next_ex fail\n");
        fflush(stdout);
        handle_error("Error in pcap_next_ex", handle);
    } else if (status == -2) {
        // End of file (offline capture) - Not expected in this live capture example
        printf("Calling pcap_next_ex fail\n");
        fflush(stdout);
        printf("End of file reached (unexpected in live capture).\n");
        fflush(stdout);
    }

    // 4. Close the pcap handle
    pcap_close(handle);
    printf("Closed pcap handle.\n");
    fflush(stdout);

    return 0;
}

