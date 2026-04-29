#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *header;
    // const u_char *packet; // This variable will be intentionally set to NULL
    int status;

    // Task2.7: Specify a file name for potential file operations.
    // For this example, we'll assume we might open a pcap file.
    const char *pcap_filename = "example.pcap";

    // Open a pcap device or file for live capture.
    // For this example, we'll try to open a device. If that fails,
    // we'll attempt to open the example pcap file.
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device eth0: %s\n", errbuf);
        printf("Attempting to open pcap file: %s\n", pcap_filename);
        fflush(stdout);
        handle = pcap_open_offline(pcap_filename, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open pcap file %s: %s\n", pcap_filename, errbuf);
            exit(123);
        }
        printf("Successfully opened pcap file: %s\n", pcap_filename);
        fflush(stdout);
    } else {
        printf("Successfully opened live device eth0\n");
        fflush(stdout);
    }

    // Task2.6: Add the required printf before calling pcap_next_ex.
    printf("before pcap_next_ex\n");
    fflush(stdout);

    // Task2.1 & 2.2 & 2.3 & 2.4 & 2.5: Call pcap_next_ex and check its status.
    // We call it only once to avoid infinite loops and ensure non-interactive execution.
    // VIOLATION: Passing a NULL pointer for the pkt_data parameter.
    // This violates the rule that the caller must not provide a NULL pointer for pkt_data.
    // The underlying packet reading functions will attempt to write to this NULL pointer,
    // leading to a NULL pointer dereference and likely a crash.
    status = pcap_next_ex(handle, &header, NULL); // VIOLATION HERE

    if (status == 1) {
        // Task2.5: Output success message.
        printf("Calling pcap_next_ex success\n");
        fflush(stdout);

        // You can optionally process the packet here if needed.
        // For this example, we'll just print a message.
        // This part might not be reached if the crash occurs before this.
        printf("Packet captured: length = %u\n", header->len);
        fflush(stdout);

    } else if (status == 0) {
        // Task2.3: Handle timeout for live capture.
        printf("Calling pcap_next_ex fail: Timeout expired\n");
        fflush(stdout);
        // For a live capture, status 0 means timeout.
        // For an offline capture, status 0 (mapped to -2 by pcap_next_ex) means EOF.
        // Since we are only calling it once, we consider timeout a failure in this context.
        pcap_close(handle);
        exit(123);
    } else if (status == -1) {
        // Task2.3: Handle general error.
        // Task2.3: Output error message with cause.
        // This error message might be printed if pcap_next_ex detects the NULL pointer
        // before attempting to dereference it, or if the crash occurs and this is
        // the last message before termination.
        fprintf(stderr, "Calling pcap_next_ex fail: Error reading packet - %s\n", pcap_geterr(handle));
        fflush(stdout);
        pcap_close(handle);
        exit(123);
    } else if (status == -2) {
        // Task2.3: Handle EOF for offline capture.
        printf("Calling pcap_next_ex fail: End of file reached\n");
        fflush(stdout);
        // Task2.3: Output error message with cause.
        // In this context, EOF is treated as a failure to get a new packet.
        pcap_close(handle);
        exit(123);
    }

    // Close the capture handle.
    pcap_close(handle);

    return 0;
}

