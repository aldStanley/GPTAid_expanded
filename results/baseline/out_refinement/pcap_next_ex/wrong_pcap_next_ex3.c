#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>



// Global pcap handle to be accessed by multiple threads
pcap_t *global_handle = NULL;
char errbuf[PCAP_ERRBUF_SIZE];

// Function to print error messages and exit
void handle_error(const char* message, pcap_t* handle) {
    fprintf(stderr, "%s: %s\n", message, pcap_geterr(handle));
    fflush(stderr);
    if (handle) {
        pcap_close(handle);
    }
    exit(123);
}

// Thread function that attempts to modify the pcap_t structure
void *modifier_thread_func(void *arg) {
    printf("Modifier thread started.\n");
    fflush(stdout);

    // In a real-world scenario, this would involve more complex manipulation
    // of the pcap_t structure. For this example, we'll simulate a modification
    // by trying to close the handle, which is a form of concurrent modification
    // that can interfere with pcap_next_ex.
    // We introduce a small delay to increase the chance of a race condition.
    sleep(1); // Give pcap_next_ex a chance to start

    if (global_handle) {
        printf("Modifier thread attempting to close the pcap handle.\n");
        fflush(stdout);
        pcap_close(global_handle); // This is a concurrent modification
        global_handle = NULL; // Mark as closed
    }

    printf("Modifier thread finished.\n");
    fflush(stdout);
    return NULL;
}

int main() {
    struct pcap_pkthdr *header;
    const u_char *packet;
    int status;
    pthread_t modifier_thread;

    // 1. Open a network interface for live capture
    const char *interface = "eth0"; // Replace with a valid interface
    global_handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (global_handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        fflush(stderr);
        return 123;
    }
    printf("Successfully opened device %s\n", interface);
    fflush(stdout);

    // 2. Create a thread that will concurrently modify the pcap_t handle
    if (pthread_create(&modifier_thread, NULL, modifier_thread_func, NULL) != 0) {
        perror("Failed to create modifier thread");
        pcap_close(global_handle);
        return 123;
    }

    // 3. Call pcap_next_ex to capture a single packet
    // This call is made while the modifier thread is running and potentially
    // modifying the pcap_t structure (by closing it in this example).
    printf("Main thread: before pcap_next_ex\n");
    fflush(stdout);

    // We expect this call to likely fail or behave unexpectedly due to the
    // concurrent modification.
    status = pcap_next_ex(global_handle, &header, &packet);

    // 4. Check the status of pcap_next_ex
    if (status == 1) {
        // Packet successfully captured (less likely with concurrent modification)
        printf("Main thread: Calling pcap_next_ex success\n");
        fflush(stdout);
        printf("Packet captured: %u bytes on wire, %u bytes captured\n", header->len, header->caplen);
        fflush(stdout);
    } else if (status == 0) {
        // Timeout occurred (live capture)
        printf("Main thread: Calling pcap_next_ex fail (timeout)\n");
        fflush(stdout);
        printf("Timeout: No packet received before the timeout expired.\n");
        fflush(stdout);
    } else if (status == -1) {
        // Error occurred
        printf("Main thread: Calling pcap_next_ex fail (error)\n");
        fflush(stdout);
        // If global_handle was closed by the modifier thread, pcap_geterr might
        // return an error related to a closed handle.
        if (global_handle) { // Check if handle is still valid before calling geterr
            handle_error("Error in pcap_next_ex", global_handle);
        } else {
            fprintf(stderr, "Error in pcap_next_ex: pcap handle was closed concurrently.\n");
            fflush(stderr);
        }
    } else if (status == -2) {
        // End of file (offline capture) - Not expected in this live capture example
        printf("Main thread: Calling pcap_next_ex fail (EOF)\n");
        fflush(stdout);
        printf("End of file reached (unexpected in live capture).\n");
        fflush(stdout);
    } else {
        printf("Main thread: Calling pcap_next_ex returned unexpected status: %d\n", status);
        fflush(stdout);
    }

    // 5. Wait for the modifier thread to finish
    pthread_join(modifier_thread, NULL);

    // 6. Close the pcap handle if it wasn't already closed by the modifier thread
    if (global_handle) {
        pcap_close(global_handle);
        printf("Main thread: Closed pcap handle.\n");
        fflush(stdout);
    } else {
        printf("Main thread: Pcap handle was already closed by the modifier thread.\n");
        fflush(stdout);
    }

    return 0;
}

