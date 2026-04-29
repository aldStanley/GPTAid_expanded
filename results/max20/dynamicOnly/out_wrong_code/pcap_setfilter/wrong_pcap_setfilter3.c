#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>



// Define a custom error code for this program
#define CUSTOM_ERROR_CODE 123

// Global pcap handle to simulate sharing across threads
pcap_t *shared_handle = NULL;
char errbuf[PCAP_ERRBUF_SIZE];

// Structure to pass filter information to threads
typedef struct {
    const char *filter_exp;
    int thread_id;
} filter_thread_args_t;

// Function for threads to set filters
void *set_filter_thread(void *arg) {
    filter_thread_args_t *args = (filter_thread_args_t *)arg;
    struct bpf_program fp; // Compiled filter program

    printf("Thread %d: Attempting to compile filter '%s'\n", args->thread_id, args->filter_exp);
    fflush(stdout);

    // Compile the filter expression
    if (pcap_compile(shared_handle, &fp, args->filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Thread %d: Couldn't parse filter %s: %s\n", args->thread_id, args->filter_exp, pcap_geterr(shared_handle));
        fflush(stdout);
        // In a real scenario, you'd handle this error more robustly,
        // but for demonstration, we'll just print and exit the thread.
        pthread_exit(NULL);
    }
    printf("Thread %d: Successfully compiled filter expression '%s'.\n", args->thread_id, args->filter_exp);
    fflush(stdout);

    // Introduce a small delay to increase the chance of a race condition
    usleep(10000); // 10 milliseconds

    printf("Thread %d: Attempting to set filter.\n", args->thread_id);
    fflush(stdout);

    // Call pcap_setfilter - this is where the violation occurs
    if (pcap_setfilter(shared_handle, &fp) == -1) {
        fprintf(stderr, "Thread %d: Calling pcap_setfilter fail: %s\n", args->thread_id, pcap_geterr(shared_handle));
        fflush(stdout);
        pcap_freecode(&fp); // Free the compiled filter program
        pthread_exit(NULL);
    }

    printf("Thread %d: Calling pcap_setfilter success.\n", args->thread_id);
    fflush(stdout);

    // Cleanup for this thread's compiled filter
    pcap_freecode(&fp);
    return NULL;
}

int main() {
    const char *interface = "lo"; // Using loopback for common availability
    pthread_t thread1, thread2;
    filter_thread_args_t args1, args2;

    // 1. Open a network interface for live capture (shared handle)
    shared_handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (shared_handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        fflush(stdout);
        return CUSTOM_ERROR_CODE;
    }
    printf("Successfully opened network device %s.\n", interface);
    fflush(stdout);

    // Prepare arguments for the threads
    args1.filter_exp = "tcp port 80";
    args1.thread_id = 1;

    args2.filter_exp = "udp port 53";
    args2.thread_id = 2;

    // 2. Create threads that will concurrently call pcap_setfilter on the shared handle
    printf("Creating thread 1 to set filter '%s'\n", args1.filter_exp);
    fflush(stdout);
    if (pthread_create(&thread1, NULL, set_filter_thread, &args1) != 0) {
        perror("Failed to create thread 1");
        fflush(stdout);
        pcap_close(shared_handle);
        return CUSTOM_ERROR_CODE;
    }

    printf("Creating thread 2 to set filter '%s'\n", args2.filter_exp);
    fflush(stdout);
    if (pthread_create(&thread2, NULL, set_filter_thread, &args2) != 0) {
        perror("Failed to create thread 2");
        fflush(stdout);
        pcap_close(shared_handle);
        return CUSTOM_ERROR_CODE;
    }

    // Wait for both threads to complete
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    // 3. Cleanup
    if (shared_handle) {
        pcap_close(shared_handle); // Close the capture handle
        printf("Cleaned up resources.\n");
        fflush(stdout);
    }

    return 0; // Indicate successful execution
}

