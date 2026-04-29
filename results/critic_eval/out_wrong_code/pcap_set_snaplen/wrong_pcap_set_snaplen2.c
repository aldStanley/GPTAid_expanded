#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


// Define a custom, intentionally small error buffer size for demonstration
#define SMALL_ERRBUF_SIZE 10

// A structure that mimics pcap_t but with a deliberately small errbuf
typedef struct {
    int activated; // Simulate the activated state
    char errbuf[SMALL_ERRBUF_SIZE]; // Intentionally small error buffer
    // Other pcap_t members would be here in a real scenario
} pcap_t_small_errbuf;

int main() {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE]; // Standard error buffer for initial operations
    int snaplen_value = 1024; // Example snapshot length
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    char *dev_name = NULL;

    // 1. Initialize pcap handle
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding all devices: %s\n", errbuf);
        fflush(stderr);
        exit(EXIT_FAILURE);
    }

    if (alldevs == NULL) {
        fprintf(stderr, "No network devices found.\n");
        fflush(stderr);
        exit(EXIT_FAILURE);
    }

    dev = alldevs;
    dev_name = dev->name;

    // Open a pcap handle on the found device
    handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap handle on device %s: %s\n", dev_name, errbuf);
        fflush(stderr);
        pcap_freealldevs(alldevs);
        exit(EXIT_FAILURE);
    }
    printf("Successfully opened pcap handle on device: %s\n", dev_name);
    fflush(stdout);

    pcap_freealldevs(alldevs);

    // --- Violation of Rule: The `pcap_t` structure's `errbuf` must be sufficiently sized ---
    // To violate this rule, we need to simulate a scenario where `pcap_set_snaplen`
    // is called on a `pcap_t` structure that has an `errbuf` that is too small.
    // The `pcap_set_snaplen` function internally calls `pcap_check_activated`,
    // which might write error messages to the `errbuf`. If the `errbuf` is too small,
    // a buffer overflow can occur.

    // We will create a `pcap_t_small_errbuf` structure and cast it to `pcap_t*`
    // to pass to `pcap_set_snaplen`. This is a direct simulation of the violation.
    // In a real-world exploit, this might involve memory corruption or a compromised library.

    pcap_t_small_errbuf *malicious_handle_data = malloc(sizeof(pcap_t_small_errbuf));
    if (!malicious_handle_data) {
        fprintf(stderr, "Failed to allocate memory for malicious handle data.\n");
        fflush(stderr);
        pcap_close(handle); // Close the valid handle
        exit(EXIT_FAILURE);
    }

    // Initialize the malicious handle data to simulate an activated state
    malicious_handle_data->activated = 1;
    // The errbuf is intentionally small (SMALL_ERRBUF_SIZE)

    // Now, we will attempt to call pcap_set_snaplen with this malformed handle.
    // The `pcap_check_activated` function (called internally by `pcap_set_snaplen`)
    // will likely try to write an error message like "capture is activated" into
    // `malicious_handle_data->errbuf`. Since `SMALL_ERRBUF_SIZE` is very small,
    // this will cause a buffer overflow.

    printf("before pcap_set_snaplen (violating errbuf size rule)\n");
    fflush(stdout);

    // Call pcap_set_snaplen with the malformed handle.
    // This call is expected to fail and potentially cause a crash or undefined behavior
    // due to the buffer overflow in the internal `pcap_check_activated` call.
    // We cast `malicious_handle_data` to `pcap_t*` to satisfy the function signature.
    int set_snaplen_result = pcap_set_snaplen((pcap_t *)malicious_handle_data, snaplen_value);

    // 5. Output: "Calling pcap_set_snaplen success" after calling pcap_set_snaplen successfully;
    // Output: "Calling pcap_set_snaplen fail" after the call to pcap_set_snaplen has failed
    if (set_snaplen_result == 0) {
        // This branch is unlikely to be reached if the violation is successful.
        printf("Calling pcap_set_snaplen success (unexpected for this violation)\n");
        fflush(stdout);
    } else {
        // 3. If API call fails, return 123 and output error message to infer the cause of the error.
        fprintf(stderr, "Calling pcap_set_snaplen fail. Error code: %d. ", set_snaplen_result);
        fflush(stderr);

        // Attempt to retrieve the error message from the malformed handle's errbuf.
        // Note: Accessing `malicious_handle_data->errbuf` directly here is for demonstration.
        // In a real crash scenario, the program might terminate before this point.
        // The error message written by pcap_check_activated might be truncated or corrupted.
        fprintf(stderr, "Attempted to read from malformed errbuf: '%.*s'\n",
                SMALL_ERRBUF_SIZE, malicious_handle_data->errbuf);
        fflush(stderr);

        // If the handle was valid, we would use pcap_geterr(handle).
        // However, here we are dealing with a simulated malformed structure.
        // The error code `PCAP_ERROR_ACTIVATED` (-1) is expected if the handle is activated.
        // The buffer overflow is the primary violation we are demonstrating.

        // Clean up the allocated memory for the malformed handle data
        free(malicious_handle_data);

        // Close the valid pcap handle opened earlier
        pcap_close(handle);
        printf("Pcap handle closed.\n");
        fflush(stdout);

        return 123; // Return a non-zero exit code to indicate failure
    }

    // Clean up the allocated memory for the malformed handle data if the call unexpectedly succeeded
    free(malicious_handle_data);

    // Clean up the valid pcap handle
    pcap_close(handle);
    printf("Pcap handle closed.\n");
    fflush(stdout);

    return 0;
}

