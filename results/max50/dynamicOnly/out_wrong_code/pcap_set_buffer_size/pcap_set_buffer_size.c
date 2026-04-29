#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


// Function to print error messages and exit
void print_error_and_exit(const char *msg, const char *pcap_err) {
    fprintf(stderr, "%s: %s\n", msg, pcap_err);
    exit(123);
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *device = NULL; // We will try to find a device

    // 1. Find a suitable network device (non-interactive)
    device = pcap_lookupdev(errbuf);
    if (device == NULL) {
        fprintf(stderr, "Could not find a default device: %s\n", errbuf);
        // Attempt to create a dummy handle for offline analysis if no device found
        // This is just to demonstrate setting buffer size before activation.
        // In a real scenario, you'd likely need a valid device or file.
        printf("No network device found. Attempting to use a dummy handle for demonstration.\n");
        fflush(stdout);
        handle = pcap_open_dead(DLT_EN10MB, BUFSIZ); // DLt_EN10MB is Ethernet, BUFSIZ is a reasonable initial buffer size
        if (handle == NULL) {
            fprintf(stderr, "Failed to create a dummy pcap handle.\n");
            fflush(stderr);
            return 123;
        }
        printf("Successfully created a dummy pcap handle.\n");
        fflush(stdout);
    } else {
        printf("Using network device: %s\n", device);
        fflush(stdout);
        // 2. Create a pcap handle
        handle = pcap_create(device, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "pcap_create failed: %s\n", errbuf);
            fflush(stderr);
            return 123;
        }
        printf("pcap_create successful for device %s.\n", device);
        fflush(stdout);

        // 3. Set buffer size (before activation)
        // We'll try setting it to a reasonably large value, e.g., 10MB
        int desired_buffer_size = 10 * 1024 * 1024; // 10 MB

        printf("before pcap_set_buffer_size\n");
        fflush(stdout);

        int set_buffer_result = pcap_set_buffer_size(handle, desired_buffer_size);

        if (set_buffer_result != 0) {
            // pcap_set_buffer_size can return PCAP_ERROR_ACTIVATED if called after activate.
            // However, in this code path, handle is not yet activated, so this specific error is unlikely
            // unless pcap_create itself somehow implicitly activated it, which is not standard.
            // The function itself returns 0 on success or if buffer_size <= 0.
            // The only explicit error code mentioned in the provided snippet is PCAP_ERROR_ACTIVATED.
            // If pcap_set_buffer_size returns something other than 0 and it's not PCAP_ERROR_ACTIVATED,
            // it might indicate a deeper issue not explicitly shown in the snippet.
            // For robustness, we check the return code against what's expected.
            // If PCAP_ERROR_ACTIVATED is returned, it means the invocation spec was violated.
            if (set_buffer_result == PCAP_ERROR_ACTIVATED) {
                fprintf(stderr, "Calling pcap_set_buffer_size failed: The pcap handle was already activated.\n");
                fflush(stderr);
            } else {
                fprintf(stderr, "Calling pcap_set_buffer_size failed with unexpected return code: %d\n", set_buffer_result);
                fflush(stderr);
            }
            pcap_close(handle); // Clean up the handle
            return 123;
        }

        printf("Calling pcap_set_buffer_size success\n");
        fflush(stdout);

        // 4. Activate the handle (now that we've set options)
        int activate_result = pcap_activate(handle);
        if (activate_result != 0) {
            // If activation fails, we still want to print an error related to it.
            // pcap_geterr() is the correct way to get the libpcap error string.
            fprintf(stderr, "pcap_activate failed: %s\n", pcap_geterr(handle));
            fflush(stderr);
            pcap_close(handle); // Clean up the handle
            return 123;
        }
        printf("pcap_activate successful.\n");
        fflush(stdout);

        // Optional: Verify the buffer size (after activation, though this might be tricky to *directly* verify from libpcap itself after activation)
        // The most reliable way to verify is to have captured data and check its behavior.
        // For demonstration, we'll just assume it was set if pcap_set_buffer_size returned success.

        printf("Buffer size set successfully (or ignored if invalid input).\n");
        fflush(stdout);

        // 5. Close the handle
        pcap_close(handle);
        printf("pcap handle closed.\n");
        fflush(stdout);
    }


    return 0;
}

