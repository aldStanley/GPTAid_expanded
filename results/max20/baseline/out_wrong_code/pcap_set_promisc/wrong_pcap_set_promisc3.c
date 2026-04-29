#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>




int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    // In a real scenario, you'd likely want to select an interface dynamically or from user input.
    // For this example, we'll assume "eth0" is available.
    // You might need to change "eth0" to your actual network interface name (e.g., "wlan0", "enp3s0").
    const char *interface = "eth0";

    // Task2.2: Non-interactive, no infinite loops.
    // Task2.3: Check API call status and output error messages.
    // Task2.4: Flush stdout after every printf.
    // Task2.5: Specific success/fail output for pcap_set_promisc.
    // Task2.6: Add "before pcap_set_promisc" line.
    // Task2.7: No file read operations are needed for this specific function.

    // Open a live capture handle.
    // The third parameter (0) means not to enter promiscuous mode immediately.
    // The fourth parameter (1000) is the timeout in milliseconds.
    handle = pcap_open_live(interface, BUFSIZ, 0, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error: Could not open device %s: %s\n", interface, errbuf);
        fflush(stderr);
        return 123;
    }
    printf("Successfully opened pcap handle for interface %s.\n", interface);
    fflush(stdout);

    // Task 1: The function pcap_set_promisc must be called *before* pcap_activate.
    // The provided code snippet for pcap_set_promisc has a check:
    // if (pcap_check_activated(p)) return (PCAP_ERROR_ACTIVATED);
    // This means if pcap_activate has already been called, pcap_set_promisc will fail.

    // Call pcap_set_promisc. We want to enable promiscuous mode.
    int promisc_setting = 1; // 1 to enable promiscuous mode

    // Task2.6: Add the required output line before calling pcap_set_promisc.
    printf("before pcap_set_promisc\n");
    fflush(stdout);

    // --- VIOLATION START ---
    // Violate Rule: The `pcap_t` handle must be properly initialized before being passed to `pcap_set_promisc`.
    // We will pass a NULL pointer to pcap_set_promisc to simulate an uninitialized or invalid handle.
    // This directly violates the requirement that the handle must be properly initialized.
    int result = pcap_set_promisc(NULL, promisc_setting);
    // --- VIOLATION END ---

    if (result == 0) {
        // Task2.5: Output success message.
        printf("Calling pcap_set_promisc success\n");
        fflush(stdout);
    } else {
        // Task2.5: Output fail message.
        printf("Calling pcap_set_promisc fail\n");
        fflush(stdout);
        // Task2.3: Output error message for failure.
        // When passing NULL, pcap_geterr might not provide a meaningful error related to the handle itself,
        // but it will indicate a failure.
        fprintf(stderr, "Error: pcap_set_promisc failed. Reason: %s\n", pcap_geterr(handle)); // Using 'handle' here for consistency, though it's not the one passed to the failing call.
        fflush(stderr);
        pcap_close(handle); // Clean up the handle
        return 123;
    }

    // To ensure the code doesn't enter an infinite loop or get stuck,
    // we will proceed to activate the handle and then close it.
    // We won't attempt to call pcap_set_promisc again after activation,
    // as that would be calling it incorrectly according to Task 1.

    int activate_result = pcap_activate(handle);
    if (activate_result != 0) {
        fprintf(stderr, "Error: Failed to activate pcap handle: %s\n", pcap_geterr(handle));
        fflush(stderr);
        pcap_close(handle); // Clean up the handle
        return 123;
    }
    printf("Successfully activated pcap handle.\n");
    fflush(stdout);

    // Clean up the pcap handle.
    pcap_close(handle);
    printf("Pcap handle closed successfully.\n");
    fflush(stdout);

    return 0;
}

