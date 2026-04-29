#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>



// The function to be tested, as provided in the problem description.
// If this function is in a separate compilation unit, it should be declared as extern.
// For simplicity, we assume it's available in the scope.
extern int pcap_set_snaplen(pcap_t *p, int snaplen);

/*
int pcap_set_snaplen(pcap_t *p, int snaplen){
	if (pcap_check_activated(p))
		return (PCAP_ERROR_ACTIVATED);
	p->snapshot = snaplen;
	return (0);
}
*/

int main() {
    pcap_t *handle = NULL;
    // Use "any" to try and capture on all interfaces. This usually requires root privileges.
    // If running without root, a specific interface like "eth0" might be needed, but could fail.
    const char *dev = "any";
    char errbuf[PCAP_ERRBUF_SIZE];
    int snapshot_len = 1024; // Example snapshot length

    // Task2.1: Code is compilable and follows invocation specification.
    // Task2.2: Non-interactive and no infinite loops.
    // Task2.3: Check call status of each API. If fails, return 123 and output error message.

    // Use pcap_create to obtain a pcap_t handle. This handle is NOT activated yet.
    // This is the correct way to get a handle on which pcap_set_snaplen can be called.
    handle = pcap_create(dev, errbuf);
    if (handle == NULL) {
        // Task2.3: Error handling for pcap_create
        fprintf(stderr, "Error during pcap_create: %s\n", errbuf);
        fflush(stderr); // Task2.4
        return 123;
    }
    printf("pcap_create successfully created a handle for device '%s'. Handle is not yet activated.\n", dev);
    fflush(stdout); // Task2.4

    // Task2.6: Add line before calling pcap_set_snaplen
    printf("before pcap_set_snaplen\n");
    fflush(stdout); // Task2.4

    // Task2.1: Call pcap_set_snaplen.
    // This call should succeed because 'handle' is not activated.
    int result = pcap_set_snaplen(handle, snapshot_len);

    // Task2.3 & 2.5: Check call status and output messages
    if (result != 0) {
        // Task2.5
        printf("Calling pcap_set_snaplen fail\n");
        fflush(stdout); // Task2.4

        // Task2.3: Infer cause of error
        if (result == PCAP_ERROR_ACTIVATED) {
            fprintf(stderr, "Error: pcap_set_snaplen failed because the pcap handle was already activated.\n");
        } else {
            // Use pcap_geterr to get a more descriptive error message from libpcap.
            fprintf(stderr, "pcap_set_snaplen failed with error code %d: %s\n", result, pcap_geterr(handle));
        }
        fflush(stderr); // Task2.4
        pcap_close(handle); // Clean up the handle on failure
        return 123; // Task2.3
    } else {
        // Task2.5
        printf("Calling pcap_set_snaplen success\n");
        fflush(stdout); // Task2.4
        // The snapshot length is set in the handle's internal structure,
        // but it is fully applied upon activation.
        printf("Snapshot length has been provisionally set to %d.\n", snapshot_len);
        fflush(stdout); // Task2.4
    }

    // Now, activate the handle. This is when the snapshot length is finalized.
    printf("Attempting to activate the pcap handle...\n");
    fflush(stdout); // Task2.4

    int activate_result = pcap_activate(handle);
    if (activate_result != 0) {
        // Task2.3: Error handling for pcap_activate
        fprintf(stderr, "Error: pcap_activate failed with code %d: %s\n", activate_result, pcap_geterr(handle));
        fflush(stderr); // Task2.4
        pcap_close(handle);
        return 123;
    }
    printf("pcap_activate successful. The capture session has started.\n");
    fflush(stdout); // Task2.4

    // Demonstrate that calling pcap_set_snaplen after activation fails.
    printf("Attempting to call pcap_set_snaplen again after activation...\n");
    fflush(stdout); // Task2.4
    int second_set_result = pcap_set_snaplen(handle, 512); // Try setting a different snaplen
    if (second_set_result != 0) {
        // Task2.5
        printf("Calling pcap_set_snaplen fail as expected after activation\n");
        fflush(stdout); // Task2.4
        // Task2.3: Infer cause of error
        fprintf(stderr, "pcap_set_snaplen correctly returned error code %d (PCAP_ERROR_ACTIVATED) after activation.\n", second_set_result);
        fflush(stderr); // Task2.4
    } else {
        // This branch should ideally not be reached if libpcap works as expected.
        printf("Calling pcap_set_snaplen success unexpectedly after activation.\n");
        fflush(stdout); // Task2.4
    }

    // Task 7: No file read operations in this code.

    // Clean up the pcap handle
    pcap_close(handle);
    printf("pcap_close called successfully. Capture session ended.\n");
    fflush(stdout); // Task2.4

    return 0;
}

