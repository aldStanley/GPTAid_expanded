#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    int error_code_success = 0; // A common successful error code (e.g., no error)
    // On Linux, sys_nerr is often around 132. An error code like 999 is likely out of bounds.
    int error_code_fail = 999;

    char *error_message;

    // --- Test Case 1: Successful call ---
    printf("before pcap_strerror\n");
    fflush(stdout);

    // Directly call the pcap_strerror function from libpcap
    error_message = pcap_strerror(error_code_success);

    // The pcap_strerror function is designed to always return a string,
    // even for unknown error codes. So, we primarily check if the returned
    // string is non-empty, though a NULL return is theoretically possible
    // if libpcap itself has an internal error allocating memory or similar,
    // which is highly unlikely for this function.
    if (error_message != NULL) {
        printf("Calling pcap_strerror success\n");
        fflush(stdout);
        printf("Error description for code %d: %s\n", error_code_success, error_message);
        fflush(stdout);
    } else {
        fprintf(stderr, "Calling pcap_strerror fail\n");
        fflush(stderr);
        fprintf(stderr, "pcap_strerror returned NULL, which is unexpected.\n");
        fflush(stderr);
        return 123;
    }

    // --- Test Case 2: Failed call (with an invalid error code) ---
    // This tests the fallback mechanism of pcap_strerror when an error code is out of range.
    printf("before pcap_strerror (for failure case)\n");
    fflush(stdout);

    // Directly call the pcap_strerror function from libpcap
    error_message = pcap_strerror(error_code_fail);

    if (error_message != NULL) {
        // Even for an invalid error code, pcap_strerror is expected to return a string.
        // We consider this a "success" in terms of the function executing and returning a string.
        printf("Calling pcap_strerror success (with potentially generic message)\n");
        fflush(stdout);
        printf("Error description for code %d: %s\n", error_code_fail, error_message);
        fflush(stdout);
    } else {
        // This path is highly unlikely for pcap_strerror.
        fprintf(stderr, "Calling pcap_strerror fail\n");
        fflush(stderr);
        fprintf(stderr, "pcap_strerror returned NULL for an invalid error code, which is unexpected.\n");
        fflush(stderr);
        return 123;
    }

    return 0;
}

