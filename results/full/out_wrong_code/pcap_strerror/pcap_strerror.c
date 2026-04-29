#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>


int main() {
    int error_code_success = 0; // A common success code
    int error_code_fail = 999; // An invalid error code to simulate failure

    // Test case 1: Successful call
    printf("Testing pcap_strerror with a valid error code.\n");
    fflush(stdout);

    printf("before pcap_strerror\n");
    fflush(stdout);

    char *error_message_success = pcap_strerror(error_code_success);

    if (error_message_success != NULL) {
        printf("Calling pcap_strerror success\n");
        fflush(stdout);
        printf("Error message for code %d: %s\n", error_code_success, error_message_success);
        fflush(stdout);
    } else {
        printf("Calling pcap_strerror fail\n");
        fflush(stdout);
        fprintf(stderr, "Error: pcap_strerror returned NULL for code %d.\n", error_code_success);
        fflush(stderr);
        return 123;
    }

    printf("\n"); // Separator between test cases
    fflush(stdout);

    // Test case 2: Unsuccessful call (invalid error code)
    printf("Testing pcap_strerror with an invalid error code.\n");
    fflush(stdout);

    printf("before pcap_strerror\n");
    fflush(stdout);

    char *error_message_fail = pcap_strerror(error_code_fail);

    // The pcap_strerror function, when it cannot find a string for an error code,
    // will format a string like "Unknown error: %d". It doesn't return NULL for
    // an invalid error number. Therefore, we check for the presence of "Unknown error".
    if (error_message_fail != NULL) {
        if (strstr(error_message_fail, "Unknown error:") != NULL) {
            printf("Calling pcap_strerror success (as it handled unknown error)\n");
            fflush(stdout);
            printf("Error message for code %d: %s\n", error_code_fail, error_message_fail);
            fflush(stdout);
        } else {
            // This would be an unexpected scenario if the error message is valid
            // for an invalid error code.
            printf("Calling pcap_strerror fail\n");
            fflush(stdout);
            fprintf(stderr, "Error: pcap_strerror returned an unexpected string for code %d: %s\n", error_code_fail, error_message_fail);
            fflush(stderr);
            return 123;
        }
    } else {
        // This case is unlikely given the implementation of pcap_strerror,
        // but good to handle for robustness.
        printf("Calling pcap_strerror fail\n");
        fflush(stdout);
        fprintf(stderr, "Error: pcap_strerror returned NULL for code %d, which is unexpected.\n", error_code_fail);
        fflush(stderr);
        return 123;
    }

    return 0;
}

