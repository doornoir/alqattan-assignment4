#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    int length;
    int i;
    
    // The key can only use 27 allowed OTP chars.
    const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";

    // Expects exactly one command-line arg which is the key length
    if (argc != 2) {
        fprintf(stderr, "Usage: keygen keylength\n");
        return 1;
    }

    // Convert length argument from string to int
    length = atoi(argv[1]);

    // reject negative key lengths
    if (length < 0) {
        fprintf(stderr, "keygen error: keylength must be nonnegative\n");
        return 1;
    }

    // Seed the RNG.
    srand((unsigned int)(time(NULL) ^ getpid()));

    // Print exactly length random chars from the allowed OTP alphabet
    for (i = 0; i < length; i++) {
        putchar(alphabet[rand() % 27]);
    }
    // End key with newline
    putchar('\n');

    return 0;
}
