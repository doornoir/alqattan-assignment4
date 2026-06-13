#define _POSIX_C_SOURCE 200809L
#include "otp_common.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// Get sockaddr, IPv4 or IPv6
static void* get_in_addr(struct sockaddr* sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}


// Connects to the server running on localhost at the given port.
// Returns the connected socket file descriptor, or -1 if connection fails.
static int connect_to_server(const char* port) {
    int sockfd;
    struct addrinfo hints;
    struct addrinfo* servinfo;
    struct addrinfo* p;
    int rv;
    char s[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    rv = getaddrinfo("localhost", port, &hints, &servinfo);
    if (rv != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    sockfd = -1;
    for (p = servinfo; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            sockfd = -1;
            continue;
        }

        break;
    }

    if (p != NULL) {
        inet_ntop(p->ai_family, get_in_addr((struct sockaddr*)p->ai_addr), s, sizeof s);
    }

    freeaddrinfo(servinfo);

    if (sockfd == -1) {
        return -1;
    }

    return sockfd;
}

// Main shared client function
int run_client(int argc, char* argv[], const char* mode, const char* server_name) {
    char* text;
    char* key;
    char* output;
    int text_len;
    int key_len;
    int err;
    int sockfd;
    char response[3];
    uint32_t net_text_len;
    uint32_t net_key_len;

    text = NULL;
    key = NULL;
    output = NULL;
    text_len = 0;
    key_len = 0;
    err = 0;

    if (argc != 4) {
        fprintf(stderr, "Usage: %s input key port\n", argv[0]);
        return 1;
    }

    text = read_file_strip_newline(argv[1], &text_len, &err);
    if (err || text == NULL) {
        fprintf(stderr, "%s error: could not open input file %s\n", argv[0], argv[1]);
        return 1;
    }

    key = read_file_strip_newline(argv[2], &key_len, &err);
    if (err || key == NULL) {
        fprintf(stderr, "%s error: could not open key file %s\n", argv[0], argv[2]);
        free(text);
        return 1;
    }

    if (!valid_otp_text(text, text_len) || !valid_otp_text(key, key_len)) {
        fprintf(stderr, "%s error: input contains bad characters\n", argv[0]);
        free(text);
        free(key);
        return 1;
    }

    if (key_len < text_len) {
        fprintf(stderr, "Error: key '%s' is too short\n", argv[2]);
        free(text);
        free(key);
        return 1;
    }

    sockfd = connect_to_server(argv[3]);
    if (sockfd == -1) {
        fprintf(stderr, "Error: could not contact %s on port %s\n", server_name, argv[3]);
        free(text);
        free(key);
        return 2;
    }

    if (send_all(sockfd, mode, 3) == -1 || recv_all(sockfd, response, 2) == -1) {
        fprintf(stderr, "Error: could not contact %s on port %s\n", server_name, argv[3]);
        close(sockfd);
        free(text);
        free(key);
        return 2;
    }

    response[2] = '\0';
    if (strcmp(response, "OK") != 0) {
        fprintf(stderr, "Error: could not contact %s on port %s\n", server_name, argv[3]);
        close(sockfd);
        free(text);
        free(key);
        return 2;
    }

    net_text_len = htonl((uint32_t)text_len);
    net_key_len = htonl((uint32_t)key_len);

    if (send_all(sockfd, &net_text_len, sizeof(net_text_len)) == -1 ||
        send_all(sockfd, &net_key_len, sizeof(net_key_len)) == -1 ||
        send_all(sockfd, text, (size_t)text_len) == -1 ||
        send_all(sockfd, key, (size_t)key_len) == -1) {
        fprintf(stderr, "%s error: failed to send data\n", argv[0]);
        close(sockfd);
        free(text);
        free(key);
        return 2;
    }

    output = calloc((size_t)text_len + 1, sizeof(char));
    if (output == NULL) {
        fprintf(stderr, "%s error: memory allocation failed\n", argv[0]);
        close(sockfd);
        free(text);
        free(key);
        return 1;
    }

    if (recv_all(sockfd, output, (size_t)text_len) == -1) {
        fprintf(stderr, "%s error: failed to receive result\n", argv[0]);
        close(sockfd);
        free(text);
        free(key);
        free(output);
        return 2;
    }

    output[text_len] = '\0';
    printf("%s\n", output);

    close(sockfd);
    free(text);
    free(key);
    free(output);
    return 0;
}
