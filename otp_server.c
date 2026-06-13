#define _POSIX_C_SOURCE 200809L
#include "otp_common.h"

// Socket setup based on the beej.us example

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// SIGCHLD handler for when every accepted client connection is handled by the child process. Then when
// a child exits, the handler reaps it so that no zombie processes build up
static void sigchld_handler(int s) {
    int saved_errno;
    (void)s;

    saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
    errno = saved_errno;
}

/* Get sockaddr, IPv4 or IPv6 */
static void* get_in_addr(struct sockaddr* sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// Create bind and listen on server socket.
static int make_listening_socket(const char* port) {
    struct addrinfo hints;
    struct addrinfo* servinfo;
    struct addrinfo* p;
    int sockfd;
    int yes;
    int rv;

    memset(&hints, 0, sizeof hints); // clear hints so all fields start as 0 before setting the ones we needed
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    rv = getaddrinfo(NULL, port, &hints, &servinfo);
    if (rv != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    // start with invalid socket value
    sockfd = -1;
    yes = 1;
    
    // try each address returned by getaddrinfo() until one works.
    for (p = servinfo; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            perror("setsockopt");
            close(sockfd);
            freeaddrinfo(servinfo);
            return -1;
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            sockfd = -1;
            continue;
        }

        break;
    }

    // Must be freed after use
    freeaddrinfo(servinfo);

    if (sockfd == -1) {
        fprintf(stderr, "server: failed to bind\n");
        return -1;
    }

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

/*
Handle one connected client
*/
static void handle_client(int new_fd, const char* expected_mode, int decrypt) {
    char mode[4];
    char reply[3];
    uint32_t net_text_len;
    uint32_t net_key_len;
    int text_len;
    int key_len;
    char* text;
    char* key;
    char* output;

    // clear mode buffer and initialize pointers for safe cleanup
    memset(mode, 0, sizeof(mode));
    text = NULL;
    key = NULL;
    output = NULL;

    // Recieve 3 byte handshake from the client
    if (recv_all(new_fd, mode, 3) == -1) {
        fprintf(stderr, "%s_server error: failed to receive handshake\n", decrypt ? "dec" : "enc");
        close(new_fd);
        close_and_exit_child(1);
    }

    // Reject clients that connected to wrong serv type
    if (strncmp(mode, expected_mode, 3) != 0) {
        memcpy(reply, "NO", 2);
        send_all(new_fd, reply, 2);
        close(new_fd);
        close_and_exit_child(0);
    }

    // send ok so client knows its properly connected
    memcpy(reply, "OK", 2);
    if (send_all(new_fd, reply, 2) == -1) {
        close(new_fd);
        close_and_exit_child(1);
    }
    
    // Recieve plaintext/ciphertext length and key length
    if (recv_all(new_fd, &net_text_len, sizeof(net_text_len)) == -1 ||
        recv_all(new_fd, &net_key_len, sizeof(net_key_len)) == -1) {
        fprintf(stderr, "%s_server error: failed to receive data lengths\n", decrypt ? "dec" : "enc");
        close(new_fd);
        close_and_exit_child(1);
    }

    text_len = (int)ntohl(net_text_len);
    key_len = (int)ntohl(net_key_len);

        
    // key must be as long as text being enc/dec.
    if (text_len < 0 || key_len < text_len) {
        fprintf(stderr, "%s_server error: bad input lengths\n", decrypt ? "dec" : "enc");
        close(new_fd);
        close_and_exit_child(1);
    }

    // Allocate buffers for the text and key.
    // The extra byte leaves room for a null terminator for safe string handling.
    text = calloc((size_t)text_len + 1, sizeof(char));
    key = calloc((size_t)key_len + 1, sizeof(char));

    if (text == NULL || key == NULL) {
        fprintf(stderr, "%s_server error: memory allocation failed\n", decrypt ? "dec" : "enc");
        free(text);
        free(key);
        close(new_fd);
        close_and_exit_child(1);
    }

    // Receive the full text and key from the client.
    // recv_all() is used because TCP may deliver data in smaller chunks.
    if (recv_all(new_fd, text, (size_t)text_len) == -1 ||
        recv_all(new_fd, key, (size_t)key_len) == -1) {
        fprintf(stderr, "%s_server error: failed to receive text/key\n", decrypt ? "dec" : "enc");
        free(text);
        free(key);
        close(new_fd);
        close_and_exit_child(1);
    }

    // Validate both text and key only use OTP chars.
    if (!valid_otp_text(text, text_len) || !valid_otp_text(key, key_len)) {
        fprintf(stderr, "%s_server error: input contains bad characters\n", decrypt ? "dec" : "enc");
        free(text);
        free(key);
        close(new_fd);
        close_and_exit_child(1);
    }

    // Enc or Dec depending on serv type
    output = transform_text(text, key, text_len, decrypt);
    if (output == NULL) {
        fprintf(stderr, "%s_server error: memory allocation failed\n", decrypt ? "dec" : "enc");
        free(text);
        free(key);
        close(new_fd);
        close_and_exit_child(1);
    }

    if (send_all(new_fd, output, (size_t)text_len) == -1) {
        fprintf(stderr, "%s_server error: failed to send result\n", decrypt ? "dec" : "enc");
    }

    free(text);
    free(key);
    free(output);
    close(new_fd);
    close_and_exit_child(0);
}

// Main shared server function in which both enc_server and dec_server both run this with different expected mode/decrypt values
int run_server(int argc, char* argv[], const char* expected_mode, int decrypt) {
    int sockfd;
    int new_fd;
    struct sigaction sa;
    struct sockaddr_storage their_addr;
    socklen_t sin_size;
    char s[INET6_ADDRSTRLEN];
    pid_t pid;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s listening_port\n", argv[0]);
        return 1;
    }

    sockfd = make_listening_socket(argv[1]);
    if (sockfd == -1) {
        return 1;
    }

    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        close(sockfd);
        return 1;
    }

    //Main server loop to keep accepting clients forever.
    while (1) {
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr*)&their_addr, &sin_size);
        if (new_fd == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr*)&their_addr), s, sizeof s);

        pid = fork();
        if (pid == -1) {
            perror("fork");
            close(new_fd);
            continue;
        }

        if (pid == 0) {
            close(sockfd);
            handle_client(new_fd, expected_mode, decrypt);
        }

        close(new_fd);
    }
}
