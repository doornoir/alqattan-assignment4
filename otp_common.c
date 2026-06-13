#define _POSIX_C_SOURCE 200809L
#include "otp_common.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/*
Reads entire file into memory and removes trailing newline chars
OTP math doesnt include \n
*/
char* read_file_strip_newline(const char* path, int* out_len, int* err) {
    FILE* fp = fopen(path, "r");
    long size;
    char* buf;

    *err = 0;
    *out_len = 0;

    if (fp == NULL) {
        *err = 1;
        return NULL;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        *err = 1;
        return NULL;
    }

    size = ftell(fp);
    if (size < 0) {
        fclose(fp);
        *err = 1;
        return NULL;
    }

    // Go back to start so the file can be read from the beginning.
    rewind(fp);

    // Allocate space for the file contents + null term
    buf = calloc((size_t)size + 1, sizeof(char));
    if (buf == NULL) {
        fclose(fp);
        *err = 1;
        return NULL;
    }
    if (size > 0 && fread(buf, sizeof(char), (size_t)size, fp) != (size_t)size) {
        free(buf);
        fclose(fp);
        *err = 1;
        return NULL;
    }
    fclose(fp);

    // Remove trailing newline or carried over return chars
    while (size > 0 && (buf[size - 1] == '\n' || buf[size - 1] == '\r')) {
        buf[size - 1] = '\0';
        size--;
    }

    *out_len = (int)size;
    return buf;
}

// Checks whether a string only contains valid OTP chars
int valid_otp_text(const char* s, int len) {
    int i;
    for (i = 0; i < len; i++) {
        if (s[i] != ' ' && (s[i] < 'A' || s[i] > 'Z')) {
            return 0;
        }
    }
    return 1;
}

// Converts OTP char to number
int char_to_val(char c) {
    if (c == ' ') {
        return 26;
    }
    return c - 'A';
}

// Converts number back into OTP char
char val_to_char(int v) {
    if (v == 26) {
        return ' ';
    }
    return (char)('A' + v);
}

// Enc or dec text using OTP algo
char* transform_text(const char* text, const char* key, int len, int decrypt) {
    int i;
    char* out = calloc((size_t)len + 1, sizeof(char));
    if (out == NULL) {
        return NULL;
    }

    for (i = 0; i < len; i++) {
        int t = char_to_val(text[i]);
        int k = char_to_val(key[i]);
        int v = decrypt ? (t - k) : (t + k);
        v %= 27;
        if (v < 0) {
            v += 27;
        }
        out[i] = val_to_char(v);
    }
    out[len] = '\0';
    return out;
}

// Sends exactly len bytes over a socket, used because send() is not garunteed to send all bytes at once.
int send_all(int sockfd, const void* buf, size_t len) {
    const char* p = (const char*)buf;
    while (len > 0) {
        size_t chunk = len > MAX_CHUNK ? MAX_CHUNK : len;
        ssize_t sent = send(sockfd, p, chunk, 0);
        if (sent < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (sent == 0) {
            return -1;
        }
        p += sent;
        len -= (size_t)sent;
    }
    return 0;
}

// Recieves exactly len bytes from a socket
int recv_all(int sockfd, void* buf, size_t len) {
    char* p = (char*)buf;
    while (len > 0) {
        size_t chunk = len > MAX_CHUNK ? MAX_CHUNK : len;
        ssize_t got = recv(sockfd, p, chunk, 0);
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (got == 0) {
            return -1;
        }
        p += got;
        len -= (size_t)got;
    }
    return 0;
}

// Connects a client to localhost on the given port
int connect_to_localhost(const char* port_str) {
    struct addrinfo hints;
    struct addrinfo* result = NULL;
    struct addrinfo* rp;
    int sockfd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo("localhost", port_str, &hints, &result) != 0) {
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1) {
            continue;
        }
        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        close(sockfd);
        sockfd = -1;
    }

    freeaddrinfo(result);
    return sockfd;
}

// Sets up TCP serv socket on the given port
int setup_server_socket(const char* port_str) {
    struct addrinfo hints;
    struct addrinfo* result = NULL;
    struct addrinfo* rp;
    int listenfd = -1;
    int yes = 1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(NULL, port_str, &hints, &result) != 0) {
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        listenfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listenfd == -1) {
            continue;
        }

        setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        if (bind(listenfd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        close(listenfd);
        listenfd = -1;
    }

    freeaddrinfo(result);

    if (listenfd == -1) {
        return -1;
    }

    if (listen(listenfd, BACKLOG) < 0) {
        close(listenfd);
        return -1;
    }

    return listenfd;
}

// Exits from child process safely, used after a forked server child finishes handling one client.
void close_and_exit_child(int code) {
    fflush(stdout);
    fflush(stderr);
    _exit(code);
}
