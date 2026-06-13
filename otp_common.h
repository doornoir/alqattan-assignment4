#ifndef OTP_COMMON_H
#define OTP_COMMON_H

#include <stddef.h>

#define BACKLOG 5
#define MAX_CHUNK 1000

char* read_file_strip_newline(const char* path, int* out_len, int* err);
int valid_otp_text(const char* s, int len);
int char_to_val(char c);
char val_to_char(int v);
char* transform_text(const char* text, const char* key, int len, int decrypt);
int send_all(int sockfd, const void* buf, size_t len);
int recv_all(int sockfd, void* buf, size_t len);
int connect_to_localhost(const char* port_str);
int setup_server_socket(const char* port_str);
void close_and_exit_child(int code);

#endif
