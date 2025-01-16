#ifndef UTILS_H
#define UTILS_H

#include <arpa/inet.h>
#include <csignal>
#include <iostream>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <vector>

int send_all(int sockfd, const char *buf, size_t len);
int recv_all(int sockfd, char *buf, size_t len);
void read_message(char* buf, size_t len);

void generate_key_pair(std::string& public_key, std::string& private_key);
std::string decrypt_with_private_key(const std::string& private_key, const std::string& ciphertext);
std::string encrypt_with_public_key(const std::string& public_key, const std::string& plaintext);

void send_file_in_chunks(int sockfd, FILE* file, std::string pubkey);
void recv_file_in_chunks(int sockfd, std::string filepath, std::string priv_key);

#define BUFFER_SIZE 1024
#define CHUNK_SIZE 128
#define ENC_CHUNK_SIZE 256

#endif // UTILS_H
