// secure_data_handler.h
#ifndef SECURE_DATA_HANDLER_H
#define __SECURE_DATA_HANDLER_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <curl/curl.h>
#include <jansson.h>

#define MAX_PAYLOAD_SIZE 4096
#define ENCRYPTION_KEY_LENGTH 32
#define IV_LENGTH 16

// Logging levels
typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
    LOG_CRITICAL
} LogLevel;

// Encryption context structure
typedef struct {
    unsigned char key[ENCRYPTION_KEY_LENGTH];
    unsigned char iv[IV_LENGTH];
} EncryptionContext;

// Secure data structure
typedef struct {
    char* payload;
    size_t payload_length;
    EncryptionContext* crypto_ctx;
} SecureData;

// Error handling structure
typedef struct {
    int error_code;
    char error_message[256];
} ErrorContext;

// Logging function
void secure_log(LogLevel level, const char* message, ...);

// Initialization functions
int secure_data_init();
void secure_data_cleanup();

// Encryption and decryption functions
SecureData* secure_data_encrypt(
    const char* payload, 
    size_t payload_length, 
    ErrorContext* error
);

char* secure_data_decrypt(
    const SecureData* encrypted_data, 
    size_t* decrypted_length, 
    ErrorContext* error
);

// Key management functions
int generate_encryption_key(EncryptionContext* ctx);
int derive_key_from_password(
    const char* password, 
    EncryptionContext* ctx
);

// Secure HTTP server structure
typedef struct {
    SSL_CTX* ssl_context;
    int server_socket;
    char* cert_file;
    char* key_file;
} SecureHTTPServer;

// HTTP server functions
SecureHTTPServer* create_secure_http_server(
    const char* cert_path, 
    const char* key_path, 
    int port
);

int start_secure_server(SecureHTTPServer* server);
void stop_secure_server(SecureHTTPServer* server);

#endif // SECURE_DATA_HANDLER_H
