#include "secure_data_handler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// Logging implementation
void secure_log(LogLevel level, const char* message, ...) {
    va_list args;
    va_start(args, message);
    
    int syslog_level;
    switch(level) {
        case LOG_DEBUG:   syslog_level = LOG_DEBUG; break;
        case LOG_INFO:    syslog_level = LOG_INFO; break;
        case LOG_WARN:    syslog_level = LOG_WARNING; break;
        case LOG_ERROR:   syslog_level = LOG_ERR; break;
        case LOG_CRITICAL: syslog_level = LOG_CRIT; break;
        default:          syslog_level = LOG_INFO;
    }
    
    openlog("SecureDataHandler", LOG_PID | LOG_CONS, LOG_USER);
    vsyslog(syslog_level, message, args);
    closelog();
    va_end(args);
}

// Generate encryption key
int generate_encryption_key(EncryptionContext* ctx) {
    if (!ctx) {
        secure_log(LOG_ERROR, "Null encryption context");
        return 0;
    }

    // Generate cryptographically secure random key and IV
    if (RAND_bytes(ctx->key, ENCRYPTION_KEY_LENGTH) != 1) {
        secure_log(LOG_CRITICAL, "Failed to generate encryption key");
        return 0;
    }

    if (RAND_bytes(ctx->iv, IV_LENGTH) != 1) {
        secure_log(LOG_CRITICAL, "Failed to generate initialization vector");
        return 0;
    }

    return 1;
}

// Secure initialization
int secure_data_init() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_library_init();
    
    // Seed random number generator
    unsigned char seed[32];
    if (RAND_bytes(seed, sizeof(seed)) != 1) {
        secure_log(LOG_CRITICAL, "Failed to seed RNG");
        return 0;
    }
    
    return 1;
}

// Encryption function with advanced error handling
SecureData* secure_data_encrypt(
    const char* payload, 
    size_t payload_length, 
    ErrorContext* error
) {
    // Validate inputs
    if (!payload || payload_length == 0) {
        if (error) {
            error->error_code = -1;
            strncpy(error->error_message, "Invalid payload", sizeof(error->error_message));
        }
        return NULL;
    }

    // Allocate secure data
    SecureData* secure_data = malloc(sizeof(SecureData));
    if (!secure_data) {
        secure_log(LOG_CRITICAL, "Memory allocation failed for SecureData");
        return NULL;
    }

    secure_data->crypto_ctx = malloc(sizeof(EncryptionContext));
    if (!secure_data->crypto_ctx) {
        secure_log(LOG_CRITICAL, "Memory allocation failed for EncryptionContext");
        free(secure_data);
        return NULL;
    }

    // Generate encryption key
    if (!generate_encryption_key(secure_data->crypto_ctx)) {
        secure_log(LOG_ERROR, "Key generation failed");
        free(secure_data->crypto_ctx);
        free(secure_data);
        return NULL;
    }

    // Encryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        secure_log(LOG_ERROR, "Failed to create cipher context");
        free(secure_data->crypto_ctx);
        free(secure_data);
        return NULL;
    }

    EVP_EncryptInit_ex(
        ctx, 
        EVP_aes_256_cbc(), 
        NULL, 
        secure_data->crypto_ctx->key, 
        secure_data->crypto_ctx->iv
    );

    // Allocate output buffer
    int cipher_buffer_length = payload_length + EVP_MAX_BLOCK_LENGTH;
    unsigned char* cipher_text = malloc(cipher_buffer_length);
    if (!cipher_text) {
        secure_log(LOG_CRITICAL, "Memory allocation failed for cipher text");
        EVP_CIPHER_CTX_free(ctx);
        free(secure_data->crypto_ctx);
        free(secure_data);
        return NULL;
    }

    int final_length = 0, encrypted_length = 0;

    // Perform encryption
    if (EVP_EncryptUpdate(
        ctx, 
        cipher_text, 
        &encrypted_length, 
        (const unsigned char*)payload, 
        payload_length
    ) != 1) {
        secure_log(LOG_ERROR, "Encryption update failed");
        free(cipher_text);
        EVP_CIPHER_CTX_free(ctx);
        free(secure_data->crypto_ctx);
        free(secure_data);
        return NULL;
    }

    if (EVP_EncryptFinal_ex(
        ctx, 
        cipher_text + encrypted_length, 
        &final_length
    ) != 1) {
        secure_log(LOG_ERROR, "Encryption finalization failed");
        free(cipher_text);
        EVP_CIPHER_CTX_free(ctx);
        free(secure_data->crypto_ctx);
        free(secure_data);
        return NULL;
    }

    // Set secure data
    secure_data->payload = (char*)cipher_text;
    secure_data->payload_length = encrypted_length + final_length;

    // Cleanup
    EVP_CIPHER_CTX_free(ctx);

    return secure_data;
}

// Decryption function
char* secure_data_decrypt(
    const SecureData* encrypted_data, 
    size_t* decrypted_length, 
    ErrorContext* error
) {
    if (!encrypted_data || !encrypted_data->payload) {
        if (error) {
            error->error_code = -1;
            strncpy(error->error_message, "Invalid encrypted data", sizeof(error->error_message));
        }
        return NULL;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        secure_log(LOG_ERROR, "Failed to create decryption context");
        return NULL;
    }

    EVP_DecryptInit_ex(
        ctx, 
        EVP_aes_256_cbc(), 
        NULL, 
        encrypted_data->crypto_ctx->key, 
        encrypted_data->crypto_ctx->iv
    );

    char* decrypted_text = malloc(encrypted_data->payload_length);
    int decrypted_len = 0, final_len = 0;

    if (EVP_DecryptUpdate(
        ctx, 
        (unsigned char*)decrypted_text, 
        &decrypted_len, 
        (const unsigned char*)encrypted_data->payload, 
        encrypted_data->payload_length
    ) != 1) {
        secure_log(LOG_ERROR, "Decryption update failed");
        free(decrypted_text);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    if (EVP_DecryptFinal_ex(
        ctx, 
        (unsigned char*)decrypted_text + decrypted_len, 
        &final_len
    ) != 1) {
        secure_log(LOG_ERROR, "Decryption finalization failed");
        free(decrypted_text);
