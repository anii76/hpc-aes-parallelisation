#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/conf.h>


int encrypt(unsigned char* text, int text_len, unsigned char* key, unsigned char* cipher)
{
    int cipher_len = 0;
    int len = 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if (!ctx) {
        perror("EVP_CIPHER_CTX_new() failed");
        return -1;
    }
                                                             /*iv ?*/
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, NULL)) {
        perror("EVP_EncryptInit_ex() failed");
        return -1;
    }

    if (!EVP_EncryptUpdate(ctx, cipher, &len, text, text_len)) {
        perror("EVP_EncryptUpdate() failed");
        return -1;
    }

    cipher_len += len;

    if (!EVP_EncryptFinal_ex(ctx, cipher + len, &len)) {
        perror("EVP_EncryptFinal_ex() failed");
        return -1;
    }

    cipher_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return cipher_len;
}
 
int decrypt(unsigned char* cipher, int cipher_len, unsigned char* key, unsigned char* text)
{
    int text_len = 0;
    int len = 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if (!ctx) {
        perror("EVP_CIPHER_CTX_new() failed");
        return -1;
    }
                                                             
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, NULL)) {
        perror("EVP_DecryptInit_ex() failed");
        return -1;
    }

    if (!EVP_DecryptUpdate(ctx, text, &len, cipher, cipher_len)) {
        perror("EVP_DecryptUpdate() failed");
        return -1;
    }

    text_len += len;

    if (!EVP_DecryptFinal_ex(ctx, text + len, &len)) {
        perror("EVP_DecryptFinal_ex() failed");
        return -1;
    }

    text_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return text_len;
}
